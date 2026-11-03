import os
import sys
import time
from datetime import datetime

os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")

from bson.errors import InvalidId
from flask import Flask, jsonify, request, render_template, redirect, url_for
from markupsafe import escape

RAIZ_PROJETO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if RAIZ_PROJETO not in sys.path:
    sys.path.insert(0, RAIZ_PROJETO)

from core.regras import carregar_regras, aplicar_regras
from core.detector import (
    BLACKLIST_PADRAO,
    detectar_brute_force,
    detectar_port_scan,
    verificar_blacklist,
    gerar_resumo_ameacas
)
from core.enriquecimento import validar_ip, eh_ip_privado, consultar_ip
from db.mongo_repo import (
    consultar_eventos,
    contar_eventos,
    consultar_alertas,
    contar_alertas,
    obter_alerta_por_id,
    salvar_alerta,
    salvar_eventos,
    salvar_alertas,
    top_ips_eventos,
    contar_eventos_por_fonte,
    contar_alertas_por_severidade
)
from db.mysql_repo import (
    inicializar_tabela_usuarios,
    criar_usuario,
    listar_usuarios,
    autenticar_operador
)
from db.migrar_logs import executar_ingestao
from ml.classificar import classificar_ip, pontuar_ameacas
from ia.assistente import analisar_evento_ia, explicar_ip_ia
from alertas.servidor_alertas import enviar_alerta_remoto, iniciar_servidor_background
from api.auth import (
    extrair_e_validar_bearer,
    gerar_token_sessao,
    obter_nivel_bearer,
    obter_operador_requisicao,
    remover_token
)


PASTA_TEMPLATES = os.path.join(RAIZ_PROJETO, "web", "templates")
ARQUIVO_LOG_ACESSO = os.path.join(RAIZ_PROJETO, "logs", "access_plataforma.log")

app = Flask(__name__, template_folder=PASTA_TEMPLATES)

cache_enriquecimento = {}
tentativas_login_por_ip = {}

SEVERIDADES_VALIDAS = {"CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"}
PONTUACAO_POR_SEVERIDADE = {"CRITICA": 9, "ALTA": 7, "MEDIA": 5, "BAIXA": 3, "INFO": 1}
LIMITE_FALHAS_LOGIN = 5
TEMPO_BLOQUEIO_SEGUNDOS = 30


def _garantir_dados_iniciais():
    """Executa a ingestão inicial caso a base de eventos esteja vazia."""
    if contar_eventos() == 0:
        executar_ingestao()


def _ler_json_objeto():
    """Lê o corpo da requisição e garante que seja um dicionário JSON válido."""
    dados = request.get_json(silent=True)
    if type(dados) is not dict:
        return None
    return dados


def _registrar_log_acesso(resposta):
    """Registra cada requisição HTTP recebida no arquivo de auditoria."""
    try:
        os.makedirs(os.path.dirname(ARQUIVO_LOG_ACESSO), exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip_cliente = request.remote_addr or "127.0.0.1"
        linha = f"[{ts}] ip={ip_cliente} metodo={request.method} rota={request.path} status={resposta.status_code}\n"
        with open(ARQUIVO_LOG_ACESSO, "a", encoding="utf-8") as f:
            f.write(linha)
    except OSError:
        pass


@app.after_request
def aplicar_headers_e_logging(resp):
    """Adiciona headers de segurança OWASP e registra o log de acesso."""
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    _registrar_log_acesso(resp)
    return resp


def _ler_paginacao():
    """Valida e converte os parâmetros de paginação pagina e tamanho."""
    try:
        pagina = int(request.args.get("pagina", "1"))
        tamanho = int(request.args.get("tamanho", "20"))
        if pagina < 1 or tamanho < 1 or tamanho > 200:
            return None, None
        return pagina, tamanho
    except ValueError:
        return None, None


def _montar_relatorio_ip(ip):
    """Consolida eventos, alertas, geolocalização, score ML e análise IA de um IP."""
    _garantir_dados_iniciais()
    todos_evs = consultar_eventos(pagina=1, tamanho=500)
    eventos_ip = consultar_eventos(ip=ip, pagina=1, tamanho=200)
    alertas_ip = consultar_alertas(ip=ip, pagina=1, tamanho=200)
    geo = consultar_ip(ip, cache_enriquecimento)
    ml_info = classificar_ip(ip, todos_evs, BLACKLIST_PADRAO)
    ia_info = explicar_ip_ia(ip, eventos_ip, alertas_ip, ml_info)

    return {
        "ip": ip,
        "tipo_ip": "privado" if eh_ip_privado(ip) else "publico",
        "na_blacklist": ip in BLACKLIST_PADRAO,
        "enriquecimento": geo,
        "ml": ml_info,
        "analise_ia": ia_info,
        "eventos": eventos_ip,
        "alertas": alertas_ip
    }


@app.route("/", methods=["GET"])
@app.route("/dashboard", methods=["GET"])
def dashboard():
    """Renderiza o painel web principal com estatísticas e alertas escapados."""
    _garantir_dados_iniciais()
    eventos_por_fonte = contar_eventos_por_fonte()
    alertas_por_severidade = contar_alertas_por_severidade()
    todos_evs = consultar_eventos(pagina=1, tamanho=500)

    top_10 = []
    for item in top_ips_eventos(10):
        ip = item["ip"]
        info_ml = classificar_ip(ip, todos_evs, BLACKLIST_PADRAO)
        top_10.append({
            "ip": ip, "total": item["total"], "na_blacklist": ip in BLACKLIST_PADRAO,
            "rotulo_ml": info_ml["rotulo"].upper(), "score_risco": info_ml["score_risco"],
            "nivel_risco": info_ml["nivel_risco"]
        })
    top_10.sort(key=lambda x: (x["score_risco"], x["total"]), reverse=True)

    return render_template(
        "dashboard.html",
        eventos_por_fonte=eventos_por_fonte,
        alertas_por_severidade=alertas_por_severidade,
        total_eventos=sum(eventos_por_fonte.values()),
        total_alertas=sum(alertas_por_severidade.values()),
        top_10_ips=top_10,
        alertas_recentes=consultar_alertas(pagina=1, tamanho=15),
        operador=obter_operador_requisicao(request),
        mensagem=request.args.get("msg", "")
    ), 200


@app.route("/buscar-ip", methods=["GET"])
def buscar_ip_web():
    """Exibe a página de detalhes de um IP específico após validar seu formato."""
    ip = request.args.get("ip", "").strip()
    if not validar_ip(ip):
        return f"<h1>Erro 400: IP inválido ({escape(ip)})</h1><a href='/'>Voltar</a>", 400
    dados = _montar_relatorio_ip(ip)
    return render_template("ip_detalhes.html", dados=dados), 200


@app.route("/cadastrar-alerta-web", methods=["POST"])
def cadastrar_alerta_web():
    """Registra um alerta enviado pelo formulário web exigindo operador autenticado."""
    if not obter_operador_requisicao(request):
        return render_template("login.html", erro="Autenticação necessária para registrar alertas."), 401

    tipo = request.form.get("tipo", "").strip()
    ip = request.form.get("ip", "").strip()
    severidade = request.form.get("severidade", "MEDIA").strip().upper()
    descricao = request.form.get("descricao", "").strip()

    if not tipo or not descricao or severidade not in SEVERIDADES_VALIDAS:
        return redirect(url_for("dashboard", msg="Dados inválidos ao cadastrar alerta."))
    if ip and not validar_ip(ip):
        return redirect(url_for("dashboard", msg="IP inválido informado no alerta."))

    novo_alerta = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "regra_id": "MANUAL", "regra": tipo, "tipo": tipo.upper(),
        "severidade": severidade, "pontuacao": PONTUACAO_POR_SEVERIDADE.get(severidade, 5),
        "ip": ip or "127.0.0.1", "fonte": "web_manual",
        "score_risco_ml": 50.0, "descricao": descricao
    }
    salvar_alerta(novo_alerta)
    enviar_alerta_remoto(novo_alerta)
    return redirect(url_for("dashboard", msg="Alerta registrado com sucesso."))


@app.route("/analisar-web", methods=["POST"])
def analisar_web():
    """Reprocessa os logs pelo formulário web exigindo operador autenticado."""
    if not obter_operador_requisicao(request):
        return render_template("login.html", erro="Autenticação necessária para reprocessar logs."), 401

    res = executar_ingestao()
    msg = f"Logs processados: {res['eventos_ingeridos']} eventos e {res['alertas_gerados']} alertas."
    return redirect(url_for("dashboard", msg=msg))


def _verificar_bloqueio_ip(ip_cliente):
    """Verifica se o IP está temporariamente bloqueado por excesso de falhas."""
    registro = tentativas_login_por_ip.get(ip_cliente)
    if not registro:
        return False
    agora = time.time()
    if registro["bloqueado_ate"] > agora:
        return True
    if registro["bloqueado_ate"] > 0 and agora >= registro["bloqueado_ate"]:
        del tentativas_login_por_ip[ip_cliente]
    return False


def _registrar_falha_login(ip_cliente):
    """Incrementa o contador de falhas de login e aplica bloqueio temporário."""
    registro = tentativas_login_por_ip.get(ip_cliente, {"falhas": 0, "bloqueado_ate": 0.0})
    registro["falhas"] += 1
    if registro["falhas"] >= LIMITE_FALHAS_LOGIN:
        registro["bloqueado_ate"] = time.time() + TEMPO_BLOQUEIO_SEGUNDOS
    tentativas_login_por_ip[ip_cliente] = registro


def _resposta_login(eh_json, mensagem, codigo, html_erro=None):
    """Formata a resposta de erro do login para JSON ou HTML."""
    if eh_json:
        return jsonify({"erro": mensagem}), codigo
    return render_template("login.html", erro=html_erro or mensagem), codigo


@app.route("/login", methods=["GET", "POST"])
@app.route("/api/login", methods=["POST"])
def login():
    """Autentica operadores no banco MySQL e emite token de sessão."""
    if request.method == "GET":
        return render_template("login.html", erro=None), 200

    inicializar_tabela_usuarios()
    eh_json = request.is_json or request.path.startswith("/api/")
    dados = _ler_json_objeto() if eh_json else request.form
    if not dados:
        return _resposta_login(eh_json, "Usuário e senha são obrigatórios", 400)

    u_raw = dados.get("usuario") if "usuario" in dados else dados.get("email")
    s_raw = dados.get("senha")
    if type(u_raw) is not str or type(s_raw) is not str or not u_raw.strip() or not s_raw.strip():
        return _resposta_login(eh_json, "Usuário e senha são obrigatórios", 400)

    ip_cli = request.remote_addr or "127.0.0.1"
    if _verificar_bloqueio_ip(ip_cli):
        return _resposta_login(eh_json, "Muitas tentativas falhas. Aguarde 30s.", 429)

    operador = autenticar_operador(u_raw.strip(), s_raw.strip())
    if not operador:
        _registrar_falha_login(ip_cli)
        return _resposta_login(eh_json, "Credenciais inválidas", 401)

    tentativas_login_por_ip.pop(ip_cli, None)
    token = gerar_token_sessao(operador["nome"], operador.get("nivel_acesso", 1))
    if eh_json:
        return jsonify({"mensagem": "Login OK", "token": token, "operador": operador}), 200

    resp = redirect(url_for("dashboard", msg=f"Bem-vindo, {operador['nome']}!"))
    resp.set_cookie("securapy_sessao", token, httponly=True, max_age=3600)
    return resp


@app.route("/logout", methods=["GET"])
def logout():
    """Encerra a sessão do operador do cliente atual."""
    token_cookie = request.cookies.get("securapy_sessao", "")
    if token_cookie:
        remover_token(token_cookie)
    resp = redirect(url_for("dashboard", msg="Sessão encerrada."))
    resp.delete_cookie("securapy_sessao")
    return resp


@app.route("/api/status", methods=["GET"])
def api_status():
    """Retorna o status operacional da API SecuraPy Platform."""
    return jsonify({"status": "online", "plataforma": "SecuraPy Platform", "versao": "2.0"}), 200


@app.route("/api/eventos", methods=["GET"])
def api_listar_eventos():
    """Lista eventos com suporte a filtros por fonte, tipo, IP e paginação."""
    _garantir_dados_iniciais()
    pagina, tamanho = _ler_paginacao()
    if pagina is None:
        return jsonify({"erro": "Parâmetros de paginação inválidos"}), 400

    fonte = request.args.get("fonte")
    tipo = request.args.get("tipo")
    ip = request.args.get("ip")
    desde = request.args.get("desde")
    if ip and not validar_ip(ip):
        return jsonify({"erro": "IP inválido no filtro"}), 400

    lista = consultar_eventos(fonte=fonte, tipo=tipo, ip=ip, desde=desde, pagina=pagina, tamanho=tamanho)
    total = contar_eventos(fonte=fonte, tipo=tipo, ip=ip, desde=desde)
    return jsonify({"pagina": pagina, "tamanho": tamanho, "total": total, "eventos": lista}), 200


@app.route("/api/alertas", methods=["GET"])
def api_listar_alertas():
    """Lista alertas com filtros de severidade, IP, tipo e paginação."""
    _garantir_dados_iniciais()
    pagina, tamanho = _ler_paginacao()
    if pagina is None:
        return jsonify({"erro": "Parâmetros de paginação inválidos"}), 400

    severidade = request.args.get("severidade")
    ip = request.args.get("ip")
    tipo = request.args.get("tipo")

    if severidade and severidade.upper() not in SEVERIDADES_VALIDAS:
        return jsonify({"erro": "Severidade inválida no filtro"}), 400
    if ip and not validar_ip(ip):
        return jsonify({"erro": "IP inválido no filtro"}), 400

    lista = consultar_alertas(severidade=severidade, ip=ip, tipo=tipo, pagina=pagina, tamanho=tamanho)
    total = contar_alertas(severidade=severidade, ip=ip, tipo=tipo)
    return jsonify({"pagina": pagina, "tamanho": tamanho, "total": total, "alertas": lista}), 200


@app.route("/api/alertas/<id>", methods=["GET"])
def api_obter_alerta(id):
    """Obtém os detalhes de um alerta específico pelo seu ID."""
    try:
        alerta = obter_alerta_por_id(id)
    except InvalidId:
        return jsonify({"erro": "id inválido"}), 400
    if not alerta:
        return jsonify({"erro": "Alerta não encontrado"}), 404
    return jsonify(alerta), 200


def _validar_payload_alerta(dados):
    """Valida todos os campos e tipos do corpo JSON de criação de alerta."""
    if not dados or "tipo" not in dados or "severidade" not in dados:
        return None, "Campos 'tipo' e 'severidade' são obrigatórios"
    if type(dados["tipo"]) is not str or type(dados["severidade"]) is not str:
        return None, "Campos 'tipo' e 'severidade' devem ser strings"
    if not dados["tipo"].strip():
        return None, "Campo 'tipo' não pode ser vazio"

    severidade = dados["severidade"].strip().upper()
    if severidade not in SEVERIDADES_VALIDAS:
        return None, "Severidade inválida. Use CRITICA, ALTA, MEDIA, BAIXA ou INFO"

    ip = dados.get("ip") if "ip" in dados else dados.get("ip_origem", "127.0.0.1")
    if type(ip) is not str or not validar_ip(ip):
        return None, "IP inválido"

    ts = dados.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    descricao = dados.get("descricao", "Alerta registrado via API")
    if type(ts) is not str or not ts.strip() or type(descricao) is not str:
        return None, "Campos 'timestamp' e 'descricao' devem ser strings válidas"

    return {
        "timestamp": ts.strip(),
        "regra_id": str(dados.get("regra_id", "API")),
        "regra": str(dados.get("regra", dados["tipo"].strip())),
        "tipo": dados["tipo"].strip().upper(),
        "severidade": severidade,
        "pontuacao": PONTUACAO_POR_SEVERIDADE.get(severidade, 5),
        "ip": ip.strip(),
        "fonte": str(dados.get("fonte", "api")),
        "descricao": descricao
    }, None


@app.route("/api/alertas", methods=["POST"])
def api_criar_alerta():
    """Cria um novo alerta via API exigindo token Bearer válido."""
    if not extrair_e_validar_bearer(request):
        return jsonify({"erro": "Não autorizado. Token Bearer ausente ou inválido."}), 401

    dados = _ler_json_objeto()
    novo_alerta, erro_msg = _validar_payload_alerta(dados)
    if erro_msg:
        return jsonify({"erro": erro_msg}), 400

    alerta_id = salvar_alerta(novo_alerta)
    novo_alerta["_id"] = alerta_id
    enviar_alerta_remoto(novo_alerta)
    return jsonify(novo_alerta), 201


def _validar_lista_eventos(eventos_custom):
    """Verifica se a lista de eventos customizados possui dicionários válidos."""
    if type(eventos_custom) is not list or not eventos_custom:
        return False
    for item in eventos_custom:
        if type(item) is not dict:
            return False
        for campo in ("fonte", "tipo", "ip", "detalhes"):
            if campo not in item or type(item[campo]) is not str:
                return False
        if not validar_ip(item["ip"]):
            return False
    return True


def _processar_eventos_customizados(eventos_custom):
    """Analisa, pontua e persiste um lote de eventos enviado via JSON."""
    regras = carregar_regras(os.path.join(RAIZ_PROJETO, "config", "regras.json"))
    alertas_gerados = aplicar_regras(eventos_custom, regras)
    bf = detectar_brute_force(eventos_custom)
    ps = detectar_port_scan(eventos_custom)
    ips_bl, cont_bl = verificar_blacklist(eventos_custom, BLACKLIST_PADRAO)
    resumo = gerar_resumo_ameacas(bf, ps, (ips_bl, cont_bl))
    ameacas_ml = pontuar_ameacas(resumo, eventos_custom, BLACKLIST_PADRAO)

    salvar_eventos(eventos_custom, limpar_antes=False)
    salvar_alertas(alertas_gerados, limpar_antes=False)
    for al in alertas_gerados:
        if al.get("severidade") in ("CRITICA", "ALTA"):
            enviar_alerta_remoto(al)

    return {
        "eventos_processados": len(eventos_custom),
        "alertas_gerados": len(alertas_gerados),
        "ameacas_priorizadas": ameacas_ml
    }


@app.route("/api/analisar", methods=["POST"])
def api_analisar():
    """Executa o pipeline completo de análise sobre os logs ou lote de eventos."""
    if not extrair_e_validar_bearer(request):
        return jsonify({"erro": "Não autorizado. Token Bearer ausente ou inválido."}), 401

    corpo_bruto = request.get_data(as_text=True).strip()
    if corpo_bruto:
        dados = _ler_json_objeto()
        if dados is None:
            return jsonify({"erro": "O corpo da requisição deve ser um objeto JSON válido"}), 400
    else:
        dados = {}

    if "eventos" in dados:
        if not _validar_lista_eventos(dados["eventos"]):
            return jsonify({"erro": "Campo 'eventos' deve ser uma lista de objetos de evento válidos"}), 400
        return jsonify(_processar_eventos_customizados(dados["eventos"])), 200

    pasta_solicitada = dados.get("pasta_logs", "logs")
    if type(pasta_solicitada) is not str or ".." in pasta_solicitada or os.path.isabs(pasta_solicitada):
        return jsonify({"erro": "Caminho de logs inválido ou não permitido"}), 400

    caminho_pasta = os.path.normpath(os.path.join(RAIZ_PROJETO, pasta_solicitada.strip()))
    if not caminho_pasta.startswith(RAIZ_PROJETO) or not os.path.isdir(caminho_pasta):
        return jsonify({"erro": "Diretório de logs não encontrado"}), 400

    resultado = executar_ingestao(pasta_logs=caminho_pasta)
    for ameaca in resultado.get("ameacas_priorizadas", []):
        if ameaca.get("severidade") in ("CRITICA", "ALTA"):
            enviar_alerta_remoto({
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "severidade": ameaca["severidade"], "regra": "Correlação SecuraPy",
                "ip": ameaca["ip"], "descricao": ", ".join(ameaca["motivos"])
            })
    return jsonify(resultado), 200


@app.route("/api/ip/<ip>", methods=["GET"])
def api_buscar_ip(ip):
    """Retorna eventos, alertas, geolocalização, score ML e explicação IA do IP."""
    if not validar_ip(ip):
        return jsonify({"erro": "IP inválido"}), 400
    return jsonify(_montar_relatorio_ip(ip)), 200


@app.route("/api/ia/explicar", methods=["POST"])
def api_explicar_ia():
    """Classifica e explica um evento ou linha de log usando o Assistente IA."""
    dados = _ler_json_objeto()
    if not dados:
        return jsonify({"erro": "Corpo JSON inválido"}), 400
    entrada = dados.get("evento") or dados.get("log")
    if not entrada or type(entrada) not in (str, dict):
        return jsonify({"erro": "Informe o campo 'evento' ou 'log' válido"}), 400
    return jsonify(analisar_evento_ia(entrada)), 200


@app.route("/api/usuarios", methods=["GET"])
def api_listar_usuarios():
    """Lista os operadores cadastrados no MySQL exigindo autenticação Bearer."""
    if not extrair_e_validar_bearer(request):
        return jsonify({"erro": "Não autorizado. Token Bearer ausente ou inválido."}), 401
    inicializar_tabela_usuarios()
    return jsonify(listar_usuarios()), 200


@app.route("/api/usuarios", methods=["POST"])
def api_criar_usuario():
    """Cadastra um novo operador no MySQL exigindo token de administrador (nível 5)."""
    if not extrair_e_validar_bearer(request):
        return jsonify({"erro": "Não autorizado. Token Bearer ausente ou inválido."}), 401
    if obter_nivel_bearer(request) < 5:
        return jsonify({"erro": "Acesso negado. Requer nível de acesso 5 (administrador)."}), 403

    dados = _ler_json_objeto()
    if not dados:
        return jsonify({"erro": "Corpo JSON inválido"}), 400

    nome = dados.get("nome")
    email = dados.get("email")
    senha = dados.get("senha")
    nivel = dados.get("nivel_acesso", dados.get("nivel", 1))

    if type(nome) is not str or type(email) is not str or type(senha) is not str:
        return jsonify({"erro": "Campos 'nome', 'email' e 'senha' são obrigatórios e devem ser strings"}), 400
    if not nome.strip() or not email.strip() or not senha.strip():
        return jsonify({"erro": "Campos 'nome', 'email' e 'senha' são obrigatórios"}), 400

    try:
        novo = criar_usuario(nome, email, senha, nivel)
        return jsonify(novo), 201
    except ValueError as e:
        return jsonify({"erro": str(e)}), 400
    except LookupError as e:
        return jsonify({"erro": str(e)}), 409


@app.errorhandler(404)
def tratar_404(e):
    """Retorna resposta JSON padronizada para rotas inexistentes."""
    return jsonify({"erro": "Recurso ou rota não encontrada"}), 404


@app.errorhandler(405)
def tratar_405(e):
    """Retorna resposta JSON padronizada para método HTTP não permitido."""
    return jsonify({"erro": "Método HTTP não permitido para esta rota"}), 405


@app.errorhandler(500)
def tratar_500(e):
    """Retorna mensagem genérica de erro interno sem expor detalhes sensíveis."""
    return jsonify({"erro": "Erro interno do servidor"}), 500


def iniciar_plataforma():
    """Inicializa bancos, servidor TCP de alertas em background e aplicação Flask."""
    inicializar_tabela_usuarios()
    _garantir_dados_iniciais()
    iniciar_servidor_background()
    porta_api = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=porta_api, debug=False)


if __name__ == "__main__":
    iniciar_plataforma()
