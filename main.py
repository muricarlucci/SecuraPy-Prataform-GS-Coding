import os
import sys
from datetime import datetime

os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")

RAIZ_PROJETO = os.path.dirname(os.path.abspath(__file__))
if RAIZ_PROJETO not in sys.path:
    sys.path.insert(0, RAIZ_PROJETO)

from core.coletor import carregar_log
from core.regras import carregar_regras, aplicar_regras
from core.detector import (
    BLACKLIST_PADRAO,
    detectar_brute_force,
    detectar_port_scan,
    verificar_blacklist,
    gerar_resumo_ameacas
)
from core.enriquecimento import consultar_ip, exibir_enriquecimento
from core.relatorios import (
    exibir_menu,
    resumo_geral,
    filtrar_eventos,
    buscar_ip,
    top_ips,
    exportar_relatorio_json,
    exibir_tabela
)
from db.mongo_repo import criar_indices, salvar_eventos, salvar_alertas
from db.mysql_repo import inicializar_tabela_usuarios
from ml.treinar import treinar_e_salvar_modelo
from ml.classificar import classificar_ip, pontuar_ameacas
from ia.assistente import explicar_ip_ia
from alertas.servidor_alertas import iniciar_servidor, enviar_alerta_remoto


PASTA_LOGS = os.path.join(RAIZ_PROJETO, "logs")
ARQUIVO_REGRAS = os.path.join(RAIZ_PROJETO, "config", "regras.json")
PASTA_SAIDA = os.path.join(RAIZ_PROJETO, "saida")
BLACKLIST = set(BLACKLIST_PADRAO)


def _ler_entrada(texto):
    """Lê entrada do terminal tratando interrupção de fluxo com segurança."""
    try:
        return input(texto).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def _notificar_ameacas_criticas(ameacas_ml):
    """Dispara notificações via socket TCP para ameaças de severidade alta ou crítica."""
    for ameaca in ameacas_ml:
        if ameaca.get("severidade") in ("CRITICA", "ALTA"):
            enviar_alerta_remoto({
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "severidade": ameaca["severidade"],
                "regra": "Correlação SecuraPy",
                "ip": ameaca["ip"],
                "descricao": ", ".join(ameaca["motivos"])
            })


def processar_pipeline_completo(cache_enriquecimento=None):
    """Executa coleta, regras, detecção comportamental, ML e persistência."""
    if cache_enriquecimento is None:
        cache_enriquecimento = {}
    ev_auth = carregar_log(os.path.join(PASTA_LOGS, "auth.log"), "auth")
    ev_fw = carregar_log(os.path.join(PASTA_LOGS, "firewall.log"), "firewall")
    ev_web = carregar_log(os.path.join(PASTA_LOGS, "web_access.log"), "web")
    eventos = ev_auth + ev_fw + ev_web
    print(
        f"{len(ev_auth)} eventos de auth, {len(ev_fw)} de firewall, "
        f"{len(ev_web)} de web. Total: {len(eventos)} eventos"
    )
    regras = carregar_regras(ARQUIVO_REGRAS)
    alertas_regras = aplicar_regras(eventos, regras)
    brute_force = detectar_brute_force(eventos)
    port_scan = detectar_port_scan(eventos)
    ips_bl, contagem_bl = verificar_blacklist(eventos, BLACKLIST)
    resumo_ameacas = gerar_resumo_ameacas(brute_force, port_scan, (ips_bl, contagem_bl))
    ameacas_ml = pontuar_ameacas(resumo_ameacas, eventos, BLACKLIST)
    inicializar_tabela_usuarios()
    criar_indices()
    salvar_eventos(eventos, limpar_antes=True)
    salvar_alertas(alertas_regras, limpar_antes=True)
    _notificar_ameacas_criticas(ameacas_ml)
    return {
        "eventos": eventos,
        "alertas": alertas_regras,
        "brute_force": brute_force,
        "port_scan": port_scan,
        "ips_blacklist": ips_bl,
        "contagem_blacklist": contagem_bl,
        "resumo_ameacas": ameacas_ml
    }


def _serializar_port_scan(port_scan):
    """Converte conjuntos de portas em listas ordenadas para exportação JSON."""
    serializavel = {}
    for ip, dados in port_scan.items():
        portas = list(dados["portas"])
        portas.sort()
        serializavel[ip] = {
            "portas": portas,
            "quantidade": dados["quantidade"],
            "severidade": dados["severidade"]
        }
    return serializavel


def gerar_relatorio_completo(estado, cache_enriquecimento):
    """Consolida estatísticas, detecções, enriquecimento e alertas em dicionário."""
    eventos = estado["eventos"]
    alertas = estado["alertas"]
    ameacas = estado["resumo_ameacas"]
    por_fonte = {"auth": 0, "firewall": 0, "web": 0}
    for e in eventos:
        f = e.get("fonte", "outro")
        por_fonte[f] = por_fonte.get(f, 0) + 1
    por_severidade = {"CRITICA": 0, "ALTA": 0, "MEDIA": 0, "BAIXA": 0, "INFO": 0}
    for a in alertas:
        s = a.get("severidade", "INFO").upper()
        por_severidade[s] = por_severidade.get(s, 0) + 1
    ips_enriquecidos = {}
    for ameaca in ameacas:
        ip = ameaca["ip"]
        ips_enriquecidos[ip] = consultar_ip(ip, cache_enriquecimento)
    ips_bl_lista = list(estado["ips_blacklist"])
    ips_bl_lista.sort()
    return {
        "gerado_em": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "plataforma": "SecuraPy Platform v2.0",
        "resumo": {
            "total_eventos": len(eventos),
            "eventos_por_fonte": por_fonte,
            "total_alertas": len(alertas),
            "alertas_por_severidade": por_severidade
        },
        "deteccoes": {
            "brute_force": estado["brute_force"],
            "port_scan": _serializar_port_scan(estado["port_scan"]),
            "ips_blacklist": ips_bl_lista
        },
        "ameacas_priorizadas_ml": ameacas,
        "enriquecimento_ips_suspeitos": ips_enriquecidos,
        "top_10_ips": top_ips(eventos, 10, BLACKLIST),
        "alertas": alertas
    }


def _executar_opcao_consulta(opcao, estado, cache_enriquecimento):
    """Processa as opções de relatório e consulta (2 a 8) do menu principal."""
    if opcao == 2:
        resumo_geral(estado["eventos"], estado["alertas"])
    elif opcao == 3:
        fonte = _ler_entrada("Fonte (auth/firewall/web ou Enter para todas): ") or None
        tipo = _ler_entrada("Tipo (FAIL/OK/BLOCK/ALLOW/REQUEST ou Enter para todos): ") or None
        ip = _ler_entrada("IP específico (ou Enter para todos): ") or None
        filtrados = filtrar_eventos(estado["eventos"], fonte=fonte, tipo=tipo, ip=ip)
        print(f"\nEventos encontrados: {len(filtrados)}")
        exibir_tabela(filtrados[:25], ["timestamp", "fonte", "tipo", "ip", "detalhes"])
    elif opcao == 4:
        ip = _ler_entrada("Digite o IP para busca completa: ")
        rel = buscar_ip(ip, estado["eventos"], estado["alertas"], cache_enriquecimento)
        ml_info = classificar_ip(ip, estado["eventos"], BLACKLIST)
        ia_info = explicar_ip_ia(ip, rel["eventos"], rel["alertas"], ml_info)
        print(f"\nClassificação ML: {ml_info['rotulo'].upper()} (Score: {ml_info['score_risco']}% - {ml_info['nivel_risco']})")
        print(f"Assistente IA [{ia_info['classificacao']}]: {ia_info['explicacao']}")
    elif opcao == 5:
        ranking = top_ips(estado["eventos"], 10, BLACKLIST)
        print("\n=== Top 10 IPs Monitorados ===")
        exibir_tabela(ranking, ["ip", "eventos", "eventos_suspeitos", "classificacao"])
    elif opcao == 6:
        sev = _ler_entrada("Filtrar severidade (CRITICA/ALTA/MEDIA/BAIXA ou Enter): ").upper()
        lista_al = [a for a in estado["alertas"] if not sev or a.get("severidade") == sev]
        exibir_tabela(lista_al, ["timestamp", "severidade", "regra", "ip", "descricao"])
    elif opcao == 7:
        print("\n=== Enriquecimento de IPs Suspeitos ===")
        for ameaca in estado["resumo_ameacas"]:
            exibir_enriquecimento(consultar_ip(ameaca["ip"], cache_enriquecimento))
            print()
    elif opcao == 8:
        os.makedirs(PASTA_SAIDA, exist_ok=True)
        caminho = os.path.join(PASTA_SAIDA, datetime.now().strftime("relatorio_%Y%m%d_%H%M%S.json"))
        exportar_relatorio_json(gerar_relatorio_completo(estado, cache_enriquecimento), caminho)


def menu_interativo():
    """Executa o laço interativo principal do sistema SIEM em modo console."""
    estado = {
        "eventos": [],
        "alertas": [],
        "brute_force": {},
        "port_scan": {},
        "ips_blacklist": set(),
        "contagem_blacklist": {},
        "resumo_ameacas": []
    }
    cache_enriquecimento = {}
    while True:
        opcao = exibir_menu()
        if opcao == -1:
            continue
        if opcao == 0:
            print("Encerrando SecuraPy. Até logo!")
            break
        if opcao == 1:
            estado = processar_pipeline_completo(cache_enriquecimento)
            print(f"Alertas de regras gerados: {len(estado['alertas'])}")
            print(f"IPs suspeitos consolidados: {len(estado['resumo_ameacas'])}")
            continue
        if opcao == 9:
            iniciar_servidor()
            continue
        if not estado["eventos"]:
            print("Carregue os logs primeiro (opção 1)")
            continue
        _executar_opcao_consulta(opcao, estado, cache_enriquecimento)


def main():
    """Ponto de entrada da plataforma SecuraPy (modos --api, --batch ou interativo)."""
    if len(sys.argv) > 1 and sys.argv[1] == "--api":
        from api.app import iniciar_plataforma
        iniciar_plataforma()
    elif len(sys.argv) > 1 and sys.argv[1] == "--batch":
        treinar_e_salvar_modelo(PASTA_LOGS)
        cache = {}
        estado = processar_pipeline_completo(cache)
        dados_rel = gerar_relatorio_completo(estado, cache)
        caminho_exemplo = os.path.join(PASTA_SAIDA, "relatorio_exemplo.json")
        exportar_relatorio_json(dados_rel, caminho_exemplo)
    else:
        menu_interativo()


if __name__ == "__main__":
    main()
