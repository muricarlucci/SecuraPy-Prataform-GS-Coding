import os
import sys

RAIZ_PROJETO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if RAIZ_PROJETO not in sys.path:
    sys.path.insert(0, RAIZ_PROJETO)

from core.coletor import carregar_todos_os_logs
from core.regras import carregar_regras, aplicar_regras
from core.detector import (
    BLACKLIST_PADRAO,
    detectar_brute_force,
    detectar_port_scan,
    verificar_blacklist,
    gerar_resumo_ameacas
)
from db.mongo_repo import criar_indices, salvar_eventos, salvar_alertas, top_ips_eventos
from db.mysql_repo import inicializar_tabela_usuarios
from ml.classificar import classificar_ip, pontuar_ameacas


def _gerar_alertas_correlacao(ameacas_pontuadas, timestamp_ref):
    """Cria alertas consolidados a partir das ameaças priorizadas."""
    alertas = []
    for ameaca in ameacas_pontuadas:
        ip = ameaca["ip"]
        motivos_str = ", ".join(ameaca["motivos"])
        alertas.append({
            "timestamp": timestamp_ref,
            "regra_id": "CORR",
            "regra": "Correlação de Ameaças",
            "tipo": "CORRELACAO",
            "severidade": ameaca["severidade"],
            "pontuacao": ameaca["pontuacao"],
            "ip": ip,
            "fonte": "correlacao",
            "score_risco_ml": ameaca.get("score_risco_ml", 0.0),
            "descricao": f"Ameaça consolidada: {motivos_str} (Score ML: {ameaca.get('score_risco_ml', 0)}%)"
        })
    return alertas


def _anexar_scores_alertas(lista_alertas, eventos):
    """Adiciona score de risco e rótulo ML a cada alerta."""
    todos_alertas = []
    scores_cache = {}
    for al in lista_alertas:
        ip = al.get("ip", "")
        if ip and ip not in scores_cache:
            scores_cache[ip] = classificar_ip(ip, eventos, BLACKLIST_PADRAO)
        info_ml = scores_cache.get(ip, {})
        copia = dict(al)
        copia["score_risco_ml"] = info_ml.get("score_risco", 0.0)
        copia["rotulo_ml"] = info_ml.get("rotulo", "normal")
        todos_alertas.append(copia)
    return todos_alertas


def _formatar_port_scan(port_scan):
    """Converte conjuntos de portas de port scan em listas ordenadas."""
    port_scan_fmt = {}
    for ip, d in port_scan.items():
        portas_ord = list(d["portas"])
        portas_ord.sort()
        port_scan_fmt[ip] = {"portas": portas_ord, "quantidade": d["quantidade"], "severidade": d["severidade"]}
    return port_scan_fmt


def executar_ingestao(pasta_logs=None, caminho_regras=None):
    """Carrega os logs, aplica regras e detecções, pontua com ML e persiste nos bancos."""
    pasta_logs = pasta_logs or os.path.join(RAIZ_PROJETO, "logs")
    caminho_regras = caminho_regras or os.path.join(RAIZ_PROJETO, "config", "regras.json")
    inicializar_tabela_usuarios()
    criar_indices()
    eventos = carregar_todos_os_logs(pasta_logs)
    alertas_regras = aplicar_regras(eventos, carregar_regras(caminho_regras))
    brute_force = detectar_brute_force(eventos)
    port_scan = detectar_port_scan(eventos)
    ips_bl, contagem_bl = verificar_blacklist(eventos, BLACKLIST_PADRAO)
    resumo_ameacas = gerar_resumo_ameacas(brute_force, port_scan, (ips_bl, contagem_bl))
    ameacas_pontuadas = pontuar_ameacas(resumo_ameacas, eventos, BLACKLIST_PADRAO)
    ts_ref = eventos[-1]["timestamp"] if eventos else "2025-02-20 08:20:35"
    alertas_correlacao = _gerar_alertas_correlacao(ameacas_pontuadas, ts_ref)
    todos_alertas = _anexar_scores_alertas(alertas_regras + alertas_correlacao, eventos)
    qtd_eventos = salvar_eventos(eventos, limpar_antes=True)
    qtd_alertas = salvar_alertas(todos_alertas, limpar_antes=True)
    bl_lista = list(ips_bl)
    bl_lista.sort()
    return {
        "eventos_ingeridos": qtd_eventos,
        "alertas_gerados": qtd_alertas,
        "alertas_regras": len(alertas_regras),
        "alertas_correlacao": len(alertas_correlacao),
        "brute_force": brute_force,
        "port_scan": _formatar_port_scan(port_scan),
        "blacklist_encontrados": bl_lista,
        "ameacas_priorizadas": ameacas_pontuadas,
        "top_ips": top_ips_eventos(5)
    }


if __name__ == "__main__":
    resultado = executar_ingestao()
    print(f"Eventos persistidos: {resultado['eventos_ingeridos']}")
    print(f"Alertas persistidos: {resultado['alertas_gerados']}")
    print("Top 5 IPs por eventos:")
    for item in resultado["top_ips"]:
        print(f"  {item['ip']:<15} -> {item['total']} eventos")
