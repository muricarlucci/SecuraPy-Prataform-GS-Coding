import os
import json
from datetime import datetime
from core.enriquecimento import consultar_ip, exibir_enriquecimento
from core.detector import BLACKLIST_PADRAO


def exibir_menu():
    """Exibe o menu principal no terminal e retorna a opção validada."""
    print("\n╔══════════════════════════════════════════╗")
    print("║         SecuraPy SIEM — Menu             ║")
    print("╠══════════════════════════════════════════╣")
    print("║  1. Carregar e processar logs            ║")
    print("║  2. Resumo geral                         ║")
    print("║  3. Filtrar eventos                      ║")
    print("║  4. Buscar IP                            ║")
    print("║  5. Top 10 IPs suspeitos                 ║")
    print("║  6. Ver alertas por severidade           ║")
    print("║  7. Enriquecer IPs suspeitos             ║")
    print("║  8. Exportar relatório JSON              ║")
    print("║  9. Iniciar servidor de alertas          ║")
    print("║  0. Sair                                 ║")
    print("╚══════════════════════════════════════════╝")

    try:
        escolha = input("Escolha uma opção: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nEntrada encerrada pelo operador.")
        return 0

    try:
        opcao = int(escolha)
        if 0 <= opcao <= 9:
            return opcao
        print("Opção inválida! Digite um número entre 0 e 9.")
        return -1
    except ValueError:
        print("Opção inválida! Digite apenas números.")
        return -1


def resumo_geral(eventos, alertas):
    """Exibe contadores gerais de eventos por fonte e alertas por severidade."""
    por_fonte = {"auth": 0, "firewall": 0, "web": 0}
    for e in eventos:
        fonte = e.get("fonte", "outro")
        por_fonte[fonte] = por_fonte.get(fonte, 0) + 1

    por_severidade = {"CRITICA": 0, "ALTA": 0, "MEDIA": 0, "BAIXA": 0, "INFO": 0}
    for a in alertas:
        sev = a.get("severidade", "INFO").upper()
        por_severidade[sev] = por_severidade.get(sev, 0) + 1

    print("\n=== Resumo Geral SecuraPy ===")
    print(
        f"Eventos por fonte -> auth: {por_fonte['auth']} | "
        f"firewall: {por_fonte['firewall']} | web: {por_fonte['web']} | "
        f"Total: {len(eventos)}"
    )
    print(
        f"Alertas por severidade -> CRITICA: {por_severidade['CRITICA']} | "
        f"ALTA: {por_severidade['ALTA']} | MEDIA: {por_severidade['MEDIA']} | "
        f"BAIXA: {por_severidade['BAIXA']} | INFO: {por_severidade['INFO']} | "
        f"Total: {len(alertas)}"
    )
    return {"eventos_por_fonte": por_fonte, "alertas_por_severidade": por_severidade}


def filtrar_eventos(eventos, fonte=None, tipo=None, ip=None):
    """Filtra a lista de eventos por fonte, tipo e endereço IP."""
    filtrados = list(eventos)
    if fonte:
        filtrados = [e for e in filtrados if e.get("fonte", "").lower() == fonte.lower()]
    if tipo:
        filtrados = [e for e in filtrados if e.get("tipo", "").upper() == tipo.upper()]
    if ip:
        filtrados = [e for e in filtrados if e.get("ip") == ip]
    return filtrados


def buscar_ip(ip, eventos, alertas, cache_enriquecimento):
    """Exibe relatório completo de um IP com eventos, alertas e geolocalização."""
    eventos_ip = [e for e in eventos if e.get("ip") == ip]
    alertas_ip = [a for a in alertas if a.get("ip") == ip]
    geo = consultar_ip(ip, cache_enriquecimento)

    print(f"\n=== Relatório do IP: {ip} ===")
    exibir_enriquecimento(geo)
    print(f"\nEventos encontrados ({len(eventos_ip)}):")
    for ev in eventos_ip:
        print(f"  [{ev['timestamp']}] [{ev['fonte']}] {ev['tipo']} - {ev['detalhes']}")

    print(f"\nAlertas relacionados ({len(alertas_ip)}):")
    for al in alertas_ip:
        print(f"  [{al['timestamp']}] [{al['severidade']}] {al.get('regra', al.get('tipo'))} - {al['descricao']}")

    return {"ip": ip, "geolocalizacao": geo, "eventos": eventos_ip, "alertas": alertas_ip}


def top_ips(eventos, n=10, blacklist=None):
    """Retorna os N IPs com mais eventos e sua classificação de ameaça."""
    if blacklist is None:
        blacklist = BLACKLIST_PADRAO

    contadores = {}
    falhas_por_ip = {}
    for ev in eventos:
        ip = ev.get("ip", "")
        if not ip:
            continue
        contadores[ip] = contadores.get(ip, 0) + 1
        if ev.get("tipo") in ("FAIL", "BLOCK") or "status=4" in ev.get("detalhes", ""):
            falhas_por_ip[ip] = falhas_por_ip.get(ip, 0) + 1

    ranking = []
    for ip, total in contadores.items():
        falhas = falhas_por_ip.get(ip, 0)
        na_bl = ip in blacklist
        status_ameaca = "ALTA AMEAÇA" if (na_bl or falhas >= 10) else ("SUSPEITO" if falhas >= 3 else "NORMAL")
        ranking.append({
            "ip": ip, "eventos": total, "eventos_suspeitos": falhas,
            "na_blacklist": na_bl, "classificacao": status_ameaca
        })

    ranking.sort(key=lambda x: x["eventos"], reverse=True)
    return ranking[:n]


def exibir_tabela(dados, colunas):
    """Exibe uma lista de dicionários como tabela formatada no terminal."""
    if not dados:
        print("Nenhum registro encontrado.")
        return

    cabecalho = " | ".join(f"{col:<18}" for col in colunas)
    print(cabecalho)
    print("-" * len(cabecalho))
    for item in dados:
        linha = " | ".join(f"{str(item.get(col, '')):<18}" for col in colunas)
        print(linha)


def exportar_relatorio_json(dados, caminho=None):
    """Salva o dicionário de relatório em um arquivo JSON formatado."""
    if caminho is None:
        os.makedirs("saida", exist_ok=True)
        nome = datetime.now().strftime("relatorio_%Y%m%d_%H%M%S.json")
        caminho = os.path.join("saida", nome)
    else:
        pasta = os.path.dirname(caminho)
        if pasta:
            os.makedirs(pasta, exist_ok=True)

    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(dados, f, indent=2, ensure_ascii=False)

    print(f"Relatório exportado com sucesso em: {caminho}")
    return caminho
