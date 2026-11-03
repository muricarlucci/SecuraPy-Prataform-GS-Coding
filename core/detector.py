BLACKLIST_PADRAO = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}


def _classificar_severidade_brute_force(tentativas):
    """Classifica a severidade do brute force conforme o total de falhas."""
    if tentativas > 20:
        return "CRITICA"
    elif tentativas >= 10:
        return "ALTA"
    elif tentativas >= 5:
        return "MEDIA"
    return "BAIXA"


def _classificar_severidade_port_scan(qtd_portas):
    """Classifica a severidade do port scan conforme o número de portas."""
    if qtd_portas >= 10:
        return "CRITICA"
    elif qtd_portas >= 5:
        return "ALTA"
    elif qtd_portas >= 3:
        return "MEDIA"
    return "BAIXA"


def detectar_brute_force(eventos, threshold=5):
    """Conta tentativas FAIL por IP nos eventos de auth acima do threshold."""
    contagem_por_ip = {}
    usuarios_por_ip = {}

    for evento in eventos:
        if evento.get("fonte") == "auth" and evento.get("tipo") == "FAIL":
            ip = evento.get("ip", "")
            contagem_por_ip[ip] = contagem_por_ip.get(ip, 0) + 1
            if ip not in usuarios_por_ip:
                usuarios_por_ip[ip] = []

            for parte in str(evento.get("detalhes", "")).split():
                if parte.startswith("usuario="):
                    usuario = parte.split("=", 1)[1]
                    if usuario not in usuarios_por_ip[ip]:
                        usuarios_por_ip[ip].append(usuario)

    resultado = {}
    for ip, tentativas in contagem_por_ip.items():
        if tentativas >= threshold:
            resultado[ip] = {
                "tentativas": tentativas,
                "usuarios": usuarios_por_ip.get(ip, []),
                "severidade": _classificar_severidade_brute_force(tentativas)
            }
    return resultado


def detectar_port_scan(eventos, threshold=3):
    """Conta portas únicas bloqueadas por IP nos eventos de firewall."""
    portas_por_ip = {}

    for evento in eventos:
        if evento.get("fonte") == "firewall" and evento.get("tipo") == "BLOCK":
            ip = evento.get("ip", "")
            if ip not in portas_por_ip:
                portas_por_ip[ip] = set()

            for parte in str(evento.get("detalhes", "")).split():
                if parte.startswith("dport="):
                    try:
                        portas_por_ip[ip].add(int(parte.split("=", 1)[1]))
                    except ValueError:
                        pass

    resultado = {}
    for ip, portas in portas_por_ip.items():
        quantidade = len(portas)
        if quantidade >= threshold:
            resultado[ip] = {
                "portas": set(portas),
                "quantidade": quantidade,
                "severidade": _classificar_severidade_port_scan(quantidade)
            }
    return resultado


def verificar_blacklist(eventos, blacklist=None):
    """Cruza IPs dos eventos com a blacklist usando interseção de conjuntos."""
    if blacklist is None:
        blacklist = BLACKLIST_PADRAO

    conjunto_blacklist = set(blacklist)
    ips_eventos = {e.get("ip") for e in eventos if e.get("ip")}
    ips_maliciosos = ips_eventos & conjunto_blacklist

    contagem_por_ip = {}
    for evento in eventos:
        ip = evento.get("ip")
        if ip in ips_maliciosos:
            contagem_por_ip[ip] = contagem_por_ip.get(ip, 0) + 1

    return ips_maliciosos, contagem_por_ip


def _Consolidar_ip(ip, brute_force, port_scan, conjunto_bl, contagem_bl):
    """Monta o dicionário consolidado de ameaça para um único IP."""
    pesos = {"INFO": 1, "BAIXA": 3, "MEDIA": 5, "ALTA": 7, "CRITICA": 9}
    motivos = []
    maior_peso = 0
    detalhes = {}

    if ip in brute_force:
        bf = brute_force[ip]
        motivos.append(f"Brute Force ({bf['tentativas']} falhas)")
        if pesos.get(bf["severidade"], 5) > maior_peso:
            maior_peso = pesos.get(bf["severidade"], 5)
        detalhes["brute_force"] = bf

    if ip in port_scan:
        ps = port_scan[ip]
        portas_lista = list(ps["portas"])
        portas_lista.sort()
        motivos.append(f"Port Scan ({ps['quantidade']} portas)")
        if pesos.get(ps["severidade"], 5) > maior_peso:
            maior_peso = pesos.get(ps["severidade"], 5)
        detalhes["port_scan"] = {
            "portas": portas_lista,
            "quantidade": ps["quantidade"],
            "severidade": ps["severidade"]
        }

    if ip in conjunto_bl:
        motivos.append("Presente na Blacklist")
        if 7 > maior_peso:
            maior_peso = 7
        detalhes["blacklist"] = {"eventos": contagem_bl.get(ip, 1)}

    qtd = len(motivos)
    pontuacao = 10 if qtd >= 3 else (maior_peso + 2 if qtd == 2 else maior_peso)
    sev = "CRITICA" if pontuacao >= 9 else ("ALTA" if pontuacao >= 7 else ("MEDIA" if pontuacao >= 5 else "BAIXA"))
    vol = (
        detalhes.get("brute_force", {}).get("tentativas", 0)
        + detalhes.get("port_scan", {}).get("quantidade", 0)
        + detalhes.get("blacklist", {}).get("eventos", 0)
    )
    return {
        "ip": ip,
        "motivos": motivos,
        "qtd_deteccoes": qtd,
        "severidade": sev,
        "pontuacao": pontuacao,
        "volume_eventos": vol,
        "detalhes": detalhes
    }


def gerar_resumo_ameacas(brute_force, port_scan, ips_blacklist):
    """Consolida todas as detecções em uma lista ordenada por severidade."""
    if type(ips_blacklist) is tuple:
        conjunto_bl, contagem_bl = ips_blacklist
    elif type(ips_blacklist) is dict:
        conjunto_bl = set(ips_blacklist.keys())
        contagem_bl = ips_blacklist
    else:
        conjunto_bl = set(ips_blacklist)
        contagem_bl = {ip: 1 for ip in conjunto_bl}

    todos_ips = set(brute_force.keys()) | set(port_scan.keys()) | conjunto_bl
    resumo = [_Consolidar_ip(ip, brute_force, port_scan, conjunto_bl, contagem_bl) for ip in todos_ips]
    resumo.sort(key=lambda x: (x["pontuacao"], x["qtd_deteccoes"], x["volume_eventos"]), reverse=True)
    return resumo
