import time
import requests


def validar_ip(ip):
    """Verifica se uma string representa um endereço IPv4 válido."""
    if type(ip) is not str or not ip.strip():
        return False
    partes = ip.strip().split(".")
    if len(partes) != 4:
        return False
    for parte in partes:
        try:
            valor = int(parte)
            if not 0 <= valor <= 255:
                return False
        except ValueError:
            return False
    return True


def eh_ip_privado(ip):
    """Verifica se um IP pertence às faixas privadas RFC 1918."""
    if not validar_ip(ip):
        return False
    octetos = [int(p) for p in ip.strip().split(".")]
    if octetos[0] == 10:
        return True
    if octetos[0] == 172 and 16 <= octetos[1] <= 31:
        return True
    if octetos[0] == 192 and octetos[1] == 168:
        return True
    return False


def _requisicao_ipinfo(ip):
    """Realiza a chamada HTTP ao ipinfo.io com tratamento de rate limit (429)."""
    url = f"https://ipinfo.io/{ip}/json"
    for tentativa in range(3):
        try:
            resposta = requests.get(url, timeout=5)
            if resposta.status_code == 429:
                time.sleep(2 ** tentativa)
                continue
            resposta.raise_for_status()
            return resposta.json()
        except requests.exceptions.RequestException:
            break
    return None


def consultar_ip(ip, cache=None):
    """Consulta informações geográficas e de rede de um IP com suporte a cache."""
    if cache is None:
        cache = {}

    if not validar_ip(ip):
        return {
            "ip": ip, "valido": False, "tipo": "invalido",
            "cidade": "N/A", "regiao": "N/A", "pais": "N/A",
            "org": "IP inválido", "hostname": "N/A", "do_cache": False
        }

    if eh_ip_privado(ip):
        return {
            "ip": ip, "valido": True, "tipo": "privado",
            "cidade": "Rede Interna", "regiao": "Rede Interna", "pais": "LAN",
            "org": "Rede Interna", "hostname": "interno", "do_cache": False
        }

    if ip in cache:
        dados_cache = dict(cache[ip])
        dados_cache["do_cache"] = True
        return dados_cache

    dados = _requisicao_ipinfo(ip)
    if dados:
        info = {
            "ip": ip, "valido": True, "tipo": "publico",
            "cidade": dados.get("city", "Desconhecida"),
            "regiao": dados.get("region", "Desconhecida"),
            "pais": dados.get("country", "??"),
            "org": dados.get("org", "Desconhecida"),
            "hostname": dados.get("hostname", "N/A"),
            "do_cache": False
        }
        cache[ip] = dict(info)
        return info

    return {
        "ip": ip, "valido": True, "tipo": "publico",
        "cidade": "Indisponível", "regiao": "Indisponível", "pais": "??",
        "org": "Consulta externa indisponível", "hostname": "N/A", "do_cache": False
    }


def enriquecer_alertas(alertas, cache=None):
    """Adiciona informações de geolocalização a uma lista de alertas."""
    if cache is None:
        cache = {}

    alertas_enriquecidos = []
    for alerta in alertas:
        copia = dict(alerta)
        ip = copia.get("ip", "")
        copia["geolocalizacao"] = consultar_ip(ip, cache)
        alertas_enriquecidos.append(copia)
    return alertas_enriquecidos


def exibir_enriquecimento(dados_ip):
    """Exibe no terminal os dados enriquecidos de um endereço IP."""
    print(f"IP: {dados_ip.get('ip', 'N/A')}")
    print(f"  Tipo:     {dados_ip.get('tipo', 'N/A').upper()}")
    print(f"  Cidade:   {dados_ip.get('cidade', 'N/A')}")
    print(f"  Região:   {dados_ip.get('regiao', 'N/A')}")
    print(f"  País:     {dados_ip.get('pais', 'N/A')}")
    print(f"  Org:      {dados_ip.get('org', 'N/A')}")
    print(f"  Hostname: {dados_ip.get('hostname', 'N/A')}")
