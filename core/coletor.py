import os


def _extrair_chave_valor(partes):
    """Converte uma lista de strings no formato chave=valor em dicionário."""
    campos = {}
    for item in partes:
        if "=" not in item:
            raise ValueError("Campo chave=valor inválido")
        chave, valor = item.split("=", 1)
        campos[chave] = valor
    return campos


def parsear_linha_auth(linha):
    """Parseia uma linha do auth.log e retorna dicionário normalizado."""
    texto = linha.strip()
    if not texto:
        return None

    partes = texto.split()
    if len(partes) < 5:
        raise ValueError("Formato inválido para log de autenticação")

    timestamp = f"{partes[0]} {partes[1]}"
    tipo = partes[2]
    if tipo not in ("OK", "FAIL"):
        raise ValueError("Tipo de evento auth inválido")

    campos = _extrair_chave_valor(partes[3:])
    if "usuario" not in campos or "ip" not in campos:
        raise ValueError("Campos obrigatórios ausentes em auth.log")

    return {
        "timestamp": timestamp,
        "fonte": "auth",
        "tipo": tipo,
        "ip": campos["ip"],
        "detalhes": f"usuario={campos['usuario']}",
        "linha_original": texto
    }


def parsear_linha_firewall(linha):
    """Parseia uma linha do firewall.log e retorna dicionário normalizado."""
    texto = linha.strip()
    if not texto:
        return None

    partes = texto.split()
    if len(partes) < 7:
        raise ValueError("Formato inválido para log de firewall")

    timestamp = f"{partes[0]} {partes[1]}"
    acao = partes[2]
    if acao not in ("ALLOW", "BLOCK"):
        raise ValueError("Ação de firewall inválida")

    campos = _extrair_chave_valor(partes[3:])
    if "src" not in campos or "dport" not in campos or "proto" not in campos:
        raise ValueError("Campos obrigatórios ausentes em firewall.log")

    int(campos["dport"])
    detalhes = f"proto={campos['proto']} dst={campos.get('dst', '')} dport={campos['dport']}"
    return {
        "timestamp": timestamp,
        "fonte": "firewall",
        "tipo": acao,
        "ip": campos["src"],
        "detalhes": detalhes,
        "linha_original": texto
    }


def parsear_linha_web(linha):
    """Parseia uma linha do web_access.log e retorna dicionário normalizado."""
    texto = linha.strip()
    if not texto:
        return None

    partes = texto.split()
    if len(partes) < 6:
        raise ValueError("Formato inválido para log web")

    timestamp = f"{partes[0]} {partes[1]}"
    metodo = partes[2]
    if metodo not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
        raise ValueError("Método HTTP inválido")

    campos = _extrair_chave_valor(partes[3:])
    if "url" not in campos or "ip" not in campos or "status" not in campos:
        raise ValueError("Campos obrigatórios ausentes em web_access.log")

    int(campos["status"])
    detalhes = f"metodo={metodo} url={campos['url']} status={campos['status']}"
    return {
        "timestamp": timestamp,
        "fonte": "web",
        "tipo": "REQUEST",
        "ip": campos["ip"],
        "detalhes": detalhes,
        "linha_original": texto
    }


def carregar_log(caminho_arquivo, fonte):
    """Lê um arquivo de log e retorna lista de eventos normalizados."""
    eventos = []
    parsers = {
        "auth": parsear_linha_auth,
        "firewall": parsear_linha_firewall,
        "web": parsear_linha_web
    }
    if fonte not in parsers:
        print(f"[ERRO] Fonte desconhecida: {fonte}")
        return eventos

    try:
        with open(caminho_arquivo, "r", encoding="utf-8") as f:
            linhas = f.readlines()
    except FileNotFoundError:
        print(f"[ERRO] Arquivo não encontrado: {caminho_arquivo}")
        return eventos
    except OSError as e:
        print(f"[ERRO] Falha ao ler {caminho_arquivo}: {e}")
        return eventos

    if not linhas or all(not l.strip() for l in linhas):
        print(f"[INFO] Arquivo de log vazio: {caminho_arquivo}")
        return eventos

    funcao_parser = parsers[fonte]
    numero = 0
    for linha in linhas:
        numero += 1
        if not linha.strip():
            continue
        try:
            evento = funcao_parser(linha)
            if evento:
                eventos.append(evento)
        except (ValueError, IndexError, KeyError) as e:
            print(f"[WARNING] Linha {numero} ignorada em {caminho_arquivo}: {e}")

    return eventos


def carregar_todos_os_logs(pasta_logs):
    """Lê todos os arquivos de log da pasta e retorna lista unificada."""
    todos_eventos = []
    if not os.path.exists(pasta_logs):
        print(f"[ERRO] Pasta de logs não encontrada: {pasta_logs}")
        return todos_eventos

    mapeamento = {
        "auth.log": "auth",
        "firewall.log": "firewall",
        "web_access.log": "web"
    }
    arquivos_pasta = os.listdir(pasta_logs)
    arquivos_pasta.sort()

    for nome_arquivo in arquivos_pasta:
        if nome_arquivo in mapeamento:
            caminho = os.path.join(pasta_logs, nome_arquivo)
            fonte = mapeamento[nome_arquivo]
            todos_eventos.extend(carregar_log(caminho, fonte))

    return todos_eventos
