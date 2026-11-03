import json


REGRAS_PADRAO = [
    {
        "id": "R001",
        "nome": "Login com Usuário Privilegiado",
        "descricao": "Tentativa de login com usuário root, admin, sa ou oracle",
        "fonte": "auth",
        "condicao": "usuario_privilegiado",
        "usuarios_alvo": ["root", "admin", "sa", "oracle", "administrator"],
        "severidade_base": 6,
        "ativa": True
    },
    {
        "id": "R002",
        "nome": "Acesso a Porta Crítica Bloqueado",
        "descricao": "Firewall bloqueou acesso a portas sensíveis",
        "fonte": "firewall",
        "condicao": "porta_critica",
        "portas_criticas": [22, 23, 3389, 445, 3306, 5432, 1433],
        "severidade_base": 7,
        "ativa": True
    },
    {
        "id": "R003",
        "nome": "Tentativa de Path Traversal",
        "descricao": "URL contém padrões de path traversal (../)",
        "fonte": "web",
        "condicao": "path_traversal",
        "padroes": ["../", "..\\", "/etc/passwd", "/etc/shadow"],
        "severidade_base": 9,
        "ativa": True
    },
    {
        "id": "R004",
        "nome": "Tentativa de XSS",
        "descricao": "URL contém padrões de Cross-Site Scripting",
        "fonte": "web",
        "condicao": "xss",
        "padroes": ["<script>", "javascript:", "onerror=", "onload="],
        "severidade_base": 8,
        "ativa": True
    },
    {
        "id": "R005",
        "nome": "Reconhecimento Web",
        "descricao": "Acesso a URLs comuns de reconhecimento/enumeração",
        "fonte": "web",
        "condicao": "reconhecimento",
        "urls_suspeitas": ["/wp-admin", "/phpmyadmin", "/shell.php", "/.env", "/admin", "/wp-login.php"],
        "severidade_base": 5,
        "ativa": True
    }
]


def carregar_regras(caminho_config):
    """Lê o arquivo regras.json e retorna lista de dicionários de regras."""
    try:
        with open(caminho_config, "r", encoding="utf-8") as f:
            dados = json.load(f)
            if type(dados) is dict and "regras" in dados:
                return dados["regras"]
            if type(dados) is list:
                return dados
            print("[ERRO] Estrutura de regras inválida. Usando regras padrão.")
            return list(REGRAS_PADRAO)
    except FileNotFoundError:
        print(f"[ERRO] Arquivo de regras não encontrado: {caminho_config}. Usando regras padrão.")
        return list(REGRAS_PADRAO)
    except json.JSONDecodeError:
        print(f"[ERRO] JSON inválido em {caminho_config}. Usando regras padrão.")
        return list(REGRAS_PADRAO)


def classificar_severidade(pontuacao):
    """Recebe pontuação numérica e retorna string de severidade."""
    if pontuacao >= 9:
        return "CRITICA"
    elif pontuacao >= 7:
        return "ALTA"
    elif pontuacao >= 5:
        return "MEDIA"
    elif pontuacao >= 3:
        return "BAIXA"
    return "INFO"


def _extrair_campos_detalhes(detalhes_str):
    """Extrai pares chave=valor de uma string de detalhes."""
    campos = {}
    for parte in str(detalhes_str).split():
        if "=" in parte:
            chave, valor = parte.split("=", 1)
            campos[chave] = valor
    return campos


def _verificar_condicao(regra, evento, campos, detalhes):
    """Verifica se a condição específica da regra foi violada pelo evento."""
    condicao = regra.get("condicao")
    if condicao == "usuario_privilegiado":
        usuario = campos.get("usuario", "")
        return evento.get("tipo") == "FAIL" and usuario in regra.get("usuarios_alvo", [])

    if condicao == "porta_critica":
        if evento.get("tipo") != "BLOCK":
            return False
        try:
            porta = int(campos.get("dport", -1))
            return porta in regra.get("portas_criticas", [])
        except ValueError:
            return False

    if condicao == "path_traversal":
        url = campos.get("url", detalhes)
        return any(padrao in url for padrao in regra.get("padroes", []))

    if condicao == "xss":
        url = campos.get("url", detalhes).lower()
        return any(p.lower() in url for p in regra.get("padroes", []))

    if condicao == "reconhecimento":
        url = campos.get("url", detalhes)
        return any(u in url for u in regra.get("urls_suspeitas", []))

    return False


def avaliar_regra(regra, evento):
    """Avalia se um evento viola uma regra específica e retorna alerta ou None."""
    if not regra.get("ativa", True) or regra.get("fonte") != evento.get("fonte"):
        return None

    detalhes = str(evento.get("detalhes", ""))
    campos = _extrair_campos_detalhes(detalhes)
    if not _verificar_condicao(regra, evento, campos, detalhes):
        return None

    pontuacao = regra.get("severidade_base", 5)
    condicao = str(regra.get("condicao", "regra")).upper()
    return {
        "timestamp": evento.get("timestamp", ""),
        "regra_id": regra.get("id", "R000"),
        "regra": regra.get("nome", "Regra"),
        "tipo": condicao,
        "severidade": classificar_severidade(pontuacao),
        "pontuacao": pontuacao,
        "ip": evento.get("ip", ""),
        "fonte": evento.get("fonte", ""),
        "descricao": f"{regra.get('descricao', '')} ({detalhes})"
    }


def aplicar_regras(eventos, regras):
    """Aplica todas as regras ativas à lista de eventos e retorna os alertas."""
    alertas = []
    regras_ativas = [r for r in regras if r.get("ativa", True)]
    for evento in eventos:
        for regra in regras_ativas:
            alerta = avaliar_regra(regra, evento)
            if alerta is not None:
                alertas.append(alerta)
    return alertas
