import os
import time
import hashlib


DURACAO_TOKEN_SEGUNDOS = 3600
tokens_ativos = {}


def gerar_token_sessao(identificador, nivel_acesso=1):
    """Gera um token Bearer criptograficamente seguro com expiração de 1 hora."""
    agora = time.time()
    entropia = os.urandom(32).hex()
    semente = f"{identificador}:{agora}:{entropia}"
    novo_token = hashlib.sha256(semente.encode("utf-8")).hexdigest()
    tokens_ativos[novo_token] = {
        "usuario": str(identificador),
        "nivel_acesso": int(nivel_acesso),
        "expira_em": agora + DURACAO_TOKEN_SEGUNDOS
    }
    return novo_token


def remover_token(token):
    """Remove um token de sessão ativo no logout."""
    if token in tokens_ativos:
        del tokens_ativos[token]


def _obter_dados_token(token):
    """Retorna os metadados do token caso seja válido e dentro do prazo de expiração."""
    if type(token) is not str or not token.strip():
        return None
    token_limpo = token.strip()

    token_env = os.environ.get("SECURAPY_API_TOKEN", "").strip()
    if token_env and token_limpo == token_env:
        return {"usuario": "token_ambiente", "nivel_acesso": 5}

    dados = tokens_ativos.get(token_limpo)
    if not dados:
        return None

    if time.time() >= dados["expira_em"]:
        del tokens_ativos[token_limpo]
        return None

    return dados


def obter_usuario_por_token(token):
    """Retorna o identificador do operador caso o token seja válido e não expirado."""
    dados = _obter_dados_token(token)
    return dados["usuario"] if dados else None


def validar_token(token):
    """Verifica se o token informado está ativo e dentro da validade."""
    return _obter_dados_token(token) is not None


def extrair_e_validar_bearer(request_obj):
    """Extrai o header Authorization Bearer da requisição e valida o token."""
    cabecalho = request_obj.headers.get("Authorization", "")
    if type(cabecalho) is not str or not cabecalho.startswith("Bearer "):
        return False
    token = cabecalho.replace("Bearer ", "", 1).strip()
    return validar_token(token)


def obter_nivel_bearer(request_obj):
    """Retorna o nível de acesso associado ao token Bearer da requisição."""
    cabecalho = request_obj.headers.get("Authorization", "")
    if type(cabecalho) is not str or not cabecalho.startswith("Bearer "):
        return 0
    token = cabecalho.replace("Bearer ", "", 1).strip()
    dados = _obter_dados_token(token)
    return int(dados.get("nivel_acesso", 0)) if dados else 0


def obter_operador_requisicao(request_obj):
    """Obtém o operador autenticado pelo cookie de sessão do cliente ou Bearer token."""
    token_cookie = request_obj.cookies.get("securapy_sessao", "")
    usuario = obter_usuario_por_token(token_cookie)
    if usuario:
        return usuario

    cabecalho = request_obj.headers.get("Authorization", "")
    if type(cabecalho) is str and cabecalho.startswith("Bearer "):
        token = cabecalho.replace("Bearer ", "", 1).strip()
        return obter_usuario_por_token(token)

    return None
