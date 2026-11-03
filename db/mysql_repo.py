import os
import time
import socket
import hashlib
from datetime import datetime
import mysql.connector
from mysql.connector import Error


MYSQL_HOST = os.environ.get("MYSQL_HOST", "localhost")
MYSQL_PORT = int(os.environ.get("MYSQL_PORT", "3306"))
MYSQL_USER = os.environ.get("MYSQL_USER", "root")
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "senha")
MYSQL_DATABASE = os.environ.get("MYSQL_DATABASE", "seguranca")


def gerar_hash_senha(senha):
    """Gera o hash SHA-256 de uma senha em texto."""
    return hashlib.sha256(str(senha).encode("utf-8")).hexdigest()


def _usuarios_padrao():
    """Retorna a lista inicial de operadores da plataforma."""
    agora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return [
        {
            "id": 1, "nome": "admin", "email": "admin@securapy.com",
            "senha_hash": gerar_hash_senha("Cyber@2024"), "nivel_acesso": 5, "criado_em": agora
        },
        {
            "id": 2, "nome": "analista", "email": "analista@securapy.com",
            "senha_hash": gerar_hash_senha("S3gur4nca!"), "nivel_acesso": 3, "criado_em": agora
        },
        {
            "id": 3, "nome": "operador", "email": "operador@securapy.com",
            "senha_hash": gerar_hash_senha("Mudar@123"), "nivel_acesso": 1, "criado_em": agora
        }
    ]


_memoria_mysql = {
    "proximo_id": 4,
    "usuarios": _usuarios_padrao(),
    "aviso_exibido": False,
    "offline_ate": 0.0
}


def _porta_mysql_ativa():
    """Verifica via socket se a porta do MySQL está acessível."""
    agora = time.time()
    if agora < _memoria_mysql["offline_ate"]:
        return False
    host = "127.0.0.1" if MYSQL_HOST == "localhost" else MYSQL_HOST
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    try:
        sock.connect((host, MYSQL_PORT))
        ativo = True
    except OSError:
        ativo = False
        _memoria_mysql["offline_ate"] = agora + 5.0
    finally:
        sock.close()
    return ativo


def _conectar_mysql():
    """Estabelece conexão com o servidor MySQL."""
    if not _porta_mysql_ativa():
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise Error("Serviço MySQL indisponível")
        if not _memoria_mysql["aviso_exibido"]:
            print("[AVISO] MySQL indisponível; operando em contingência de sessão.")
            _memoria_mysql["aviso_exibido"] = True
        raise Error("Contingência ativa")

    return mysql.connector.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE
    )


def inicializar_tabela_usuarios():
    """Cria a tabela usuarios no MySQL e cadastra os operadores iniciais."""
    try:
        conexao = _conectar_mysql()
        cursor = conexao.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INT AUTO_INCREMENT PRIMARY KEY,
                nome VARCHAR(100) NOT NULL,
                email VARCHAR(150) NOT NULL UNIQUE,
                senha_hash VARCHAR(64) NOT NULL,
                nivel_acesso INT DEFAULT 1,
                criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        for u in _usuarios_padrao():
            cursor.execute("SELECT id FROM usuarios WHERE email = %s", (u["email"],))
            if cursor.fetchone() is None:
                cursor.execute(
                    "INSERT INTO usuarios (nome, email, senha_hash, nivel_acesso) VALUES (%s, %s, %s, %s)",
                    (u["nome"], u["email"], u["senha_hash"], u["nivel_acesso"])
                )
        conexao.commit()
        cursor.close()
        conexao.close()
        return True
    except Error:
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise
        return False


def _validar_dados_usuario(nome, email, senha, nivel_acesso):
    """Valida tipos e valores para criação de usuário."""
    if type(nome) is not str or type(email) is not str or type(senha) is not str:
        raise ValueError("Nome, email e senha devem ser textos válidos.")
    if not nome.strip() or not email.strip() or not senha.strip():
        raise ValueError("Nome, email e senha são obrigatórios.")
    if type(nivel_acesso) is bool:
        raise ValueError("Nível de acesso inválido. Deve ser entre 1 e 5.")
    try:
        nivel = int(nivel_acesso)
    except (ValueError, TypeError):
        raise ValueError("Nível de acesso inválido. Deve ser entre 1 e 5.")
    if not 1 <= nivel <= 5:
        raise ValueError("Nível de acesso inválido. Deve ser entre 1 e 5.")
    return nivel


def criar_usuario(nome, email, senha, nivel_acesso=1):
    """Cadastra um novo usuário exigindo nome, email e senha com query parametrizada."""
    nivel = _validar_dados_usuario(nome, email, senha, nivel_acesso)
    senha_hash = gerar_hash_senha(senha)

    try:
        conexao = _conectar_mysql()
        cursor = conexao.cursor()
        try:
            cursor.execute(
                "INSERT INTO usuarios (nome, email, senha_hash, nivel_acesso) VALUES (%s, %s, %s, %s)",
                (nome.strip(), email.strip(), senha_hash, nivel)
            )
            conexao.commit()
            return {"id": cursor.lastrowid, "nome": nome.strip(), "email": email.strip(), "nivel_acesso": nivel}
        except mysql.connector.IntegrityError:
            raise LookupError("Email já cadastrado.")
        finally:
            cursor.close()
            conexao.close()
    except Error:
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise
        for u in _memoria_mysql["usuarios"]:
            if u["email"].lower() == email.strip().lower():
                raise LookupError("Email já cadastrado.")
        novo_id = _memoria_mysql["proximo_id"]
        _memoria_mysql["proximo_id"] = novo_id + 1
        novo = {
            "id": novo_id, "nome": nome.strip(), "email": email.strip(),
            "senha_hash": senha_hash, "nivel_acesso": nivel,
            "criado_em": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        _memoria_mysql["usuarios"].append(novo)
        return {"id": novo_id, "nome": novo["nome"], "email": novo["email"], "nivel_acesso": nivel}


def listar_usuarios():
    """Retorna todos os usuários cadastrados sem expor o hash de senha."""
    try:
        conexao = _conectar_mysql()
        cursor = conexao.cursor(dictionary=True)
        cursor.execute("SELECT id, nome, email, nivel_acesso, criado_em FROM usuarios ORDER BY id ASC")
        usuarios = cursor.fetchall()
        cursor.close()
        conexao.close()
        for u in usuarios:
            if u.get("criado_em") is not None:
                u["criado_em"] = str(u["criado_em"])
        return usuarios
    except Error:
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise
        return [
            {
                "id": u["id"], "nome": u["nome"], "email": u["email"],
                "nivel_acesso": u["nivel_acesso"], "criado_em": u.get("criado_em", "")
            }
            for u in _memoria_mysql["usuarios"]
        ]


def buscar_usuario_por_email(email):
    """Busca um usuário pelo endereço de email usando query parametrizada."""
    try:
        conexao = _conectar_mysql()
        cursor = conexao.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, nome, email, nivel_acesso, criado_em FROM usuarios WHERE email = %s",
            (email,)
        )
        usuario = cursor.fetchone()
        cursor.close()
        conexao.close()
        if usuario and usuario.get("criado_em") is not None:
            usuario["criado_em"] = str(usuario["criado_em"])
        return usuario
    except Error:
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise
        for u in _memoria_mysql["usuarios"]:
            if u["email"] == email:
                return {
                    "id": u["id"], "nome": u["nome"], "email": u["email"],
                    "nivel_acesso": u["nivel_acesso"], "criado_em": u.get("criado_em", "")
                }
        return None


def buscar_usuario_por_id(usuario_id):
    """Busca um usuário pelo ID usando query parametrizada."""
    try:
        conexao = _conectar_mysql()
        cursor = conexao.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, nome, email, nivel_acesso, criado_em FROM usuarios WHERE id = %s",
            (int(usuario_id),)
        )
        usuario = cursor.fetchone()
        cursor.close()
        conexao.close()
        if usuario and usuario.get("criado_em") is not None:
            usuario["criado_em"] = str(usuario["criado_em"])
        return usuario
    except Error:
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise
        for u in _memoria_mysql["usuarios"]:
            if int(u["id"]) == int(usuario_id):
                return {
                    "id": u["id"], "nome": u["nome"], "email": u["email"],
                    "nivel_acesso": u["nivel_acesso"], "criado_em": u.get("criado_em", "")
                }
        return None


def _atualizar_usuario_memoria(usuario_id, nome, email, nivel_acesso):
    """Atualiza um usuário na estrutura de contingência em memória."""
    alvo = None
    for u in _memoria_mysql["usuarios"]:
        if int(u["id"]) == int(usuario_id):
            alvo = u
            break
    if not alvo:
        return None
    if email is not None:
        for u in _memoria_mysql["usuarios"]:
            if int(u["id"]) != int(usuario_id) and u["email"].lower() == email.lower():
                raise LookupError("Email já cadastrado.")
        alvo["email"] = email
    if nome is not None:
        alvo["nome"] = nome
    if nivel_acesso is not None:
        alvo["nivel_acesso"] = int(nivel_acesso)
    return {"id": alvo["id"], "nome": alvo["nome"], "email": alvo["email"], "nivel_acesso": alvo["nivel_acesso"]}


def atualizar_usuario(usuario_id, nome=None, email=None, nivel_acesso=None):
    """Atualiza dados e nível de acesso de um usuário de forma parametrizada."""
    if nivel_acesso is not None:
        nivel = int(nivel_acesso)
        if not 1 <= nivel <= 5:
            raise ValueError("Nível de acesso deve ser entre 1 e 5.")

    try:
        conexao = _conectar_mysql()
        cursor = conexao.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM usuarios WHERE id = %s", (int(usuario_id),))
            atual = cursor.fetchone()
            if not atual:
                return None
            n_nome = nome if nome is not None else atual["nome"]
            n_email = email if email is not None else atual["email"]
            n_nivel = int(nivel_acesso) if nivel_acesso is not None else atual["nivel_acesso"]
            cursor.execute(
                "UPDATE usuarios SET nome = %s, email = %s, nivel_acesso = %s WHERE id = %s",
                (n_nome, n_email, n_nivel, int(usuario_id))
            )
            conexao.commit()
            return {"id": int(usuario_id), "nome": n_nome, "email": n_email, "nivel_acesso": n_nivel}
        except mysql.connector.IntegrityError:
            raise LookupError("Email já cadastrado.")
        finally:
            cursor.close()
            conexao.close()
    except Error:
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise
        return _atualizar_usuario_memoria(usuario_id, nome, email, nivel_acesso)


def remover_usuario(usuario_id):
    """Remove um usuário pelo ID usando query parametrizada."""
    try:
        conexao = _conectar_mysql()
        cursor = conexao.cursor()
        cursor.execute("DELETE FROM usuarios WHERE id = %s", (int(usuario_id),))
        conexao.commit()
        apagados = cursor.rowcount
        cursor.close()
        conexao.close()
        return apagados > 0
    except Error:
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise
        antes = len(_memoria_mysql["usuarios"])
        _memoria_mysql["usuarios"] = [u for u in _memoria_mysql["usuarios"] if int(u["id"]) != int(usuario_id)]
        return len(_memoria_mysql["usuarios"]) < antes


def autenticar_operador(identificador, senha):
    """Autentica um operador por nome ou email verificando o hash SHA-256."""
    if type(identificador) is not str or type(senha) is not str:
        return None
    if not identificador.strip() or not senha.strip():
        return None

    senha_hash = gerar_hash_senha(senha)

    try:
        conexao = _conectar_mysql()
        cursor = conexao.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, nome, email, nivel_acesso, senha_hash FROM usuarios WHERE email = %s OR nome = %s",
            (identificador, identificador)
        )
        usuario = cursor.fetchone()
        cursor.close()
        conexao.close()
        if usuario and usuario["senha_hash"] == senha_hash:
            return {
                "id": usuario["id"], "nome": usuario["nome"],
                "email": usuario["email"], "nivel_acesso": usuario["nivel_acesso"]
            }
        return None
    except Error:
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise
        for u in _memoria_mysql["usuarios"]:
            if u["email"] == identificador or u["nome"] == identificador:
                if u["senha_hash"] == senha_hash:
                    return {
                        "id": u["id"], "nome": u["nome"],
                        "email": u["email"], "nivel_acesso": u["nivel_acesso"]
                    }
        return None
