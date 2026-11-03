import json
import socket
import threading
from datetime import datetime


HOST_PADRAO = "0.0.0.0"
PORTA_PADRAO = 9999

clientes = {}
historico_alertas = []
lock = threading.Lock()
_servidor_background_ativo = False


def formatar_alerta(alerta_dict):
    """Converte dicionário de alerta em string formatada para exibição."""
    if type(alerta_dict) is not dict:
        return str(alerta_dict)

    ts_bruto = str(alerta_dict.get("timestamp", datetime.now().strftime("%H:%M:%S")))
    partes_ts = ts_bruto.split()
    horario = partes_ts[-1] if partes_ts else ts_bruto
    severidade = str(alerta_dict.get("severidade", "INFO")).upper()
    regra = alerta_dict.get("regra") or alerta_dict.get("tipo") or "Alerta"
    ip = alerta_dict.get("ip") or alerta_dict.get("ip_origem") or "N/A"
    descricao = alerta_dict.get("descricao", "Sem descrição")
    return f"[{horario}] [{severidade}] {regra} — {ip} — {descricao}"


def remover_cliente(conexao):
    """Remove um cliente desconectado e fecha seu socket com segurança."""
    with lock:
        endereco = clientes.pop(conexao, None)
    try:
        conexao.close()
    except OSError:
        pass
    if endereco:
        agora = datetime.now().strftime("%H:%M:%S")
        print(f"[{agora}] Cliente desconectado: {endereco[0]}:{endereco[1]}")


def broadcast_alerta(alerta):
    """Envia um alerta formatado para todos os clientes TCP conectados."""
    texto_alerta = formatar_alerta(alerta)
    with lock:
        historico_alertas.append(texto_alerta)
        conexoes_ativas = list(clientes.keys())

    falhas = []
    for conexao in conexoes_ativas:
        try:
            conexao.send((texto_alerta + "\n").encode("utf-8"))
        except (ConnectionResetError, BrokenPipeError, OSError):
            falhas.append(conexao)

    for conexao in falhas:
        remover_cliente(conexao)

    agora = datetime.now().strftime("%H:%M:%S")
    qtd_enviados = len(conexoes_ativas) - len(falhas)
    print(f"[{agora}] Alerta enviado para {qtd_enviados} clientes: {texto_alerta}")
    return texto_alerta


def _processar_comando_cliente(conexao, mensagem):
    """Processa um comando individual (/status, /historico ou /sair) do cliente TCP."""
    cmd = mensagem.strip()
    if not cmd:
        return True

    if cmd.lower() == "/sair":
        conexao.send("Desconectando do servidor SecuraPy...\n".encode("utf-8"))
        return False

    if cmd.lower() == "/status":
        with lock:
            qtd_c = len(clientes)
            qtd_a = len(historico_alertas)
        conexao.send(f"Clientes conectados: {qtd_c} | Alertas na sessão: {qtd_a}\n".encode("utf-8"))
        return True

    if cmd.lower() == "/historico":
        with lock:
            ultimos = historico_alertas[-10:]
        if not ultimos:
            conexao.send("Nenhum alerta registrado nesta sessão.\n".encode("utf-8"))
        else:
            conexao.send(("=== Últimos Alertas ===\n" + "\n".join(ultimos) + "\n").encode("utf-8"))
        return True

    conexao.send("Comando desconhecido. Use /status, /historico ou /sair\n".encode("utf-8"))
    return True


def tratar_cliente(conexao, endereco):
    """Gerencia a comunicação com um cliente conectado em sua própria thread."""
    agora = datetime.now().strftime("%H:%M:%S")
    with lock:
        clientes[conexao] = endereco
    print(f"[{agora}] Cliente conectado: {endereco[0]}:{endereco[1]}")

    boas_vindas = (
        f"Conectado ao SecuraPy SIEM ({endereco[0]}:{endereco[1]})\n"
        "Comandos: /status, /historico, /sair\n"
    )
    try:
        conexao.send(boas_vindas.encode("utf-8"))
        continuar = True
        while continuar:
            dados = conexao.recv(4096)
            if not dados:
                break
            linhas = dados.decode("utf-8", errors="ignore").splitlines()
            for linha in linhas:
                if not _processar_comando_cliente(conexao, linha):
                    continuar = False
                    break
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
        pass
    finally:
        remover_cliente(conexao)


def enviar_alerta_remoto(alerta, host="127.0.0.1", porta=PORTA_PADRAO):
    """Transmite o alerta em tempo real para todos os clientes TCP conectados."""
    broadcast_alerta(alerta)
    return True


def iniciar_servidor_background(host=HOST_PADRAO, porta=PORTA_PADRAO):
    """Inicia o servidor TCP em uma thread daemon caso a porta esteja livre."""
    global _servidor_background_ativo
    if _servidor_background_ativo:
        return True

    try:
        servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind((host, porta))
        servidor.listen(10)
    except OSError:
        return False

    _servidor_background_ativo = True

    def _loop():
        """Aceita conexões TCP continuamente em segundo plano."""
        while True:
            try:
                conexao, endereco = servidor.accept()
                t = threading.Thread(target=tratar_cliente, args=(conexao, endereco), daemon=True)
                t.start()
            except OSError:
                break

    thread = threading.Thread(target=_loop, daemon=True)
    thread.start()
    return True


def iniciar_servidor(host=HOST_PADRAO, porta=PORTA_PADRAO):
    """Inicia o servidor TCP principal e aguarda conexões continuamente."""
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((host, porta))
    servidor.listen(10)

    print("=== Servidor de Alertas SecuraPy ===")
    print(f"Rodando em {host}:{porta}")
    print("Aguardando conexões...\n")

    try:
        while True:
            conexao, endereco = servidor.accept()
            t = threading.Thread(target=tratar_cliente, args=(conexao, endereco), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\nEncerrando servidor de alertas...")
        with lock:
            conexoes = list(clientes.keys())
        for c in conexoes:
            try:
                c.send("Servidor de alertas encerrado.\n".encode("utf-8"))
                c.close()
            except OSError:
                pass
    finally:
        servidor.close()


if __name__ == "__main__":
    iniciar_servidor()
