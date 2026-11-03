import sys
import socket
import threading


HOST_PADRAO = "127.0.0.1"
PORTA_PADRAO = 9999


def receber_alertas(cliente):
    """Thread que recebe e exibe alertas enviados pelo servidor TCP."""
    while True:
        try:
            dados = cliente.recv(4096)
            if not dados:
                print("\nServidor desconectou.")
                break
            texto = dados.decode("utf-8", errors="ignore")
            print(f"\r{texto}", end="")
            print(">> ", end="", flush=True)
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            print("\nConexão encerrada com o servidor.")
            break
    try:
        cliente.close()
    except OSError:
        pass


def conectar_servidor(host=HOST_PADRAO, porta=PORTA_PADRAO):
    """Conecta ao servidor de alertas e gerencia o envio de comandos."""
    try:
        porta_int = int(porta)
    except (ValueError, TypeError):
        print(f"Erro: Porta inválida ({porta}). Informe um número inteiro.")
        return

    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        cliente.connect((host, porta_int))
    except ConnectionRefusedError:
        print(f"Erro: Não foi possível conectar ao servidor em {host}:{porta_int}")
        return
    except socket.gaierror:
        print(f"Erro: Endereço ou host inválido ({host}).")
        return
    except OSError as e:
        print(f"Erro de conexão com {host}:{porta_int}: {e}")
        return

    thread = threading.Thread(target=receber_alertas, args=(cliente,), daemon=True)
    thread.start()

    while True:
        try:
            comando = input(">> ").strip()
            if not comando:
                continue
            cliente.send(comando.encode("utf-8"))
            if comando.lower() == "/sair":
                break
        except (BrokenPipeError, ConnectionResetError, OSError):
            print("Conexão perdida.")
            break
        except (KeyboardInterrupt, EOFError):
            try:
                cliente.send("/sair".encode("utf-8"))
            except OSError:
                pass
            print("\nDesconectando...")
            break

    cliente.close()


if __name__ == "__main__":
    host_arg = sys.argv[1] if len(sys.argv) > 1 else HOST_PADRAO
    porta_arg = sys.argv[2] if len(sys.argv) > 2 else PORTA_PADRAO
    conectar_servidor(host_arg, porta_arg)
