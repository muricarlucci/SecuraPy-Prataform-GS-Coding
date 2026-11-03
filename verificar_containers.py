import docker
from docker.errors import DockerException


SERVICOS_ESPERADOS = ("securapy_api", "securapy_mongo", "securapy_mysql")


def verificar_status_containers():
    """Lista os contêineres Docker da plataforma e verifica se estão em execução."""
    try:
        client = docker.from_env()
        containers = client.containers.list(all=True)
    except DockerException as e:
        print(f"[ERRO] Não foi possível conectar ao daemon do Docker via SDK: {e}")
        return []

    print(f"{'NOME':<22} {'STATUS':<12} {'IMAGEM'}")
    print("-" * 60)

    resumo = []
    rodando = 0
    for c in containers:
        tags = c.image.tags
        imagem = tags[0] if tags else c.image.short_id
        alerta = "" if c.status == "running" else " <- ALERTA: PARADO"
        if c.status == "running":
            rodando += 1
        print(f"{c.name:<22} {c.status:<12} {imagem}{alerta}")
        resumo.append({"nome": c.name, "status": c.status, "imagem": imagem})

    print("-" * 60)
    print(f"Total: {len(containers)} | Rodando: {rodando} | Parados: {len(containers) - rodando}")

    nomes_ativos = {item["nome"] for item in resumo if item["status"] == "running"}
    faltantes = [srv for srv in SERVICOS_ESPERADOS if srv not in nomes_ativos]
    if not faltantes and resumo:
        print("Todos os 3 contêineres da plataforma SecuraPy estão 'running'.")
    elif faltantes:
        print(f"Serviços da plataforma ainda não ativos: {', '.join(faltantes)}")

    return resumo


if __name__ == "__main__":
    verificar_status_containers()
