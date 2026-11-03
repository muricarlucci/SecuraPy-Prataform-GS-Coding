import os
import time
import socket
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from bson import ObjectId


MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB = os.environ.get("MONGO_DB", "seguranca")

_memoria_mongo = {"eventos": [], "alertas": [], "aviso_exibido": False, "offline_ate": 0.0}


def _porta_mongo_ativa():
    """Verifica via socket se a porta do MongoDB está acessível."""
    agora = time.time()
    if agora < _memoria_mongo["offline_ate"]:
        return False
    partes = MONGO_URI.replace("mongodb://", "").split("/")[0].split(":")
    host = partes[0] if partes[0] else "127.0.0.1"
    if host == "localhost":
        host = "127.0.0.1"
    porta = int(partes[1]) if len(partes) > 1 and partes[1].isdigit() else 27017
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    try:
        sock.connect((host, porta))
        ativo = True
    except OSError:
        ativo = False
        _memoria_mongo["offline_ate"] = agora + 5.0
    finally:
        sock.close()
    return ativo


def _obter_colecoes():
    """Conecta ao MongoDB e retorna as coleções de eventos e alertas."""
    if not _porta_mongo_ativa():
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise PyMongoError("Serviço MongoDB indisponível")
        if not _memoria_mongo["aviso_exibido"]:
            print("[AVISO] MongoDB indisponível; operando em contingência de sessão.")
            _memoria_mongo["aviso_exibido"] = True
        raise PyMongoError("Contingência ativa")

    client = MongoClient(MONGO_URI)
    client.admin.command("ping")
    db = client[MONGO_DB]
    return db["eventos"], db["alertas"]


def serializar_documento(doc):
    """Converte o campo _id ObjectId em string para serialização JSON."""
    if doc is None:
        return None
    copia = dict(doc)
    if "_id" in copia:
        copia["_id"] = str(copia["_id"])
    return copia


def criar_indices():
    """Cria índices em ip, timestamp e severidade nas coleções do MongoDB."""
    try:
        eventos_col, alertas_col = _obter_colecoes()
        eventos_col.create_index("ip")
        eventos_col.create_index("timestamp")
        eventos_col.create_index([("fonte", 1), ("timestamp", -1)])
        alertas_col.create_index("ip")
        alertas_col.create_index("severidade")
        alertas_col.create_index("timestamp")
        return True
    except PyMongoError:
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise
        return False


def salvar_eventos(lista_eventos, limpar_antes=True):
    """Salva uma lista de eventos normalizados na coleção eventos."""
    documentos = []
    for ev in lista_eventos:
        copia = dict(ev)
        if "_id" not in copia:
            copia["_id"] = ObjectId()
        documentos.append(copia)

    try:
        eventos_col, _ = _obter_colecoes()
        if limpar_antes:
            eventos_col.delete_many({})
        if documentos:
            res = eventos_col.insert_many(documentos)
            return len(res.inserted_ids)
        return 0
    except PyMongoError:
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise
        if limpar_antes:
            _memoria_mongo["eventos"] = []
        for doc in documentos:
            _memoria_mongo["eventos"].append(serializar_documento(doc))
        return len(documentos)


def salvar_alerta(alerta):
    """Insere um único alerta na coleção alertas e retorna seu ID."""
    copia = dict(alerta)
    oid = ObjectId()
    copia["_id"] = oid

    try:
        _, alertas_col = _obter_colecoes()
        res = alertas_col.insert_one(copia)
        return str(res.inserted_id)
    except PyMongoError:
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise
        _memoria_mongo["alertas"].append(serializar_documento(copia))
        return str(oid)


def salvar_alertas(lista_alertas, limpar_antes=True):
    """Salva uma lista de alertas preservando alertas manuais cadastrados via API ou Web."""
    documentos = []
    for al in lista_alertas:
        copia = dict(al)
        if "_id" not in copia:
            copia["_id"] = ObjectId()
        documentos.append(copia)

    try:
        _, alertas_col = _obter_colecoes()
        if limpar_antes:
            alertas_col.delete_many({"fonte": {"$nin": ["api", "web_manual"]}})
        if documentos:
            res = alertas_col.insert_many(documentos)
            return len(res.inserted_ids)
        return 0
    except PyMongoError:
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise
        if limpar_antes:
            _memoria_mongo["alertas"] = [
                a for a in _memoria_mongo["alertas"]
                if a.get("fonte") in ("api", "web_manual")
            ]
        for doc in documentos:
            _memoria_mongo["alertas"].append(serializar_documento(doc))
        return len(documentos)


def _montar_filtro_eventos(fonte=None, tipo=None, ip=None, desde=None):
    """Monta dicionário de filtro dinâmico ignorando parâmetros None."""
    filtro = {}
    if fonte:
        filtro["fonte"] = fonte.lower()
    if tipo:
        filtro["tipo"] = tipo.upper()
    if ip:
        filtro["ip"] = ip
    if desde:
        filtro["timestamp"] = {"$gte": desde}
    return filtro


def _filtrar_eventos_memoria(fonte=None, tipo=None, ip=None, desde=None):
    """Aplica filtros sobre os eventos em contingência de sessão."""
    filtrados = []
    for ev in _memoria_mongo["eventos"]:
        if fonte and ev.get("fonte", "").lower() != fonte.lower():
            continue
        if tipo and ev.get("tipo", "").upper() != tipo.upper():
            continue
        if ip and ev.get("ip") != ip:
            continue
        if desde and str(ev.get("timestamp", "")) < str(desde):
            continue
        filtrados.append(serializar_documento(ev))
    return filtrados


def consultar_eventos(fonte=None, tipo=None, ip=None, desde=None, pagina=1, tamanho=20):
    """Consulta eventos com filtros dinâmicos, ordenação e paginação."""
    filtro = _montar_filtro_eventos(fonte, tipo, ip, desde)
    pular = (pagina - 1) * tamanho if pagina > 1 else 0

    try:
        eventos_col, _ = _obter_colecoes()
        cursor = eventos_col.find(filtro).sort("timestamp", -1).skip(pular).limit(tamanho)
        return [serializar_documento(d) for d in cursor]
    except PyMongoError:
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise
        filtrados = _filtrar_eventos_memoria(fonte, tipo, ip, desde)
        filtrados.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return filtrados[pular:pular + tamanho]


def contar_eventos(fonte=None, tipo=None, ip=None, desde=None):
    """Retorna a contagem total de eventos que atendem aos filtros."""
    filtro = _montar_filtro_eventos(fonte, tipo, ip, desde)
    try:
        eventos_col, _ = _obter_colecoes()
        return eventos_col.count_documents(filtro)
    except PyMongoError:
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise
        return len(_filtrar_eventos_memoria(fonte, tipo, ip, desde))


def _filtrar_alertas_memoria(severidade=None, ip=None, tipo=None):
    """Aplica filtros sobre os alertas em contingência de sessão."""
    filtrados = []
    for al in _memoria_mongo["alertas"]:
        if severidade and al.get("severidade", "").upper() != severidade.upper():
            continue
        if ip and al.get("ip") != ip:
            continue
        if tipo and al.get("tipo", "").upper() != tipo.upper():
            continue
        filtrados.append(serializar_documento(al))
    return filtrados


def consultar_alertas(severidade=None, ip=None, tipo=None, pagina=1, tamanho=20):
    """Consulta alertas com filtros opcionais, ordenados por severidade."""
    filtro = {}
    if severidade:
        filtro["severidade"] = severidade.upper()
    if ip:
        filtro["ip"] = ip
    if tipo:
        filtro["tipo"] = tipo.upper()
    pular = (pagina - 1) * tamanho if pagina > 1 else 0

    try:
        _, alertas_col = _obter_colecoes()
        cursor = alertas_col.find(filtro).sort([("pontuacao", -1), ("timestamp", -1)]).skip(pular).limit(tamanho)
        return [serializar_documento(d) for d in cursor]
    except PyMongoError:
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise
        filtrados = _filtrar_alertas_memoria(severidade, ip, tipo)
        filtrados.sort(key=lambda x: (x.get("pontuacao", 0), x.get("timestamp", "")), reverse=True)
        return filtrados[pular:pular + tamanho]


def contar_alertas(severidade=None, ip=None, tipo=None):
    """Retorna a quantidade de alertas que correspondem aos filtros."""
    filtro = {}
    if severidade:
        filtro["severidade"] = severidade.upper()
    if ip:
        filtro["ip"] = ip
    if tipo:
        filtro["tipo"] = tipo.upper()

    try:
        _, alertas_col = _obter_colecoes()
        return alertas_col.count_documents(filtro)
    except PyMongoError:
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise
        return len(_filtrar_alertas_memoria(severidade, ip, tipo))


def obter_alerta_por_id(alerta_id):
    """Busca um alerta específico pelo seu ObjectId."""
    oid = ObjectId(alerta_id)
    try:
        _, alertas_col = _obter_colecoes()
        doc = alertas_col.find_one({"_id": oid})
        return serializar_documento(doc) if doc else None
    except PyMongoError:
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise
        for al in _memoria_mongo["alertas"]:
            if str(al.get("_id")) == str(oid):
                return serializar_documento(al)
        return None


def top_ips_eventos(limite=10):
    """Agrega e retorna os IPs com maior volume de eventos."""
    pipeline = [
        {"$group": {"_id": "$ip", "total": {"$sum": 1}}},
        {"$sort": {"total": -1}},
        {"$limit": limite}
    ]
    try:
        eventos_col, _ = _obter_colecoes()
        return [{"ip": l["_id"], "total": l["total"]} for l in eventos_col.aggregate(pipeline)]
    except PyMongoError:
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise
        contagem = {}
        for ev in _memoria_mongo["eventos"]:
            ip = ev.get("ip")
            if ip:
                contagem[ip] = contagem.get(ip, 0) + 1
        lista = [{"ip": ip, "total": tot} for ip, tot in contagem.items()]
        lista.sort(key=lambda x: x["total"], reverse=True)
        return lista[:limite]


def contar_eventos_por_fonte():
    """Agrega a quantidade de eventos agrupados por fonte."""
    pipeline = [{"$group": {"_id": "$fonte", "total": {"$sum": 1}}}, {"$sort": {"total": -1}}]
    resumo = {"auth": 0, "firewall": 0, "web": 0}
    try:
        eventos_col, _ = _obter_colecoes()
        for linha in eventos_col.aggregate(pipeline):
            resumo[linha["_id"]] = linha["total"]
        return resumo
    except PyMongoError:
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise
        for ev in _memoria_mongo["eventos"]:
            f = ev.get("fonte", "outro")
            resumo[f] = resumo.get(f, 0) + 1
        return resumo


def contar_alertas_por_severidade():
    """Agrega a quantidade de alertas agrupados por severidade."""
    pipeline = [{"$group": {"_id": "$severidade", "total": {"$sum": 1}}}, {"$sort": {"total": -1}}]
    resumo = {"CRITICA": 0, "ALTA": 0, "MEDIA": 0, "BAIXA": 0, "INFO": 0}
    try:
        _, alertas_col = _obter_colecoes()
        for linha in alertas_col.aggregate(pipeline):
            resumo[str(linha["_id"]).upper()] = linha["total"]
        return resumo
    except PyMongoError:
        if os.environ.get("MODO_BANCO_ESTRITO") == "1":
            raise
        for al in _memoria_mongo["alertas"]:
            s = str(al.get("severidade", "INFO")).upper()
            resumo[s] = resumo.get(s, 0) + 1
        return resumo
