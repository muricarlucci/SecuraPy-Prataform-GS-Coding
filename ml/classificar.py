import os
import sys

os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

RAIZ_PROJETO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if RAIZ_PROJETO not in sys.path:
    sys.path.insert(0, RAIZ_PROJETO)

from core.detector import BLACKLIST_PADRAO
from ml.treinar import (
    CAMINHO_MODELO,
    CAMINHO_HASH,
    calcular_hash_arquivo,
    extrair_features_ip,
    treinar_e_salvar_modelo
)


def verificar_integridade_modelo(caminho_modelo=CAMINHO_MODELO, caminho_hash=CAMINHO_HASH):
    """Compara o hash SHA-256 atual do modelo com o hash registrado."""
    if not os.path.exists(caminho_modelo) or not os.path.exists(caminho_hash):
        return False, "Arquivo de modelo ou hash não encontrado."

    with open(caminho_hash, "r", encoding="utf-8") as f:
        hash_esperado = f.read().strip()

    hash_atual = calcular_hash_arquivo(caminho_modelo)
    if hash_atual != hash_esperado:
        return False, "ALERTA: arquivo do modelo foi modificado! Hash SHA-256 não confere."

    return True, hash_atual


def carregar_modelo_seguro(caminho_modelo=CAMINHO_MODELO, caminho_hash=CAMINHO_HASH):
    """Carrega o arquivo modelo.pkl somente após validar sua integridade SHA-256."""
    if not os.path.exists(caminho_modelo) or not os.path.exists(caminho_hash):
        treinar_e_salvar_modelo()

    integro, mensagem = verificar_integridade_modelo(caminho_modelo, caminho_hash)
    if not integro:
        raise ValueError(mensagem)

    return joblib.load(caminho_modelo)


def classificar_ip(ip, eventos, blacklist=None, caminho_modelo=CAMINHO_MODELO, caminho_hash=CAMINHO_HASH):
    """Classifica um IP como normal ou ataque e calcula seu score de risco."""
    if blacklist is None:
        blacklist = BLACKLIST_PADRAO

    modelo = carregar_modelo_seguro(caminho_modelo, caminho_hash)
    vetor = extrair_features_ip(ip, eventos, blacklist)
    amostra = np.array([vetor], dtype=float)

    predicao = int(modelo.predict(amostra)[0])
    probabilidades = modelo.predict_proba(amostra)[0]
    prob_ataque = float(probabilidades[1]) if len(probabilidades) > 1 else float(predicao)
    score_risco = round(prob_ataque * 100, 2)

    nivel_risco = "CRITICO" if score_risco >= 80 else ("ALTO" if score_risco >= 60 else ("MEDIO" if score_risco >= 35 else "BAIXO"))
    rotulo = "ataque" if predicao == 1 else "normal"

    return {
        "ip": ip,
        "rotulo": rotulo,
        "classe": predicao,
        "score_risco": score_risco,
        "nivel_risco": nivel_risco,
        "features": {
            "qtd_fails_auth": vetor[0],
            "qtd_portas_bloqueadas": vetor[1],
            "esta_na_blacklist": vetor[2],
            "qtd_erros_web": vetor[3],
            "total_eventos": vetor[4]
        }
    }


def pontuar_ameacas(resumo_ameacas, eventos, blacklist=None):
    """Adiciona o score de risco do modelo ML às ameaças e ordena por prioridade."""
    if blacklist is None:
        blacklist = BLACKLIST_PADRAO

    ameacas_pontuadas = []
    for item in resumo_ameacas:
        copia = dict(item)
        ip = copia.get("ip", "")
        avaliacao_ml = classificar_ip(ip, eventos, blacklist)
        copia["ml_rotulo"] = avaliacao_ml["rotulo"]
        copia["score_risco_ml"] = avaliacao_ml["score_risco"]
        copia["nivel_risco_ml"] = avaliacao_ml["nivel_risco"]
        copia["features_ml"] = avaliacao_ml["features"]
        ameacas_pontuadas.append(copia)

    ameacas_pontuadas.sort(
        key=lambda x: (
            x.get("score_risco_ml", 0),
            x.get("pontuacao", 0),
            x.get("features_ml", {}).get("total_eventos", 0)
        ),
        reverse=True
    )
    return ameacas_pontuadas


def detectar_anomalias_ml(eventos, blacklist=None):
    """Aplica Isolation Forest para detectar IPs com comportamento anômalo."""
    if blacklist is None:
        blacklist = BLACKLIST_PADRAO

    ips = list({e.get("ip") for e in eventos if e.get("ip")})
    ips.sort()
    if not ips:
        return []

    vetores = [extrair_features_ip(ip, eventos, blacklist) for ip in ips]
    X = np.array(vetores, dtype=float)

    detector = IsolationForest(contamination=0.25, random_state=42)
    resultados = detector.fit_predict(X)

    anomalias = []
    for ip, vetor, res in zip(ips, vetores, resultados):
        anomalias.append({
            "ip": ip,
            "status_anomalia": "ANOMALIA" if int(res) == -1 else "Normal",
            "codigo": int(res),
            "features": {
                "qtd_fails_auth": vetor[0],
                "qtd_portas_bloqueadas": vetor[1],
                "esta_na_blacklist": vetor[2],
                "qtd_erros_web": vetor[3],
                "total_eventos": vetor[4]
            }
        })
    return anomalias


if __name__ == "__main__":
    from core.coletor import carregar_todos_os_logs
    pasta = os.path.join(RAIZ_PROJETO, "logs")
    evs = carregar_todos_os_logs(pasta)
    for ip_teste in ("185.220.101.1", "91.240.118.172", "192.168.1.10"):
        res = classificar_ip(ip_teste, evs)
        print(f"IP {ip_teste:<15} -> rótulo: {res['rotulo']:<8} | score: {res['score_risco']}% ({res['nivel_risco']})")
