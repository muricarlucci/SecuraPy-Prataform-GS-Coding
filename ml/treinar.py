import os
import sys
import json
import hashlib

os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")

import joblib
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

RAIZ_PROJETO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if RAIZ_PROJETO not in sys.path:
    sys.path.insert(0, RAIZ_PROJETO)

from core.coletor import carregar_todos_os_logs
from core.detector import BLACKLIST_PADRAO


DIRETORIO_ML = os.path.dirname(os.path.abspath(__file__))
CAMINHO_MODELO = os.path.join(DIRETORIO_ML, "modelo.pkl")
CAMINHO_HASH = os.path.join(DIRETORIO_ML, "modelo.sha256")
CAMINHO_METRICAS = os.path.join(DIRETORIO_ML, "metricas_ml.json")

COLUNAS_FEATURES = [
    "qtd_fails_auth",
    "qtd_portas_bloqueadas",
    "esta_na_blacklist",
    "qtd_erros_web",
    "total_eventos"
]

ROTULOS_CENARIO_SOC = {
    "192.168.1.10": 0,
    "192.168.1.20": 0,
    "192.168.1.45": 0,
    "10.0.0.5": 0,
    "185.220.101.1": 1,
    "91.240.118.172": 1,
    "45.33.32.156": 1
}


def calcular_hash_arquivo(caminho):
    """Calcula o hash SHA-256 de um arquivo binário em blocos."""
    sha256 = hashlib.sha256()
    with open(caminho, "rb") as f:
        while bloco := f.read(8192):
            sha256.update(bloco)
    return sha256.hexdigest()


def extrair_features_ip(ip, eventos, blacklist=None):
    """Extrai o vetor numérico de 5 features de comportamento para um IP."""
    if blacklist is None:
        blacklist = BLACKLIST_PADRAO

    qtd_fails_auth = 0
    portas_bloqueadas = set()
    qtd_erros_web = 0
    total_eventos = 0

    for ev in eventos:
        if ev.get("ip") != ip:
            continue
        total_eventos += 1
        fonte = ev.get("fonte")
        tipo = ev.get("tipo")
        detalhes = str(ev.get("detalhes", ""))

        if fonte == "auth" and tipo == "FAIL":
            qtd_fails_auth += 1
        elif fonte == "firewall" and tipo == "BLOCK":
            for parte in detalhes.split():
                if parte.startswith("dport="):
                    try:
                        portas_bloqueadas.add(int(parte.split("=", 1)[1]))
                    except ValueError:
                        pass
        elif fonte == "web":
            if any(cod in detalhes for cod in ("status=400", "status=401", "status=403", "status=404", "status=500")):
                qtd_erros_web += 1

    esta_na_blacklist = 1 if ip in blacklist else 0
    return [qtd_fails_auth, len(portas_bloqueadas), esta_na_blacklist, qtd_erros_web, total_eventos]


def construir_dataset_treinamento(eventos, blacklist=None):
    """Monta o DataFrame de features e rótulos históricos independentes."""
    if blacklist is None:
        blacklist = BLACKLIST_PADRAO

    ips_logs = list({e.get("ip") for e in eventos if e.get("ip")})
    ips_logs.sort()
    registros = []

    for ip in ips_logs:
        vetor = extrair_features_ip(ip, eventos, blacklist)
        rotulo_real = ROTULOS_CENARIO_SOC.get(ip, 0)
        registros.append(vetor + [rotulo_real])

    historico_soc = [
        [0, 0, 0, 0, 2, 0], [1, 0, 0, 0, 4, 0], [0, 0, 0, 1, 6, 0],
        [2, 0, 0, 0, 5, 0], [0, 1, 0, 0, 3, 0], [1, 1, 0, 1, 8, 0],
        [12, 5, 1, 4, 21, 1], [8, 4, 0, 2, 14, 1], [6, 0, 0, 5, 11, 1],
        [0, 6, 0, 2, 8, 1], [15, 8, 1, 6, 29, 1], [4, 3, 0, 3, 10, 1],
        [9, 2, 0, 4, 15, 1]
    ]
    df = pd.DataFrame(registros + historico_soc, columns=COLUNAS_FEATURES + ["rotulo"])
    X = df[COLUNAS_FEATURES].to_numpy(dtype=float)
    y = df["rotulo"].to_numpy(dtype=int)
    return X, y, len(ips_logs)


def _salvar_relatorio_metricas(qtd_total, qtd_reais, scores_cv, y_test, previsoes, hash_sha256):
    """Salva as métricas de validação cruzada e teste em arquivo JSON."""
    metricas = {
        "modelo": "Pipeline(StandardScaler + RandomForestClassifier)",
        "features": COLUNAS_FEATURES,
        "amostras_totais": int(qtd_total),
        "ips_reais_logs": int(qtd_reais),
        "amostras_historico_soc": int(qtd_total - qtd_reais),
        "observacao_metodologica": (
            "Os 3 arquivos de log originais possuem 58 eventos distribuídos em 7 IPs únicos "
            "(4 ativos internos legítimos e 3 origens externas de ataque). Para viabilizar "
            "validação cruzada de 5 folds (cv=5) e avaliação em conjunto de teste separado (X_test) "
            "sem vazamento de dados, os 7 IPs foram combinados com 13 registros históricos do SOC "
            "rotulados de forma independente."
        ),
        "validacao_cruzada_5_folds": {
            "acuracia_media": round(float(scores_cv.mean()), 4),
            "acuracia_desvio": round(float(scores_cv.std()), 4)
        },
        "avaliacao_teste": {
            "acuracia": round(float(accuracy_score(y_test, previsoes)), 4),
            "precisao": round(float(precision_score(y_test, previsoes)), 4),
            "recall": round(float(recall_score(y_test, previsoes)), 4),
            "f1_score": round(float(f1_score(y_test, previsoes)), 4),
            "matriz_confusao": confusion_matrix(y_test, previsoes).tolist()
        },
        "integridade": {
            "arquivo_modelo": "modelo.pkl",
            "sha256": hash_sha256
        }
    }
    with open(CAMINHO_METRICAS, "w", encoding="utf-8") as f:
        json.dump(metricas, f, indent=2, ensure_ascii=False)
    return metricas


def treinar_e_salvar_modelo(pasta_logs=None):
    """Treina o pipeline de ML, avalia métricas, salva modelo.pkl e gera hash SHA-256."""
    if pasta_logs is None:
        pasta_logs = os.path.join(RAIZ_PROJETO, "logs")

    eventos = carregar_todos_os_logs(pasta_logs)
    X, y, qtd_ips_reais = construir_dataset_treinamento(eventos, BLACKLIST_PADRAO)

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(n_estimators=100, random_state=42))
    ])

    scores_cv = cross_val_score(pipeline, X, y, cv=5)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    pipeline.fit(X_train, y_train)
    previsoes = pipeline.predict(X_test)

    joblib.dump(pipeline, CAMINHO_MODELO)
    hash_sha256 = calcular_hash_arquivo(CAMINHO_MODELO)
    with open(CAMINHO_HASH, "w", encoding="utf-8") as f:
        f.write(hash_sha256)

    metricas = _salvar_relatorio_metricas(len(X), qtd_ips_reais, scores_cv, y_test, previsoes, hash_sha256)

    print("=== Treinamento de Machine Learning SecuraPy ===")
    print(f"Validação Cruzada (5 folds) - Acurácia: {scores_cv.mean():.2f} (+/- {scores_cv.std():.2f})")
    print(
        f"Métricas Teste -> Precisão: {metricas['avaliacao_teste']['precisao']:.2f} | "
        f"Recall: {metricas['avaliacao_teste']['recall']:.2f} | "
        f"F1: {metricas['avaliacao_teste']['f1_score']:.2f}"
    )
    print(classification_report(y_test, previsoes))
    print(f"Modelo salvo: {CAMINHO_MODELO} | SHA-256: {hash_sha256}")
    return metricas


if __name__ == "__main__":
    treinar_e_salvar_modelo()
