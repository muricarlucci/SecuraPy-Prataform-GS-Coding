# SecuraPy Platform: SIEM e Plataforma de Segurança

## 1. Descrição e Objetivo

O **SecuraPy Platform** é um sistema de gerenciamento de informações e eventos de segurança (SIEM) desenvolvido em Python para a Global Solution da disciplina **Coding for Security** (Prof. Fabio Bara).

O objetivo do projeto é evoluir o núcleo de coleta e correlação de logs do primeiro semestre para uma plataforma integrada de operações de segurança (SOC), adicionando persistência em bancos de dados SQL e NoSQL, classificação de risco com Machine Learning, API RESTful autenticada, dashboard web protegido contra vulnerabilidades do OWASP Top 10, triagem assistida por LLM e empacotamento em contêineres Docker.

---

## 2. Arquitetura do Projeto

```text
securaPy_platform/
├── core/
│   ├── coletor.py             # Leitura, parsing e normalização de auth.log, firewall.log e web_access.log
│   ├── regras.py              # Motor de regras configurável via JSON (R001 a R005)
│   ├── detector.py            # Detecção de brute force, port scan, blacklist e consolidação
│   ├── enriquecimento.py      # Validação estrita RFC 1918, consulta ipinfo.io, cache e retry (HTTP 429)
│   └── relatorios.py          # Menu CLI, filtros, busca por IP e exportação de relatórios JSON
├── db/
│   ├── mongo_repo.py          # Persistência de eventos/alertas, filtros, índices e agregações no MongoDB
│   ├── mysql_repo.py          # CRUD parametrizado de operadores, níveis de acesso e autenticação no MySQL
│   ├── migrar_logs.py         # Script de ingestão inicial dos logs e alertas nos bancos
│   └── schema.sql             # Script DDL de inicialização da tabela de usuários no MySQL
├── ml/
│   ├── treinar.py             # DataFrame pandas, Pipeline StandardScaler + RandomForest, CV 5-fold e SHA-256
│   ├── classificar.py         # Verificação de integridade SHA-256, pontuação de risco e IsolationForest
│   ├── modelo.pkl             # Modelo de Machine Learning persistido com joblib
│   ├── modelo.sha256          # Hash SHA-256 para validação de integridade do modelo
│   └── metricas_ml.json       # Relatório de métricas obtido na avaliação de teste (holdout)
├── api/
│   ├── app.py                 # Aplicação Flask (rotas REST, dashboard web, RBAC, headers OWASP e logs)
│   └── auth.py                # Emissão e validação de Bearer Token / sessão (os.urandom + SHA-256, 1h)
├── ia/
│   └── assistente.py          # Triagem e explicação de eventos com OpenAI (gpt-4o-mini) e fallback por regras
├── web/
│   └── templates/
│       ├── login.html         # Página de autenticação de operadores do SOC
│       ├── dashboard.html     # Painel principal com métricas, top 10 IPs e alertas escapados contra XSS
│       └── ip_detalhes.html   # Relatório detalhado por IP (eventos, alertas, geolocalização, ML e IA)
├── alertas/
│   ├── servidor_alertas.py    # Servidor TCP multithread para broadcast de alertas em tempo real
│   └── cliente_alertas.py     # Console cliente TCP (/status, /historico, /sair)
├── logs/
│   ├── auth.log               # Log de autenticação (23 eventos)
│   ├── firewall.log           # Log de firewall (17 eventos)
│   └── web_access.log         # Log de servidor web (18 eventos)
├── config/
│   └── regras.json            # Regras configuráveis de detecção
├── saida/
│   └── relatorio_exemplo.json # Relatório JSON consolidado gerado pelo sistema
├── verificar_containers.py    # Verificação dos contêineres em execução via Docker SDK for Python
├── testar_plataforma.py       # Suíte automatizada de testes funcionais, de segurança e auditoria AST
├── main.py                    # Ponto de entrada unificado (CLI interativo, modo batch e modo API)
├── Dockerfile                 # Imagem Docker da aplicação Python
├── docker-compose.yml         # Orquestração dos serviços api, mongodb e mysql com healthchecks e .env
├── requirements.txt           # Dependências do projeto com versões fixadas para deploy reproduzível
├── .env                       # Variáveis de ambiente utilizadas pelo Docker Compose
└── .env.example               # Modelo de variáveis de ambiente
```

---

## 3. O Que Foi Reconstruído da GS1 e O Que Foi Acrescentado na GS2

### Base reconstruída e integrada do 1º Semestre (Módulo A)
- **Coletor (`core/coletor.py`):** leitura e normalização dos 58 eventos distribuídos em `auth.log` (23), `firewall.log` (17) e `web_access.log` (18), com tratamento de arquivos inexistentes, arquivos vazios e linhas malformadas.
- **Motor de Regras (`core/regras.py`):** avaliação das 5 regras do arquivo `config/regras.json` (`R001` a `R005`) e classificação de severidade (`INFO`, `BAIXA`, `MEDIA`, `ALTA`, `CRITICA`).
- **Detector de Ameaças (`core/detector.py`):** detecção de brute force por contagem de falhas de login, detecção de port scan com conjuntos (`set`) de portas bloqueadas, cruzamento com blacklist via interseção de conjuntos (`&`) e consolidação de ameaças.
- **Enriquecimento (`core/enriquecimento.py`):** verificação estrita de IPs privados RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), consulta à API `ipinfo.io`, cache em dicionário e tratamento de falhas de rede e rate limit (`HTTP 429`).
- **Alertas em Tempo Real (`alertas/`):** servidor e cliente TCP com `socket` e `threading`, broadcast simultâneo para múltiplos analistas e comandos `/status`, `/historico` e `/sair`.

### Funcionalidades desenvolvidas no 2º Semestre (Módulos B a G)
- **Módulo B — Persistência Híbrida (`db/`):** armazenamento de eventos e alertas no MongoDB com índices, preservação de alertas manuais durante reprocessamentos e pipelines de agregação (`$group`, `$sort`, `$limit`); gerenciamento de operadores e níveis de acesso (`1` a `5`) no MySQL com senhas em hash SHA-256 e queries parametrizadas (`%s`) contra SQL Injection.
- **Módulo C — Machine Learning (`ml/`):** extração de 5 features por IP estruturadas em `pandas.DataFrame`, treinamento de `Pipeline` (`StandardScaler` + `RandomForestClassifier`), avaliação com validação cruzada de 5 folds e métricas no conjunto de teste (`precisão`, `recall`, `F1`), detecção de anomalias com `IsolationForest`, persistência com `joblib` e verificação de integridade com hash SHA-256 antes do carregamento.
- **Módulo D — API REST (`api/`):** endpoints para consulta filtrada e paginada de eventos e alertas, criação de alertas, gestão de usuários restrita a administradores (`nível 5`, retornando `403 Forbidden` para níveis inferiores) e análise de logs protegidos por Bearer Token (emitido via `POST /api/login` com entropia `os.urandom(32)` + `SHA-256` e expiração de 1 hora), além do dossiê unificado por IP (`GET /api/ip/<ip>`).
- **Módulo E — Dashboard Web e Segurança OWASP (`web/` e `api/app.py`):** interface web em Jinja2 com autoescape contra XSS, sessão individual por operador via cookie `HttpOnly`, headers de segurança (`X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`), login endurecido com mensagens genéricas anti-enumeração, bloqueio temporário por força bruta (30s após 5 falhas) e log de auditoria de acessos (`logs/access_plataforma.log`).
- **Módulo F — Docker (`Dockerfile`, `docker-compose.yml`, `verificar_containers.py`):** conteinerização da plataforma junto aos serviços MongoDB 7 e MySQL 8 com `healthcheck` (`service_healthy`), variáveis de ambiente carregadas via `.env`, inicialização integrada da API Flask (`5000`) e do Servidor TCP de Alertas (`9999`), e script de monitoramento via SDK `docker`.
- **Módulo G — Assistente LLM (`ia/assistente.py`):** classificação (`NORMAL`, `SUSPEITO`, `CRITICO` — sem acento, seguindo o padrão da Aula 13) e explicação em linguagem natural via API da OpenAI (`gpt-4o-mini`), com sanitização de segredos, delimitação `<log>...</log>`, detecção de Prompt Injection (em português, inglês e quebra de tags), validação estrita de saída e fallback automático por regras quando `OPENAI_API_KEY` não está configurada.

---

## 4. Notas Técnicas de Conformidade e Decisões de Implementação

1. **Contagem real de falhas em `logs/auth.log` (11 vs 10):** O arquivo oficial `auth.log` fornecido no enunciado contém 23 linhas no total, sendo **11** eventos `FAIL` para o IP `185.220.101.1`, 5 `FAIL` para `91.240.118.172`, 3 `FAIL` para `45.33.32.156` e 4 eventos `OK` (`11 + 5 + 3 + 4 = 23`). Embora o texto do enunciado e o Exercício 2.2 da Apostila 2 mencionem "10 falhas", o coletor e o detector reportam fielmente as 11 ocorrências reais presentes no arquivo de log.
2. **Faixas de severidade e `threshold` em `detectar_brute_force` (`core/detector.py`):** No enunciado da GS1, a assinatura padrão é `detectar_brute_force(eventos, threshold=5)` (e a tabela A2 da GS2 cobra `185.220.101.1` com `ALTA` e `91.240.118.172` com 5 falhas = `MEDIA`), enquanto o Cenário 1 da GS1 menciona também `45.33.32.156` com 3 falhas (`BAIXA`). Para atender ambos sem contradição: com `threshold=5` (padrão da assinatura) são retornados `185.220.101.1` (`ALTA`) e `91.240.118.172` (`MEDIA`); ao chamar `detectar_brute_force(eventos, threshold=3)`, `45.33.32.156` também é retornado com severidade `BAIXA`. Ambos os modos são validados em `testar_plataforma.py`.
3. **Metodologia do conjunto de treinamento de Machine Learning (`ml/treinar.py`):** Os 3 arquivos de log contêm **7 IPs únicos** (`185.220.101.1`, `91.240.118.172`, `45.33.32.156`, `192.168.1.10`, `192.168.1.20`, `192.168.1.35` e `10.0.0.5`). Como `cross_val_score(..., cv=5)` e `train_test_split(..., test_size=0.3)` exigem amostras suficientes por classe em cada fold, o dataset combina os 7 IPs reais dos logs com 13 perfis históricos representativos de tráfego SOC (totalizando 20 amostras), avaliando as métricas exclusivamente sobre a partição de teste (`X_test`, `y_test`) após `pipeline.fit(X_train, y_train)`.
4. **Justificativa de recursos exigidos pela GS2 além dos exemplos literais da apostila:**
   - **Emissão de tokens e cookies de sessão:** A Apostila 2 (Aula 7) mostra o consumo de Bearer Token; para que o login exigido pela GS2 funcione ponta a ponta na API e no Dashboard sem expor tokens estáticos, `api/auth.py` gera tokens dinâmicos usando `os.urandom(32)` + `hashlib.sha256` (módulos padrão já utilizados na disciplina) e armazena o token no navegador via cookie `HttpOnly`.
   - **Header CSP com `'unsafe-inline'` em `style-src`:** Mantém `default-src 'self'` (bloqueando scripts inline e externos, conforme Aula 8) e adiciona `style-src 'self' 'unsafe-inline'` exclusivamente para permitir a renderização das tags `<style>` dos templates HTML do Dashboard.
   - **Servidor HTTP em produção:** Para execução local e didática utiliza-se `app.run(host="0.0.0.0", port=5000, debug=False)` conforme a Aula 7; em ambiente produtivo recomenda-se executar via servidor WSGI (`gunicorn -w 4 -b 0.0.0.0:5000 "api.app:app"`), conforme recomendado na Aula 8 (pacote `gunicorn` incluído no `requirements.txt`).

---

## 5. Tecnologias e Dependências

- **Linguagem:** Python 3.11+
- **Bancos de Dados:** MongoDB 7 (`pymongo==4.10.1`) e MySQL 8 (`mysql-connector-python==9.1.0`)
- **Machine Learning:** `scikit-learn==1.6.1`, `numpy==2.2.3`, `pandas==2.2.3`, `joblib==1.4.2`
- **Web e API:** `Flask==3.1.0`, `MarkupSafe==3.0.2`, `requests==2.32.3`, `gunicorn==23.0.0`
- **Infraestrutura e IA:** `docker==7.1.0` (Docker SDK for Python), `openai==1.65.4`

Instalação local das dependências:

```bash
pip install -r requirements.txt
```

---

## 6. Instruções de Execução com Docker

1. Certifique-se de que o Docker Desktop esteja em execução.
2. Na pasta `securaPy_platform`, inicie os três serviços (`mongodb`, `mysql` e `api`):

```bash
docker-compose up -d --build
```

3. Verifique o estado dos contêineres utilizando o script com o SDK do Docker:

```bash
python verificar_containers.py
```

4. Para encerrar os serviços mantendo os volumes persistidos:

```bash
docker-compose down
```

---

## 7. Instruções de Execução Local (Sem Docker ou para Desenvolvimento)

Caso deseje executar diretamente pelo Python no sistema local:

1. **Treinar o modelo de ML, ingerir os logs e gerar o relatório JSON de exemplo:**

```bash
python main.py --batch
```

2. **Iniciar a API REST, o Dashboard Web (porta 5000) e o Servidor TCP (porta 9999):**

```bash
python api/app.py
```

3. **Iniciar o menu interativo de linha de comando (CLI):**

```bash
python main.py
```

4. **Conectar Clientes TCP ao Servidor de Alertas (porta 9999):**

```bash
# Terminal Analista 1
python alertas/cliente_alertas.py

# Terminal Analista 2
python alertas/cliente_alertas.py
```

5. **Executar a suíte automatizada de testes (Módulos A a G):**

```bash
python testar_plataforma.py
```

---

## 8. Como Utilizar a API REST e o Dashboard Web

### Acesso ao Dashboard Web
- Painel principal: `http://localhost:5000/`
- Página de login de operador: `http://localhost:5000/login`
  - Credenciais padrão inicializadas no banco (`db/schema.sql`):
    - Usuário: `admin` (ou `admin@securapy.com`) | Senha: `Cyber@2024` (Nível 5 — Administrador)
    - Usuário: `analista` (ou `analista@securapy.com`) | Senha: `S3gur4nca!` (Nível 3 — Analista)
    - Usuário: `operador` (ou `operador@securapy.com`) | Senha: `Mudar@123` (Nível 1 — Operador)

### Principais Endpoints da API REST

- **1. Autenticar operador e obter Bearer Token (válido por 1 hora):**
  ```bash
  curl -X POST http://localhost:5000/api/login \
    -H "Content-Type: application/json" \
    -d "{\"usuario\": \"admin\", \"senha\": \"Cyber@2024\"}"
  ```
- **2. Status da plataforma:**
  ```bash
  curl http://localhost:5000/api/status
  ```
- **3. Executar análise completa dos logs (autenticado):**
  ```bash
  curl -X POST http://localhost:5000/api/analisar \
    -H "Authorization: Bearer <TOKEN_OBTIDO_NO_LOGIN>" \
    -H "Content-Type: application/json" \
    -d "{\"pasta_logs\": \"logs\"}"
  ```
- **4. Listar eventos com filtros e paginação:**
  ```bash
  curl "http://localhost:5000/api/eventos?fonte=auth&tipo=FAIL&pagina=1&tamanho=5"
  ```
- **5. Listar alertas por severidade e paginação:**
  ```bash
  curl "http://localhost:5000/api/alertas?severidade=CRITICA&pagina=1&tamanho=5"
  ```
- **6. Cadastrar novo alerta (autenticado — preservado mesmo após reprocessamentos):**
  ```bash
  curl -X POST http://localhost:5000/api/alertas \
    -H "Authorization: Bearer <TOKEN_OBTIDO_NO_LOGIN>" \
    -H "Content-Type: application/json" \
    -d "{\"tipo\": \"BRUTE_FORCE\", \"severidade\": \"CRITICA\", \"ip\": \"185.220.101.1\", \"descricao\": \"11 falhas seguidas\"}"
  ```
- **7. Busca consolidada por IP (Eventos + Alertas + Geolocalização + Score ML + Explicação IA):**
  ```bash
  curl http://localhost:5000/api/ip/185.220.101.1
  ```
- **8. Explicação de evento pelo Assistente IA:**
  ```bash
  curl -X POST http://localhost:5000/api/ia/explicar \
    -H "Content-Type: application/json" \
    -d "{\"log\": \"GET url=/../../etc/passwd ip=91.240.118.172 status=400\"}"
  ```

---

## 9. Integrantes e Divisão de Tarefas

| Papel na Equipe | Módulos sob Responsabilidade |
|-----------------|------------------------------|
| **Murilo Carlucci (Núcleo e Bancos)** | Módulo A (Coletor, Regras, Detector, Enriquecimento, Alertas TCP) e Módulo B (Persistência MongoDB e MySQL) |
| **Miguell Junquira (Machine Learning)** | Módulo C (Extração de Features, Pipeline StandardScaler + RandomForest, Métricas, IsolationForest e SHA-256) |
| **Guilherme Mendonça (API REST e Docker)** | Módulo D (Endpoints REST Flask, Paginação, Autenticação Bearer/RBAC) e Módulo F (Dockerfile, Docker Compose e SDK) |
| **Murilo e Miguell (Segurança Web e IA)** | Módulo E (Dashboard Web, Proteção XSS, Headers OWASP, Access Log), Módulo G (Assistente LLM e Anti-Injection) e Integração |
