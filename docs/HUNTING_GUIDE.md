# Guide de Recherche de Vulnérabilités

Après une orchestration d'attaque, comment exploiter les logs pour trouver des failles.

## Workflow Global

```mermaid
flowchart TB
    subgraph ATTACK["1. Orchestration"]
        HAR[HAR File] --> ORCH[ZAP Orchestrator]
        ORCH --> SCRIPTS[Active Scripts]
        SCRIPTS --> ZAP[ZAP Proxy]
    end

    subgraph COLLECT["2. Collecte"]
        ZAP --> SHIPPER[zap_shipper.py]
        SHIPPER --> BACKEND{Backend?}
        BACKEND -->|Loki| LOKI[(Loki)]
        BACKEND -->|ES| ES[(Elasticsearch)]
    end

    subgraph ANALYZE["3. Analyse"]
        LOKI --> GRAFANA[Grafana]
        ES --> KIBANA[Kibana]
        GRAFANA --> HUNT[Hunting]
        KIBANA --> HUNT
    end

    subgraph EXPLOIT["4. Exploitation"]
        HUNT --> TRIAGE[Triage]
        TRIAGE --> VERIFY[Vérification manuelle]
        VERIFY --> REPORT[Rapport]
    end

    style HAR fill:#e3f2fd
    style HUNT fill:#fff9c4
    style REPORT fill:#c8e6c9
```

## Phase 1: Identifier les alertes critiques

```mermaid
flowchart LR
    subgraph PRIORITY["Ordre de priorité"]
        direction TB
        H[HIGH Risk] --> M[MEDIUM Risk]
        M --> L[LOW Risk]
        L --> I[INFO]
    end

    subgraph FILTERS["Filtres initiaux"]
        F1["risk:HIGH"] --> F2["confidence:HIGH"]
        F2 --> F3["NOT false_positive"]
    end

    PRIORITY --> FILTERS
```

### Requêtes Grafana (Loki)

```logql
# Alertes HIGH uniquement
{job="zap", type="alert", risk="HIGH"}

# Alertes HIGH avec confiance >= MEDIUM
{job="zap", type="alert", risk="HIGH"} | json | confidence =~ "HIGH|MEDIUM"

# Mass Assignment spécifiquement
{job="zap", type="alert"} |= "Mass Assignment"

# IDOR sur endpoints /api/
{job="zap", type="alert"} |= "IDOR" | json | url =~ ".*/api/.*"

# Authentification cassée
{job="zap", type="alert"} |= "Authentication" | json
```

### Requêtes Kibana (Elasticsearch)

```kql
# Alertes HIGH
type:alert AND risk:HIGH

# Mass Assignment avec evidence
type:alert AND name:"Mass Assignment" AND evidence:*admin*

# IDOR sur users
type:alert AND name:*IDOR* AND url:*user*

# Toutes les vulns auth
type:alert AND (name:*auth* OR name:*token* OR name:*session*)
```

## Phase 2: Corréler requêtes et alertes

```mermaid
sequenceDiagram
    participant A as Analyste
    participant G as Grafana/Kibana
    participant L as Logs

    A->>G: Filtre alertes HIGH
    G->>L: Query alerts
    L-->>G: 15 alertes

    A->>G: Sélectionne alerte IDOR
    G->>L: Détails alerte (URL, param)
    L-->>G: /api/users/123, id=124

    A->>G: Cherche requêtes associées
    G->>L: Query requests WHERE url LIKE /api/users/%
    L-->>G: Timeline requêtes

    A->>A: Compare baseline vs attack
    A->>G: Export pour vérification manuelle
```

### Trouver les requêtes associées à une alerte

**Grafana:**
```logql
# Toutes les requêtes vers l'endpoint vulnérable
{job="zap", type="request"} | json | url =~ ".*api/users.*"

# Requêtes avec status 200 (succès suspect)
{job="zap", type="request"} | json | url =~ ".*api/users.*" | status = "200"

# Timeline autour d'une alerte (±5min)
{job="zap"} | json | __timestamp__ >= now() - 5m
```

**Kibana:**
```kql
# Requêtes vers endpoint spécifique
type:request AND url:*api/users*

# Avec filtre temporel dans l'UI
type:request AND url:*api/users* AND @timestamp:[now-1h TO now]
```

## Phase 3: Patterns de détection

```mermaid
flowchart TD
    subgraph MASS["Mass Assignment Hunting"]
        MA1["Chercher: param injecté accepté"]
        MA2["Filtrer: response différente baseline"]
        MA3["Vérifier: privilege escalation réelle?"]
        MA1 --> MA2 --> MA3
    end

    subgraph AUTH["Broken Auth Hunting"]
        AU1["Chercher: requests sans auth header"]
        AU2["Filtrer: status 2xx"]
        AU3["Vérifier: données sensibles exposées?"]
        AU1 --> AU2 --> AU3
    end

    subgraph RACE["Race Condition Hunting"]
        RC1["Chercher: requêtes parallèles"]
        RC2["Filtrer: même endpoint, même seconde"]
        RC3["Vérifier: état incohérent?"]
        RC1 --> RC2 --> RC3
    end

    subgraph IDOR["IDOR Hunting"]
        ID1["Chercher: IDs modifiés"]
        ID2["Filtrer: réponse différente"]
        ID3["Vérifier: données autre user?"]
        ID1 --> ID2 --> ID3
    end
```

### Queries par type de vulnérabilité

#### Mass Assignment

```logql
# Grafana: Paramètres admin/role injectés
{job="zap", type="alert"} | json | param =~ "admin|role|privilege|permission"

# Avec evidence de changement
{job="zap", type="alert"} |= "Mass Assignment" | json | evidence =~ ".*granted.*|.*admin.*|.*elevated.*"
```

```kql
# Kibana
type:alert AND name:"Mass Assignment" AND param:(admin OR role OR privilege)
```

#### Broken Authentication

```logql
# Grafana: Endpoints accessibles sans auth
{job="zap", type="alert"} |= "Unauthenticated" | json

# Tokens invalides acceptés
{job="zap", type="alert"} |= "Invalid Token" | json
```

```kql
# Kibana
type:alert AND (name:*Unauthenticated* OR name:*Invalid Token*)
```

#### Race Condition

```logql
# Grafana: Alertes race avec succès multiples
{job="zap", type="alert"} |= "Race Condition" | json

# Requêtes groupées par timestamp (même seconde)
{job="zap", type="request"} | json | __timestamp__ > now() - 1m
  | pattern `<method> <url>`
  | count by (url, method)
```

```kql
# Kibana: Agrégation par endpoint et timestamp
type:request | date_histogram(@timestamp, 1s) | terms(url)
```

#### IDOR

```logql
# Grafana: IDOR avec différence de contenu
{job="zap", type="alert"} |= "IDOR" | json

# Requêtes avec IDs numériques modifiés
{job="zap", type="request"} | json | url =~ ".*/[0-9]+.*"
```

```kql
# Kibana
type:alert AND name:*IDOR* AND evidence:*

# Requêtes avec IDs
type:request AND url:/.*\/[0-9]+.*/
```

## Phase 4: Triage et vérification

```mermaid
flowchart TD
    ALERT[Alerte détectée] --> CHECK{Vérification}

    CHECK -->|Automatique| AUTO[Confidence HIGH]
    CHECK -->|Manuelle| MANUAL[Confidence LOW/MEDIUM]

    AUTO --> FP{False Positive?}
    MANUAL --> FP

    FP -->|Oui| DISMISS[Ignorer + Tag FP]
    FP -->|Non| CONFIRM[Confirmer]

    CONFIRM --> SEVERITY{Sévérité réelle?}

    SEVERITY -->|Critical| CRIT[Escalade immédiate]
    SEVERITY -->|High| HIGH[Rapport prioritaire]
    SEVERITY -->|Medium| MED[Backlog sécurité]
    SEVERITY -->|Low| LOW[Documentation]

    CRIT --> REPORT[Rapport final]
    HIGH --> REPORT
    MED --> REPORT
    LOW --> REPORT

    style CRIT fill:#ffcdd2
    style HIGH fill:#ffe0b2
    style DISMISS fill:#e0e0e0
```

### Checklist de vérification

| Vulnérabilité | Vérification manuelle |
|---------------|----------------------|
| Mass Assignment | Rejouer requête avec param → vérifier persistance en base |
| Broken Auth | Tester endpoint sans header → données sensibles? |
| Race Condition | Burp Turbo Intruder → double spending réel? |
| IDOR | Changer ID → accès données autre utilisateur? |

### Commandes de vérification

```bash
# Rejouer une requête ZAP
curl -X POST "http://localhost:8080/JSON/core/action/sendRequest/" \
  -d "request=POST /api/users HTTP/1.1\r\nHost: target.com\r\n..."

# Export alertes pour rapport
curl "http://localhost:8080/JSON/core/view/alerts/" | jq '.alerts[] | select(.risk == "3")'

# Générer rapport HTML
curl "http://localhost:8080/OTHER/core/other/htmlreport/" > report.html
```

## Phase 5: Dashboards de monitoring

```mermaid
flowchart LR
    subgraph REALTIME["Temps Réel"]
        RT1[Alertes/min]
        RT2[Requests/sec]
        RT3[Erreurs 5xx]
    end

    subgraph SUMMARY["Résumé"]
        S1[Total HIGH]
        S2[Total MEDIUM]
        S3[Par type]
    end

    subgraph TRENDS["Tendances"]
        T1[Alertes/jour]
        T2[Top endpoints]
        T3[Nouveaux patterns]
    end

    REALTIME --> SUMMARY --> TRENDS
```

### Panels Grafana recommandés

1. **Stat Panel**: Compteurs HIGH/MEDIUM/LOW
2. **Pie Chart**: Distribution par type d'attaque
3. **Logs Panel**: Stream temps réel filtré
4. **Time Series**: Alertes par heure
5. **Table**: Top 10 endpoints vulnérables
6. **Bar Gauge**: Confiance par alerte

## Exemples de recherches avancées

### Trouver des patterns d'attaque réussis

```logql
# Grafana: Séquence login → action privilégiée
{job="zap", type="request"}
  | json
  | url =~ ".*(login|auth).*"
  | line_format "{{.method}} {{.url}} {{.status}}"

# Suivi: même session, endpoint admin
{job="zap", type="request"}
  | json
  | url =~ ".*admin.*"
  | status = "200"
```

### Détecter des anomalies de réponse

```logql
# Réponses anormalement longues (data leak?)
{job="zap", type="request"}
  | json
  | response_length > 100000

# Réponses différentes pour même endpoint
{job="zap", type="request"}
  | json
  | url = "/api/users/me"
  | response_length != 1234  # baseline connu
```

### Timeline d'une attaque

```logql
# Toute l'activité sur un endpoint dans les 10 dernières minutes
{job="zap"}
  | json
  | url =~ ".*vulnerable-endpoint.*"
  | __timestamp__ >= now() - 10m
  | line_format "{{.__timestamp__}} [{{.type}}] {{.method}} {{.status}} {{.name}}"
```

## Workflow complet en une image

```mermaid
flowchart TB
    subgraph PREPARE["Préparation"]
        P1[Upload HAR] --> P2[Config attack strategies]
        P2 --> P3[Start ZAP + Shipper]
    end

    subgraph EXECUTE["Exécution"]
        E1[Run Orchestrator] --> E2[Scripts actifs]
        E2 --> E3[Logs vers backend]
    end

    subgraph HUNT["Hunting"]
        H1[Dashboard overview] --> H2[Filter HIGH risk]
        H2 --> H3[Drill down alerts]
        H3 --> H4[Correlate requests]
        H4 --> H5[Verify manually]
    end

    subgraph REPORT["Rapport"]
        R1[Export findings] --> R2[Severity matrix]
        R2 --> R3[Remediation plan]
        R3 --> R4[Executive summary]
    end

    PREPARE --> EXECUTE --> HUNT --> REPORT

    style P1 fill:#e3f2fd
    style H2 fill:#fff9c4
    style R4 fill:#c8e6c9
```

## Ressources

- [Grafana LogQL Documentation](https://grafana.com/docs/loki/latest/logql/)
- [Kibana KQL Documentation](https://www.elastic.co/guide/en/kibana/current/kuery-query.html)
- [ZAP API Documentation](https://www.zaproxy.org/docs/api/)
