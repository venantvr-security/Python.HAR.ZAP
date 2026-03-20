# Architecture Red Team - Pipeline HAR → ZAP

## Vue d'ensemble

```mermaid
flowchart TB
    subgraph INPUT["Entrée"]
        HAR[("HAR File<br/>Traffic capturé")]
    end

    subgraph PYTHON["Python Layer"]
        HA["har_analyzer.py<br/>Extraction endpoints"]
        RA["redteam_attacks.py<br/>Logique d'attaque"]
        LLM["llm/zap_integration.py<br/>Enrichissement IA"]

        HA --> RA
        LLM --> RA
    end

    subgraph ZAP_PROXY["ZAP Proxy Layer"]
        ZHC["zap_http_client.py<br/>Proxy HTTP"]
        SM["script_manager.py<br/>Chargement scripts"]

        subgraph SCRIPTS["scripts/active/"]
            MA["mass_assignment.js"]
            UR["unauth_replay.js"]
        end
    end

    subgraph ZAP_ENGINE["ZAP Engine"]
        AS["Active Scanner"]
        ALERTS[("Alertes ZAP")]
    end

    subgraph TARGET["Cible"]
        APP[("Application Web")]
    end

    HAR --> HA
    RA -->|"Requêtes via proxy"| ZHC
    ZHC -->|"Toutes requêtes loggées"| APP

    SM -->|"Charge JS"| SCRIPTS
    SCRIPTS --> AS
    AS -->|"Exécute sur URLs"| APP

    ZHC -->|"raise_alert()"| ALERTS
    AS -->|"raiseAlert()"| ALERTS

    style HAR fill:#e1f5fe
    style ALERTS fill:#ffcdd2
    style APP fill:#c8e6c9
    style SCRIPTS fill:#fff9c4
```

## Deux chemins d'attaque parallèles

### Chemin 1: Python Direct (redteam_attacks.py)

```mermaid
sequenceDiagram
    participant HAR as HAR File
    participant PY as Python<br/>redteam_attacks.py
    participant ZHC as ZAP HTTP Client
    participant ZAP as ZAP Proxy
    participant APP as Application

    HAR->>PY: Parse entries
    PY->>PY: identify_authenticated_requests()

    loop Pour chaque endpoint authentifié
        PY->>PY: Prépare attaque<br/>(retire headers auth)
        PY->>ZHC: request(method, url, headers)
        ZHC->>ZAP: Proxy request
        ZAP->>APP: HTTP Request
        APP->>ZAP: HTTP Response
        ZAP->>ZHC: Response
        ZHC->>PY: Response dict
        PY->>PY: Analyse réponse
        alt Vulnérabilité détectée
            PY->>ZHC: raise_alert()
            ZHC->>ZAP: API alertes
        end
    end
```

**Avantages:**
- Contrôle total sur la logique
- Payloads complexes (JSON nested, arrays)
- Concurrence avec ThreadPoolExecutor
- Analyse HAR offline
- Tests multi-étapes (race conditions)

### Chemin 2: Scripts JS dans ZAP (scripts/active/*.js)

```mermaid
sequenceDiagram
    participant SM as script_manager.py
    participant ZAP as ZAP Engine
    participant JS as mass_assignment.js
    participant APP as Application

    SM->>ZAP: zap.script.load(path, 'active')
    SM->>ZAP: zap.script.enable(name)

    Note over ZAP: Active Scan démarre

    loop Pour chaque URL dans scope
        ZAP->>JS: scan(as, msg, src)
        JS->>JS: Clone request
        JS->>JS: Injecte paramètres
        JS->>ZAP: as.sendAndReceive(testMsg)
        ZAP->>APP: HTTP Request modifié
        APP->>ZAP: Response
        ZAP->>JS: Response dans testMsg
        JS->>JS: Analyse réponse
        alt Vulnérabilité détectée
            JS->>ZAP: as.raiseAlert(risk, name, ...)
        end
    end
```

**Avantages:**
- Intégration native ZAP UI (History, Alerts)
- Exécuté sur URLs découvertes par Spider
- Contexte d'authentification ZAP (Replacer)
- Compatible avec Acceptance Engine
- Pas de dépendance Python runtime

## Structure des scripts JS

### Signature obligatoire

```javascript
// Active script - signature standard
function scan(as, msg, src) {
    // as  = ActiveScan helper (sendAndReceive, raiseAlert)
    // msg = HttpMessage original
    // src = Script source object
}

// Alternative avec paramètres (pour fuzzing)
function scan(as, msg, param, value) {
    // param = nom du paramètre à fuzzer
    // value = valeur originale
}
```

### API ZAP disponible dans JS

```mermaid
classDiagram
    class ActiveScan {
        +sendAndReceive(msg)
        +raiseAlert(risk, name, desc, uri, param, attack, solution, evidence, msg)
        +getHostForMessage(msg)
    }

    class HttpMessage {
        +cloneRequest()
        +getRequestHeader()
        +getRequestBody()
        +setRequestBody(body)
        +getResponseHeader()
        +getResponseBody()
    }

    class HttpRequestHeader {
        +getURI()
        +getMethod()
        +setURI(uri)
        +setHeader(name, value)
        +getHeader(name)
    }

    HttpMessage --> HttpRequestHeader
    ActiveScan --> HttpMessage
```

## mass_assignment.js - Détail

```mermaid
flowchart TD
    START([scan appelé]) --> CLONE[Clone request]
    CLONE --> METHOD{Méthode?}

    METHOD -->|POST/PUT/PATCH| BODY{Body type?}
    METHOD -->|GET| URL[Inject dans URL params]

    BODY -->|JSON| JSON[Parse + inject param]
    BODY -->|Form| FORM[Append &param=value]

    JSON --> SEND
    FORM --> SEND
    URL --> SEND

    SEND[sendAndReceive] --> ANALYZE{Analyse réponse}

    ANALYZE -->|Indicateur trouvé| BASELINE[Requête baseline]
    ANALYZE -->|Pas d'indicateur| NEXT[Prochain param]

    BASELINE --> COMPARE{Diff > 100 chars?}
    COMPARE -->|Oui| ALERT[raiseAlert]
    COMPARE -->|Non| NEXT

    ALERT --> NEXT
    NEXT --> END([Fin])

    style ALERT fill:#ffcdd2
```

### Paramètres testés

| Catégorie | Paramètres |
|-----------|------------|
| Admin | `admin`, `isAdmin`, `is_admin` |
| Rôles | `role`, `user_role`, `userRole` |
| Debug | `debug`, `isDebug`, `is_debug` |
| Privilèges | `priv`, `privilege`, `permissions` |
| Accès | `access_level`, `accessLevel` |

### Valeurs injectées

```
true, 1, admin, administrator
```

## unauth_replay.js - Détail

```mermaid
flowchart TD
    START([scan appelé]) --> CHECK{Headers auth?}

    CHECK -->|Non| SKIP([Skip - pas auth])
    CHECK -->|Oui| CLONE1[Clone request]

    CLONE1 --> REMOVE[Retire tous headers auth]
    REMOVE --> SEND1[sendAndReceive]

    SEND1 --> STATUS1{Status 2xx?}
    STATUS1 -->|Oui| ALERT1[raiseAlert<br/>Unauthenticated Access]
    STATUS1 -->|Non| TEST2[Test token invalide]

    TEST2 --> CLONE2[Clone request]
    CLONE2 --> INVALID[Set Authorization:<br/>Bearer invalid_token]
    INVALID --> SEND2[sendAndReceive]

    SEND2 --> STATUS2{Status 2xx?}
    STATUS2 -->|Oui| ALERT2[raiseAlert<br/>Invalid Token Accepted]
    STATUS2 -->|Non| END([Fin])

    ALERT1 --> END
    ALERT2 --> END

    style ALERT1 fill:#ffcdd2
    style ALERT2 fill:#ffcdd2
```

### Headers d'authentification détectés

```
Authorization, X-Auth-Token, X-API-Key, Cookie
```

## Intégration avec le flux Python

```mermaid
flowchart LR
    subgraph ORCHESTRATOR["zap_orchestrator.py"]
        direction TB
        LOAD["_load_attack_scripts()"]
        SCAN["run_active_scan()"]
    end

    subgraph SCRIPT_MGR["script_manager.py"]
        direction TB
        LIST["list_scripts()"]
        LOAD_S["load_script()"]
        ENABLE["enable_script()"]
    end

    subgraph FILES["scripts/active/"]
        MA["mass_assignment.js"]
        UR["unauth_replay.js"]
    end

    subgraph ZAP["ZAP API"]
        Z_LOAD["zap.script.load()"]
        Z_ENABLE["zap.script.enable()"]
        Z_SCAN["zap.ascan.scan()"]
    end

    LOAD --> LOAD_S
    LOAD_S --> FILES
    FILES --> Z_LOAD
    LOAD_S --> ENABLE
    ENABLE --> Z_ENABLE
    SCAN --> Z_SCAN

    style FILES fill:#fff9c4
```

## Quand utiliser quoi?

| Scénario | Python | JS/ZAP |
|----------|--------|--------|
| Analyse HAR offline | ✅ | ❌ |
| Spider + scan auto | ❌ | ✅ |
| Race conditions multi-requêtes | ✅ | ❌ |
| Intégration UI ZAP native | ❌ | ✅ |
| Payloads JSON complexes | ✅ | ⚠️ |
| Tests avec état (sessions) | ✅ | ⚠️ |
| CI/CD headless | ✅ | ✅ |
| Enrichissement LLM | ✅ | ❌ |

## Ajout d'un nouveau script

1. Créer `scripts/active/mon_script.js`
2. Implémenter `function scan(as, msg, src)`
3. Le script sera chargé automatiquement par `_load_attack_scripts()`

```javascript
// Template minimal
function scan(as, msg, src) {
    var testMsg = msg.cloneRequest();

    // Modifier la requête...

    as.sendAndReceive(testMsg);

    // Analyser la réponse...

    if (vulnerable) {
        as.raiseAlert(
            1,  // risk: 0=Info, 1=Low, 2=Medium, 3=High
            'Nom de la vuln',
            'Description',
            testMsg.getRequestHeader().getURI().toString(),
            'param_name',
            'payload_utilisé',
            'Solution recommandée',
            'Evidence (extrait réponse)',
            testMsg
        );
    }
}
```
