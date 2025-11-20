# Tests Documentation

Suite de tests complète pour la plateforme DAST Python.HAR.ZAP.

## Structure

```
tests/
├── unit/                          # Tests unitaires
│   ├── test_masking.py           # Tests du module de masquage
│   └── test_redteam_attacks.py   # Tests des attaques Red Team
├── features/                      # Tests BDD (Gherkin)
│   ├── redteam_payloads.feature  # Scénarios payloads configurables
│   ├── race_condition.feature    # Scénarios race conditions
│   ├── secrets_masking.feature   # Scénarios masquage secrets
│   └── steps/                    # Implémentations step definitions
│       ├── redteam_steps.py
│       ├── race_condition_steps.py
│       └── masking_steps.py
└── README.md                      # Ce fichier
```

## Installation

```bash
pip install -r requirements.txt
```

## Exécution des tests

### Tests unitaires (pytest)

```bash
# Tous les tests unitaires
pytest

# Avec couverture de code
pytest --cov=modules --cov-report=html

# Tests spécifiques
pytest tests/unit/test_masking.py
pytest tests/unit/test_redteam_attacks.py

# Tests async uniquement
pytest -m asyncio

# Mode verbose
pytest -v
```

### Tests BDD (behave)

```bash
# Tous les scénarios BDD
behave tests/features/

# Scénario spécifique
behave tests/features/redteam_payloads.feature
behave tests/features/race_condition.feature
behave tests/features/secrets_masking.feature

# Avec tags
behave --tags=@security
behave --tags=@masking

# Mode verbose
behave -v
```

## Couverture des tests

### Tests unitaires (test_masking.py)

**Couverture : modules/utils/masking.py**

- ✅ Masquage de tokens JWT
- ✅ Masquage de tokens Bearer
- ✅ Masquage de clés API (AWS, Stripe, génériques)
- ✅ Masquage de sessions/cookies
- ✅ Masquage de passwords dans URLs/données
- ✅ Masquage de cartes de crédit
- ✅ Masquage d'emails (PII)
- ✅ Masquage de SSN
- ✅ Masquage d'en-têtes HTTP sensibles
- ✅ Masquage récursif dans structures imbriquées
- ✅ Masquage d'entrées HAR complètes
- ✅ Gestion des cas limites (None, vide, types mixtes)

### Tests unitaires (test_redteam_attacks.py)

**Couverture : modules/redteam_attacks.py**

#### MassAssignmentFuzzer

- ✅ Chargement payloads depuis config
- ✅ Fallback aux payloads par défaut
- ✅ Identification endpoints mutation (POST/PUT/PATCH)
- ✅ Injection de paramètres dangereux
- ✅ Détection de succès (200/201/204)

#### HiddenParameterDiscovery

- ✅ Chargement paramètres cachés depuis config
- ✅ Parsing format "param=value"
- ✅ Test de variations de paramètres
- ✅ Détection via différence de contenu

#### RaceConditionTester

- ✅ Configuration burst_count depuis config
- ✅ Identification d'endpoints critiques (keywords)
- ✅ Exécution burst async avec aiohttp
- ✅ Analyse de réponses (success_count, variance)
- ✅ Détection de vulnérabilités (multiple succès)
- ✅ Gestion des erreurs réseau

#### UnauthenticatedReplayAttack

- ✅ Identification de requêtes authentifiées
- ✅ Suppression des headers d'auth
- ✅ Détection d'accès non autorisé
- ✅ Calcul de confidence

#### RedTeamOrchestrator

- ✅ Orchestration de toutes les attaques
- ✅ Passage de config aux modules
- ✅ Agrégation des résultats
- ✅ Filtrage findings critiques (confidence > 0.5)
- ✅ Génération de rapports

### Tests BDD (Gherkin)

#### redteam_payloads.feature (6 scénarios)

- ✅ Utilisation payloads par défaut
- ✅ Configuration payloads personnalisés Mass Assignment
- ✅ Fallback si config invalide
- ✅ Configuration paramètres cachés personnalisés
- ✅ Combinaison des deux types de payloads

#### race_condition.feature (9 scénarios)

- ✅ Configuration par défaut (50 requêtes)
- ✅ Configuration personnalisée du burst
- ✅ Détection de vulnérabilités
- ✅ Détection de protections
- ✅ Analyse de variance des réponses
- ✅ Test de multiples endpoints
- ✅ Gestion des timeouts
- ✅ Détection via variation de longueurs

#### secrets_masking.feature (16 scénarios)

- ✅ Masquage JWT dans rapports JSON
- ✅ Masquage en-têtes Authorization/Cookie
- ✅ Masquage clés API dans logs console
- ✅ Masquage tokens dans URLs
- ✅ Masquage passwords dans corps de requêtes
- ✅ Masquage cookies de session
- ✅ Masquage emails (PII)
- ✅ Masquage cartes de crédit
- ✅ Préservation données non-sensibles
- ✅ Masquage récursif structures imbriquées
- ✅ Masquage dans rapports HTML ZAP
- ✅ Masquage tokens Stripe
- ✅ Placeholder personnalisable
- ✅ Masquage dans logs Red Team
- ✅ Masquage dans rapports critiques

## Métriques de qualité

### Objectifs de couverture

- **Code coverage** : >85%
- **Ligne coverage** : >90%
- **Branch coverage** : >80%

### Commandes pour métriques

```bash
# Génération rapport HTML
pytest --cov=modules --cov-report=html
open htmlcov/index.html

# Génération rapport XML (CI/CD)
pytest --cov=modules --cov-report=xml

# Fail si couverture < 85%
pytest --cov=modules --cov-fail-under=85
```

## Tests d'intégration (à venir)

TODO: Ajouter tests d'intégration end-to-end

- Orchestrateur complet avec HAR réel
- Intégration avec Docker/ZAP
- Tests de performance (burst async)

## CI/CD

Configuration recommandée pour pipeline :

```yaml
test:
  script:
    - pip install -r requirements.txt
    - pytest --cov=modules --cov-report=xml --cov-fail-under=85
    - behave tests/features/
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage.xml
```

## Conventions

- Tests unitaires : `test_*.py` dans `tests/unit/`
- Tests BDD : `*.feature` dans `tests/features/`
- Fixtures pytest : Définies dans les classes de test
- Mocking : Utiliser `unittest.mock` ou `pytest-mock`
- Async tests : Marquer avec `@pytest.mark.asyncio`

## Debugging

```bash
# Mode debug pytest
pytest -vv --tb=long

# Stop au premier échec
pytest -x

# Lancer test spécifique
pytest tests/unit/test_masking.py::TestMaskString::test_mask_jwt_token

# Behave avec debug
behave tests/features/ --no-capture
```

## Performance

Les tests doivent s'exécuter rapidement :

- Tests unitaires : < 30 secondes
- Tests BDD : < 60 secondes
- Total : < 2 minutes

Utiliser mocking pour éviter :

- Appels réseau réels
- Opérations I/O lentes
- Dépendances externes (Docker, ZAP)
