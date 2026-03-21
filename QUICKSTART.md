# HAR.ZAP - Guide de démarrage rapide

## Prérequis

- Python 3.8+
- Docker (pour ZAP)
- Clé API Gemini ou Anthropic

## Étape 1: Installation

```bash
git clone https://github.com/venantvr-security/Python.HAR.ZAP.git
cd Python.HAR.ZAP
make setup
```

## Étape 2: Configuration

```bash
# Copier le fichier d'exemple
cp .env.example .env

# Éditer .env avec votre clé API
nano .env  # ou code .env
```

Contenu minimal de `.env`:
```
HARZAP_GEMINI_API_KEY=AIzaSy...votre-clé...
```

## Étape 3: Démarrer (ZAP + Streamlit)

```bash
make start
```

Ouvre automatiquement:
- ZAP: http://localhost:8080
- Streamlit: http://localhost:8501

## Étape 4: Première analyse

1. **Upload HAR**: Glisser un fichier `.har` dans l'interface
   - Obtenir un HAR: DevTools (F12) → Network → Export HAR

2. **Analyser**: Cliquer sur "Analyze HAR"
   - Extraction des endpoints
   - Détection des patterns d'authentification
   - Identification des IDs (IDOR potentiel)

3. **Red Team**: Onglet "Red Team Attacks"
   - Sélectionner les attaques à exécuter
   - Lancer le scan

4. **Résultats**: Voir les alertes ZAP
   - Interface ZAP: http://localhost:8080
   - Dashboard Grafana (optionnel, voir ci-dessous)

## Optionnel: Dashboard Grafana

```bash
make observability-up
```

- **Grafana**: http://localhost:3000 (admin / harzap2024)
- Dashboard pré-configuré avec alertes ZAP

## Commandes utiles

```bash
make test          # Lancer les tests
make test-cov      # Tests avec couverture
make stop          # Arrêter ZAP + observability
make zap-logs      # Voir les logs ZAP
make help          # Liste toutes les commandes
```

## Structure des fichiers importants

- `app.py` - Application Streamlit
- `config.yaml` - Configuration principale
- `.env` - Secrets (non commité)
- `modules/` - Code Python (har_analyzer, redteam_attacks, llm/)
- `scripts/active/` - Scripts ZAP JS (redteam_scanner.js)
- `deployment/` - Docker observability

## Troubleshooting

### ZAP ne démarre pas
```bash
# Vérifier si le port est utilisé
lsof -i :8080
# Tuer le processus si nécessaire
kill -9 <PID>
```

### Erreur "No module named 'zapv2'"
```bash
pip install python-owasp-zap-v2.4
```

### Erreur API Gemini
- Vérifier la clé dans `.env`
- Vérifier que `HARZAP_GEMINI_API_KEY` est bien défini
- Tester: `echo $HARZAP_GEMINI_API_KEY`

### Pas de données dans Grafana
- Attendre quelques secondes (polling interval)
- Vérifier que des requêtes passent par ZAP
- Logs shipper: `docker logs harzap-shipper`

## Prochaines étapes

- Lire [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) pour comprendre le pipeline
- Lire [docs/HUNTING_GUIDE.md](docs/HUNTING_GUIDE.md) pour la recherche de vulnérabilités
- Lire [scripts/ARCHITECTURE.md](scripts/ARCHITECTURE.md) pour les scripts ZAP
