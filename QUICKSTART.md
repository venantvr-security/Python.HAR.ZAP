# HAR.ZAP - Guide de démarrage rapide

## Prérequis

- Python 3.8+
- Docker (pour ZAP)
- Clé API Gemini ou Anthropic

## Étape 1: Installation

```bash
# Cloner le repo
git clone https://github.com/venantvr-security/Python.HAR.ZAP.git
cd Python.HAR.ZAP

# Créer l'environnement virtuel
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Installer les dépendances
pip install -r requirements.txt
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

## Étape 3: Lancer ZAP (Docker)

```bash
# Terminal 1: Démarrer ZAP
docker run -u zap -p 8080:8080 -p 8090:8090 \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true \
  -config api.disablekey=true
```

Vérifier que ZAP est prêt:
```bash
curl http://localhost:8080/JSON/core/view/version/
# Doit retourner: {"version":"2.x.x"}
```

## Étape 4: Lancer l'application

```bash
# Terminal 2: Démarrer l'app Streamlit
streamlit run app.py
```

Ouvrir dans le navigateur: http://localhost:8501

## Étape 5: Première analyse

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

Pour visualiser les logs et alertes:

```bash
cd deployment
docker compose -f docker-compose.observability.yml --profile loki up -d
```

- **Grafana**: http://localhost:3000 (admin / harzap2024)
- Dashboard pré-configuré avec alertes ZAP

## Commandes utiles

```bash
# Lancer les tests
pytest tests/ -v

# Voir la couverture
pytest tests/ --cov=modules --cov-report=html
open htmlcov/index.html

# Arrêter ZAP
docker stop $(docker ps -q --filter ancestor=ghcr.io/zaproxy/zaproxy:stable)

# Arrêter Grafana/Loki
cd deployment && docker compose -f docker-compose.observability.yml down
```

## Structure des fichiers importants

- `app.py` - Application Streamlit
- `config.yaml` - Configuration principale
- `.env` - Secrets (non commité)
- `modules/`
- `har_analyzer.py` - Analyse HAR
- `redteam_attacks.py` - Attaques red team
- `llm/` - Intégration LLM
- `scripts/active/` - Scripts ZAP JS
- `redteam_scanner.js`
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
