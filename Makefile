.PHONY: help venv install install-dev test test-unit test-bdd test-cov test-fast lint format clean run run-dev orchestrate docker-up docker-down docker-clean tor-up tor-down tor-status tor-newcircuit status setup env-setup check-env start stop app zap-up zap-down zap-logs observability-up observability-down start-full

# Variables
VENV := .venv
PYTHON := $(VENV)/bin/python3
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest
BEHAVE := $(VENV)/bin/behave
UVICORN := $(VENV)/bin/uvicorn
STREAMLIT := $(VENV)/bin/streamlit
DOCKER := docker
COMPOSE := docker compose
PORT := 8000
ZAP_PORT := 8080
STREAMLIT_PORT := 8501

# Détection si venv existe
VENV_EXISTS := $(shell [ -d $(VENV) ] && echo 1 || echo 0)

# Couleurs pour output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

help: ## Affiche cette aide
	@echo "$(BLUE)Python.HAR.ZAP - DAST Security Platform$(NC)"
	@echo ""
	@echo "$(GREEN)Commandes disponibles:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, $$2}'

venv: ## Crée le virtualenv .venv
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(BLUE)Création du virtualenv $(VENV)...$(NC)"; \
		python3 -m venv $(VENV); \
		echo "$(GREEN)✓ Virtualenv créé$(NC)"; \
	else \
		echo "$(YELLOW)⚠ Virtualenv $(VENV) existe déjà$(NC)"; \
	fi

install: venv ## Installe les dépendances de production
	@echo "$(BLUE)Installation des dépendances...$(NC)"
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé. Lancez 'make venv' d'abord$(NC)"; \
		exit 1; \
	fi
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.in
	@echo "$(GREEN)✓ Installation terminée$(NC)"

install-dev: install ## Installe toutes les dépendances (dev + test)
	@echo "$(BLUE)Installation des dépendances de développement...$(NC)"
	$(PIP) install flake8 black pytest-benchmark
	@echo "$(GREEN)✓ Installation dev terminée$(NC)"

test: ## Lance tous les tests (unitaires uniquement)
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé. Lancez 'make install' d'abord$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Exécution de tous les tests...$(NC)"
	@$(MAKE) test-unit
	@echo "$(GREEN)✓ Tous les tests sont passés$(NC)"

test-unit: ## Lance les tests unitaires avec pytest
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé. Lancez 'make install' d'abord$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Exécution des tests unitaires...$(NC)"
	$(PYTEST) tests/unit/ -v
	@echo "$(GREEN)✓ Tests unitaires OK$(NC)"

test-bdd: ## Lance les tests BDD avec behave
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé. Lancez 'make install' d'abord$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Exécution des tests BDD...$(NC)"
	$(BEHAVE) tests/features/ -v
	@echo "$(GREEN)✓ Tests BDD OK$(NC)"

test-cov: ## Lance les tests avec couverture de code
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé. Lancez 'make install' d'abord$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Exécution des tests avec couverture...$(NC)"
	$(PYTEST) tests/unit/ --cov=modules --cov-report=term-missing --cov-report=html --cov-report=xml -v
	@echo "$(GREEN)✓ Rapport de couverture généré dans htmlcov/$(NC)"
	@echo "$(YELLOW)Ouvrir htmlcov/index.html pour voir le rapport détaillé$(NC)"

test-fast: ## Lance les tests rapidement (sans couverture)
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé. Lancez 'make install' d'abord$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Exécution rapide des tests...$(NC)"
	$(PYTEST) tests/unit/ -x -q
	@echo "$(GREEN)✓ Tests rapides OK$(NC)"

test-masking: ## Lance uniquement les tests de masquage
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé. Lancez 'make install' d'abord$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Tests du module de masquage...$(NC)"
	$(PYTEST) tests/unit/test_masking.py -v

test-redteam: ## Lance uniquement les tests Red Team
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé. Lancez 'make install' d'abord$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Tests des attaques Red Team...$(NC)"
	$(PYTEST) tests/unit/test_redteam_attacks.py -v

test-fuzzer: ## Lance uniquement les tests du fuzzer
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé. Lancez 'make install' d'abord$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Tests du token extractor...$(NC)"
	$(PYTEST) tests/unit/test_token_extractor.py -v

test-watch: ## Lance les tests en mode watch (relance automatique)
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé. Lancez 'make install' d'abord$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Mode watch activé (Ctrl+C pour quitter)...$(NC)"
	$(PYTEST) tests/unit/ -f

lint: ## Vérifie le code avec flake8
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé. Lancez 'make install-dev' d'abord$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Vérification du code...$(NC)"
	@if [ ! -f "$(VENV)/bin/flake8" ]; then \
		echo "$(YELLOW)flake8 non installé, installation...$(NC)"; \
		$(PIP) install flake8; \
	fi
	$(VENV)/bin/flake8 modules/ --max-line-length=120 --exclude=__pycache__,*.pyc
	@echo "$(GREEN)✓ Code conforme$(NC)"

format: ## Formate le code avec black
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé. Lancez 'make install-dev' d'abord$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Formatage du code...$(NC)"
	@if [ ! -f "$(VENV)/bin/black" ]; then \
		echo "$(YELLOW)black non installé, installation...$(NC)"; \
		$(PIP) install black; \
	fi
	$(VENV)/bin/black modules/ tests/ --line-length=120
	@echo "$(GREEN)✓ Code formaté$(NC)"

clean: ## Nettoie les fichiers temporaires
	@echo "$(BLUE)Nettoyage des fichiers temporaires...$(NC)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.coverage" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/
	rm -rf coverage.xml
	rm -rf .coverage
	rm -rf dist/
	rm -rf build/
	rm -rf wordlists/
	@echo "$(GREEN)✓ Nettoyage terminé$(NC)"

clean-venv: clean ## Supprime également le virtualenv
	@echo "$(BLUE)Suppression du virtualenv...$(NC)"
	rm -rf $(VENV)
	@echo "$(GREEN)✓ Virtualenv supprimé$(NC)"

run: ## Lance l'interface web FastAPI
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé. Lancez 'make install' d'abord$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Démarrage de l'interface web sur http://localhost:$(PORT)...$(NC)"
	$(UVICORN) web.api.main:app --host 0.0.0.0 --port $(PORT)

run-dev: ## Lance l'interface web en mode développement (hot reload)
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé. Lancez 'make install' d'abord$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Démarrage en mode dev sur http://localhost:$(PORT)...$(NC)"
	$(UVICORN) web.api.main:app --host 0.0.0.0 --port $(PORT) --reload

orchestrate: ## Lance l'orchestrateur CLI (nécessite HAR_FILE)
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé. Lancez 'make install' d'abord$(NC)"; \
		exit 1; \
	fi
	@if [ -z "$(HAR_FILE)" ]; then \
		echo "$(RED)Erreur: HAR_FILE non spécifié$(NC)"; \
		echo "$(YELLOW)Usage: make orchestrate HAR_FILE=path/to/file.har$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Lancement de l'orchestrateur...$(NC)"
	$(PYTHON) orchestrator.py $(HAR_FILE)

docker-up: ## Démarre ZAP dans Docker
	@echo "$(BLUE)Démarrage de ZAP Docker...$(NC)"
	$(DOCKER) run -d -p 8080:8080 --name zap ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
	@echo "$(GREEN)✓ ZAP démarré sur http://localhost:8080$(NC)"

docker-down: ## Arrête ZAP Docker
	@echo "$(BLUE)Arrêt de ZAP Docker...$(NC)"
	$(DOCKER) stop zap 2>/dev/null || true
	$(DOCKER) rm zap 2>/dev/null || true
	@echo "$(GREEN)✓ ZAP arrêté$(NC)"

docker-clean: docker-down ## Nettoie les conteneurs et images Docker
	@echo "$(BLUE)Nettoyage Docker...$(NC)"
	$(DOCKER) system prune -f
	@echo "$(GREEN)✓ Docker nettoyé$(NC)"

docker-logs: ## Affiche les logs de ZAP Docker
	@$(DOCKER) logs -f zap

docker-status: ## Vérifie le statut de ZAP Docker
	@$(DOCKER) ps -a | grep zap || echo "$(YELLOW)ZAP n'est pas en cours d'exécution$(NC)"

tor-up: ## Démarre TOR dans Docker
	@echo "$(BLUE)Démarrage de TOR Docker...$(NC)"
	$(DOCKER) run -d -p 9050:9050 -p 9051:9051 --name tor dperson/torproxy
	@echo "$(GREEN)✓ TOR démarré sur socks5://localhost:9050$(NC)"

tor-down: ## Arrête TOR Docker
	@echo "$(BLUE)Arrêt de TOR Docker...$(NC)"
	$(DOCKER) stop tor 2>/dev/null || true
	$(DOCKER) rm tor 2>/dev/null || true
	@echo "$(GREEN)✓ TOR arrêté$(NC)"

tor-status: ## Vérifie la connexion TOR
	@curl -s --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip 2>/dev/null && echo "$(GREEN)✓ TOR connecté$(NC)" || echo "$(RED)✗ TOR non connecté$(NC)"

tor-newcircuit: ## Demande un nouveau circuit TOR
	@echo -e 'AUTHENTICATE ""\nSIGNAL NEWNYM\nQUIT' | nc 127.0.0.1 9051
	@echo "$(GREEN)✓ Nouveau circuit demandé$(NC)"

scan: ## Lance un scan complet (web UI + tests)
	@echo "$(BLUE)Démarrage du scan complet...$(NC)"
	@$(MAKE) docker-up
	@sleep 5
	@echo "$(GREEN)ZAP prêt, lancez l'interface web avec 'make run'$(NC)"

coverage-report: test-cov ## Génère et ouvre le rapport de couverture HTML
	@echo "$(BLUE)Ouverture du rapport de couverture...$(NC)"
	@if command -v xdg-open >/dev/null 2>&1; then \
		xdg-open htmlcov/index.html; \
	elif command -v open >/dev/null 2>&1; then \
		open htmlcov/index.html; \
	else \
		echo "$(YELLOW)Ouvrir manuellement: htmlcov/index.html$(NC)"; \
	fi

ci: ## Commande pour CI/CD (tests + couverture)
	@echo "$(BLUE)Exécution du pipeline CI...$(NC)"
	@$(MAKE) venv
	@$(MAKE) install
	@$(MAKE) test-cov
	@$(MAKE) lint
	@echo "$(GREEN)✓ Pipeline CI terminé avec succès$(NC)"

deps-check: ## Vérifie les dépendances obsolètes
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Vérification des dépendances...$(NC)"
	$(PIP) list --outdated

deps-update: ## Met à jour les dépendances
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Mise à jour des dépendances...$(NC)"
	$(PIP) install --upgrade -r requirements.in

security-check: ## Vérifie les vulnérabilités de sécurité
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Vérification de sécurité avec safety...$(NC)"
	@if [ ! -f "$(VENV)/bin/safety" ]; then \
		echo "$(YELLOW)safety non installé, installation...$(NC)"; \
		$(PIP) install safety; \
	fi
	$(VENV)/bin/safety check

bandit: ## Analyse de sécurité du code avec bandit
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Analyse de sécurité du code...$(NC)"
	@if [ ! -f "$(VENV)/bin/bandit" ]; then \
		echo "$(YELLOW)bandit non installé, installation...$(NC)"; \
		$(PIP) install bandit; \
	fi
	$(VENV)/bin/bandit -r modules/ -ll

validate-config: ## Valide le fichier config.yaml
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Validation de config.yaml...$(NC)"
	@$(PYTHON) -c "import yaml; yaml.safe_load(open('config.yaml'))" && echo "$(GREEN)✓ config.yaml valide$(NC)" || echo "$(RED)✗ config.yaml invalide$(NC)"

benchmark: ## Lance des benchmarks de performance
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Exécution des benchmarks...$(NC)"
	@if [ ! -f "$(VENV)/bin/pytest" ]; then \
		echo "$(YELLOW)pytest-benchmark non installé, installation...$(NC)"; \
		$(PIP) install pytest-benchmark; \
	fi
	$(PYTEST) tests/unit/ --benchmark-only

docs: ## Génère la documentation
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Génération de la documentation...$(NC)"
	@if [ ! -f "$(VENV)/bin/pdoc" ]; then \
		echo "$(YELLOW)pdoc non installé, installation...$(NC)"; \
		$(PIP) install pdoc; \
	fi
	$(VENV)/bin/pdoc --html --output-dir docs/ modules/
	@echo "$(GREEN)✓ Documentation générée dans docs/$(NC)"

requirements: ## Génère requirements.txt depuis requirements.in
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Génération de requirements.txt...$(NC)"
	$(PIP) freeze > requirements.txt
	@echo "$(GREEN)✓ requirements.txt généré$(NC)"

version: ## Affiche les versions des outils
	@echo "$(BLUE)Versions des outils:$(NC)"
	@if [ -d "$(VENV)" ]; then \
		echo "Python: $$($(PYTHON) --version)"; \
		echo "Pip: $$($(PIP) --version)"; \
		echo "Pytest: $$($(PYTEST) --version 2>&1 || echo 'non installé')"; \
		echo "Behave: $$($(BEHAVE) --version 2>&1 || echo 'non installé')"; \
	else \
		echo "$(YELLOW)Virtualenv non trouvé. Lancez 'make venv'$(NC)"; \
	fi
	@echo "Docker: $$($(DOCKER) --version 2>&1 || echo 'non installé')"

status: ## Affiche le statut de l'environnement
	@echo "$(BLUE)Statut de l'environnement:$(NC)"
	@if [ -d "$(VENV)" ]; then \
		echo "$(GREEN)✓ Virtualenv: $(VENV) existe$(NC)"; \
		echo "  Python: $$($(PYTHON) --version)"; \
		echo "  Packages installés: $$($(PIP) list --format=freeze | wc -l)"; \
	else \
		echo "$(RED)✗ Virtualenv: non trouvé$(NC)"; \
		echo "  Lancez 'make venv' pour le créer"; \
	fi
	@echo ""
	@if $(DOCKER) ps | grep -q zap; then \
		echo "$(GREEN)✓ ZAP Docker: en cours d'exécution$(NC)"; \
	else \
		echo "$(YELLOW)⚠ ZAP Docker: arrêté$(NC)"; \
	fi
	@if $(DOCKER) ps | grep -q tor; then \
		echo "$(GREEN)✓ TOR Docker: en cours d'exécution$(NC)"; \
	else \
		echo "$(YELLOW)⚠ TOR Docker: arrêté$(NC)"; \
	fi

all: clean-venv venv install test ## Setup complet: clean + venv + install + test

# =============================================================================
# QUICKSTART TARGETS
# =============================================================================

env-setup: ## Crée .env depuis .env.example si absent
	@if [ ! -f ".env" ]; then \
		if [ -f ".env.example" ]; then \
			echo "$(BLUE)Création de .env depuis .env.example...$(NC)"; \
			cp .env.example .env; \
			echo "$(YELLOW)⚠ Éditez .env pour ajouter vos clés API$(NC)"; \
		else \
			echo "$(RED)✗ .env.example non trouvé$(NC)"; \
			exit 1; \
		fi \
	else \
		echo "$(GREEN)✓ .env existe déjà$(NC)"; \
	fi

setup: venv install ## Setup initial: venv + install
	@echo "$(GREEN)✓ Setup terminé$(NC)"
	@echo ""
	@echo "$(YELLOW)Prochaines étapes:$(NC)"
	@echo "  1. cp .env.example .env && nano .env"
	@echo "  2. Vérifiez config.yaml"
	@echo "  3. Lancez: make start"

zap-up: ## Démarre ZAP Docker avec config complète
	@echo "$(BLUE)Démarrage de ZAP...$(NC)"
	@$(DOCKER) rm -f harzap-zap 2>/dev/null || true
	@$(DOCKER) run -d \
		--name harzap-zap \
		-p $(ZAP_PORT):8080 \
		-p 8090:8090 \
		-v $(PWD)/scripts:/home/zap/scripts:ro \
		ghcr.io/zaproxy/zaproxy:stable \
		zap.sh -daemon -host 0.0.0.0 -port 8080 \
		-config api.addrs.addr.name=.* \
		-config api.addrs.addr.regex=true \
		-config api.disablekey=true
	@echo "$(BLUE)Attente de ZAP...$(NC)"
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
		if curl -s http://localhost:$(ZAP_PORT)/JSON/core/view/version/ >/dev/null 2>&1; then \
			echo "$(GREEN)✓ ZAP prêt sur http://localhost:$(ZAP_PORT)$(NC)"; \
			break; \
		fi; \
		echo "  Tentative $$i/10..."; \
		sleep 2; \
	done

zap-down: ## Arrête ZAP Docker
	@echo "$(BLUE)Arrêt de ZAP...$(NC)"
	@$(DOCKER) stop harzap-zap 2>/dev/null || true
	@$(DOCKER) rm harzap-zap 2>/dev/null || true
	@echo "$(GREEN)✓ ZAP arrêté$(NC)"

zap-logs: ## Affiche les logs ZAP
	@$(DOCKER) logs -f harzap-zap

app: ## Lance l'application Streamlit
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé. Lancez 'make setup' d'abord$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Démarrage de Streamlit sur http://localhost:$(STREAMLIT_PORT)...$(NC)"
	$(STREAMLIT) run app.py --server.port $(STREAMLIT_PORT)

check-env: ## Vérifie que .env existe
	@if [ ! -f ".env" ]; then \
		echo "$(RED)✗ .env non trouvé$(NC)"; \
		echo "$(YELLOW)Créez-le: cp .env.example .env && nano .env$(NC)"; \
		exit 1; \
	fi
	@echo "$(GREEN)✓ .env trouvé$(NC)"

start: setup check-env zap-up ## Démarre tout: setup + ZAP + app Streamlit
	@echo "$(GREEN)HAR.ZAP prêt$(NC)"
	@echo "  ZAP:       http://localhost:$(ZAP_PORT)"
	@echo "  Streamlit: http://localhost:$(STREAMLIT_PORT)"
	@$(MAKE) app

stop: zap-down observability-down ## Arrête tous les services
	@echo "$(GREEN)✓ Tous les services arrêtés$(NC)"

observability-up: ## Démarre Grafana + Loki pour les dashboards
	@echo "$(BLUE)Démarrage de la stack observability...$(NC)"
	@cd deployment && $(COMPOSE) -f docker-compose.observability.yml --profile loki up -d
	@echo "$(GREEN)✓ Grafana: http://localhost:3000 (admin/harzap2024)$(NC)"

observability-down: ## Arrête Grafana + Loki
	@echo "$(BLUE)Arrêt de la stack observability...$(NC)"
	@cd deployment && $(COMPOSE) -f docker-compose.observability.yml --profile loki down 2>/dev/null || true
	@echo "$(GREEN)✓ Stack observability arrêtée$(NC)"

start-full: start observability-up ## Démarre tout + dashboards Grafana
	@echo "$(GREEN)✓ Stack complète démarrée$(NC)"
	@echo "  Grafana: http://localhost:3000"

.DEFAULT_GOAL := help
