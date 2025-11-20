.PHONY: help venv install install-dev test test-unit test-bdd test-cov test-fast lint format clean run docker-up docker-down docker-clean

# Variables
VENV := .venv
PYTHON := $(VENV)/bin/python3
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest
BEHAVE := $(VENV)/bin/behave
STREAMLIT := $(VENV)/bin/streamlit
DOCKER := docker
COMPOSE := docker-compose

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

run: ## Lance l'interface web Streamlit
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé. Lancez 'make install' d'abord$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Démarrage de l'interface web...$(NC)"
	$(STREAMLIT) run app.py

run-cli: ## Lance le scanner en CLI (nécessite HAR_FILE)
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗ Virtualenv non trouvé. Lancez 'make install' d'abord$(NC)"; \
		exit 1; \
	fi
	@if [ -z "$(HAR_FILE)" ]; then \
		echo "$(RED)Erreur: HAR_FILE non spécifié$(NC)"; \
		echo "$(YELLOW)Usage: make run-cli HAR_FILE=path/to/file.har$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Lancement du scan CLI...$(NC)"
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

all: clean-venv venv install test ## Setup complet: clean + venv + install + test

.DEFAULT_GOAL := help
