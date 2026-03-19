Feature: Support multi-provider LLM avec Gemini
  En tant que pentester
  Je veux utiliser Google Gemini comme provider LLM
  Afin de bénéficier du mode batch asynchrone et des coûts réduits

  Background:
    Given le module LLM est configuré

  Scenario: Analyser un HAR avec Gemini en mode synchrone
    Given le provider LLM est "gemini"
    And le modèle est "gemini-1.5-pro"
    And la clé API Gemini est configurée
    And le mode batch est désactivé
    When j'analyse un fichier HAR d'une application e-commerce
    Then l'analyse devrait retourner un SecurityPlan
    And le plan devrait contenir des stratégies d'attaque
    And le metadata devrait indiquer "gemini" comme provider
    And la réponse devrait être synchrone

  Scenario: Analyser un HAR avec Gemini en mode batch asynchrone
    Given le provider LLM est "gemini"
    And le modèle est "gemini-1.5-flash"
    And la clé API Gemini est configurée
    And le mode batch est activé
    And le poll interval est 2 secondes
    When j'analyse un fichier HAR volumineux
    Then le système devrait créer un job batch
    And le système devrait poller le statut jusqu'à completion
    And l'analyse devrait retourner un SecurityPlan valide
    And la latence devrait être enregistrée
    And le coût devrait être réduit de 50%

  Scenario: Basculer entre providers Anthropic et Gemini
    Given j'ai deux configurations LLM:
      | provider   | model                    | api_key_env          |
      | anthropic  | claude-sonnet-4-20250514 | HARZAP_LLM_API_KEY   |
      | gemini     | gemini-1.5-pro           | HARZAP_GEMINI_API_KEY|
    When je change la variable d'environnement HARZAP_LLM_PROVIDER
    Then le client LLM devrait utiliser le bon provider
    And les appels API devraient être dirigés vers le bon endpoint
    And le format de réponse devrait être normalisé en LLMResponse

  Scenario: Gérer l'échec d'un batch Gemini
    Given le provider LLM est "gemini"
    And le mode batch est activé
    When j'analyse un HAR avec un contenu invalide
    And le job batch retourne "JOB_STATE_FAILED"
    Then une RuntimeError devrait être levée
    And l'erreur devrait contenir "Gemini batch failed"
    And les logs devraient enregistrer l'échec

  Scenario: Timeout du polling batch
    Given le provider LLM est "gemini"
    And le mode batch est activé
    And le batch_max_wait est 5 secondes
    When j'analyse un HAR
    And le job batch reste en "JOB_STATE_RUNNING" pendant plus de 5 secondes
    Then une TimeoutError devrait être levée
    And l'erreur devrait contenir "Gemini batch timeout"

  Scenario: Cache fonctionne avec tous les providers
    Given le provider LLM est "gemini"
    And le cache LLM est activé
    When j'analyse le même HAR deux fois
    Then la première analyse devrait appeler l'API Gemini
    And la deuxième analyse devrait utiliser le cache
    And le metadata devrait indiquer "cached: true"
    And aucun appel API supplémentaire ne devrait être fait

  Scenario: Configuration via variables d'environnement
    Given les variables d'environnement suivantes:
      | variable                       | valeur            |
      | HARZAP_LLM_PROVIDER            | gemini            |
      | HARZAP_GEMINI_API_KEY          | test-key-123      |
      | HARZAP_LLM_MODEL               | gemini-2.0-flash  |
      | HARZAP_LLM_BATCH_ENABLED       | true              |
      | HARZAP_LLM_BATCH_POLL_INTERVAL | 3.0               |
    When je charge la configuration LLM
    Then le client devrait être configuré avec:
      | attribut            | valeur attendue   |
      | provider            | gemini            |
      | gemini_api_key      | test-key-123      |
      | model               | gemini-2.0-flash  |
      | batch_enabled       | true              |
      | batch_poll_interval | 3.0               |

  Scenario: Validation de la configuration au démarrage
    Given le provider LLM est "gemini"
    And la clé API Gemini n'est pas configurée
    When j'initialise le client LLM
    Then une ValueError devrait être levée
    And le message devrait contenir "Gemini API key required"
    And le système devrait suggérer de configurer HARZAP_GEMINI_API_KEY

  Scenario: Rate limiting fonctionne avec Gemini
    Given le provider LLM est "gemini"
    And le requests_per_minute est 10
    When j'effectue 15 analyses successives
    Then les 10 premières devraient passer immédiatement
    And les 5 suivantes devraient être rate-limitées
    And le temps total devrait respecter la limite de 10 req/min
