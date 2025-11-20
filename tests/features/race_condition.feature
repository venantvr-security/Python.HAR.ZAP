Feature: Race Condition Testing
  En tant que testeur de sécurité
  Je veux détecter les vulnérabilités de race condition
  Afin de prévenir les attaques TOCTOU et les abus de concurrence

  Background:
    Given a HAR file with critical endpoints

  Scenario: Configuration par défaut avec 50 requêtes
    Given no race condition configuration is provided
    When I execute Race Condition testing
    Then 50 concurrent requests should be sent per endpoint
    And the burst should execute in parallel

  Scenario: Configuration personnalisée du nombre de requêtes
    Given a config with race_condition_requests set to 100
    When I execute Race Condition testing on a transfer endpoint
    Then 100 concurrent requests should be sent
    And all requests should execute quasi-simultaneously

  Scenario: Détection de race condition sur un endpoint vulnérable
    Given a vulnerable endpoint "/api/coupon/redeem"
    And the endpoint allows multiple redemptions
    When I send 50 concurrent requests
    Then multiple successful responses should be detected
    And the attack should report a vulnerability
    And the confidence level should be above 0.5

  Scenario: Protection contre race condition détectée
    Given a protected endpoint "/api/transfer"
    And the endpoint uses proper locking
    When I send 50 concurrent requests
    Then only one successful response should occur
    And the attack should report no vulnerability

  Scenario: Analyse des réponses pour détecter des anomalies
    Given an endpoint with race condition vulnerability
    When I execute burst testing with 30 requests
    Then the analyzer should detect response variance
    And the analyzer should identify multiple successes
    And vulnerability indicators should be listed in the evidence

  Scenario: Test de plusieurs endpoints critiques
    Given a HAR file with endpoints:
      | endpoint              |
      | /api/transfer         |
      | /api/coupon/redeem    |
      | /api/vote             |
      | /api/purchase         |
    When I execute Race Condition testing
    Then all 4 endpoints should be tested
    And results should be aggregated
    And vulnerable endpoints should be highlighted

  Scenario: Gestion des erreurs réseau pendant le burst
    Given a slow endpoint that may timeout
    When I execute burst testing with 20 requests
    Then timeout errors should be captured
    And errors should not crash the test
    And partial results should still be analyzed

  Scenario: Variation des longueurs de réponse comme indicateur
    Given an endpoint with inconsistent race behavior
    When I send 40 concurrent requests
    And responses have varying content lengths
    Then high length variance should be detected
    And it should be reported as a vulnerability indicator
