Feature: Secrets Masking in Reports and Logs
  En tant qu'administrateur sécurité
  Je veux que les secrets soient masqués dans tous les rapports
  Afin d'éviter les fuites de données sensibles

  Background:
    Given the masking module is loaded

  Scenario: Masquer les tokens JWT dans les rapports JSON
    Given a security report containing JWT tokens
    When I generate the JSON report
    Then all JWT tokens should be replaced with "[MASKED]"
    And the report should be valid JSON

  Scenario: Masquer les en-têtes Authorization
    Given a HAR file with Authorization headers
    When I generate a report
    Then Authorization header values should show "[MASKED]"
    And Cookie header values should show "[MASKED]"

  Scenario: Masquer les clés API dans les logs console
    Given an alert with AWS API keys in the description
    When I print the alert to console
    Then the AWS key "AKIAIOSFODNN7EXAMPLE" should not appear
    And "[MASKED]" should appear instead

  Scenario: Masquer les tokens Bearer dans les URLs
    Given a vulnerable endpoint with token in query string:
      """
      https://api.example.com/data?token=secret123&page=1
      """
    When I log the URL
    Then the output should be "https://api.example.com/data?token=[MASKED]&page=1"

  Scenario: Masquer les mots de passe dans les corps de requête
    Given a POST request body:
      """
      {"username": "john", "password": "MySecret123"}
      """
    When I generate a report including this request
    Then "MySecret123" should not appear in the report
    And the password field should contain "[MASKED]"

  Scenario: Masquer les cookies de session
    Given a HAR entry with session cookies
    When I process the HAR entry for reporting
    Then all cookie values should be "[MASKED]"
    And cookie names should remain visible

  Scenario: Masquer les emails (PII)
    Given an alert description containing "user@example.com"
    When I save the alert to a text report
    Then "user@example.com" should be replaced with "[MASKED]"

  Scenario: Masquer les cartes de crédit
    Given response content with "4532-1234-5678-9010"
    When I include the response in a report
    Then the credit card number should be masked

  Scenario: Ne pas masquer les données normales
    Given a report with non-sensitive data:
      | field       | value                    |
      | url         | https://example.com/api  |
      | status      | 200                      |
      | method      | GET                      |
      | description | SQL injection detected   |
    When I apply masking
    Then all values should remain unchanged

  Scenario: Masquer récursivement dans les structures imbriquées
    Given a nested data structure:
      """
      {
        "level1": {
          "level2": {
            "Authorization": "Bearer secret123"
          }
        }
      }
      """
    When I apply masking
    Then the Authorization value should be "[MASKED]" at all levels

  Scenario: Masquer dans les rapports HTML générés par ZAP
    Given a ZAP HTML report with sensitive data
    When I save the HTML report
    Then sensitive patterns should be masked
    And the HTML structure should remain valid

  Scenario: Masquer les tokens Stripe
    Given an alert with "sk_live_abcdefghijklmnopqrstuvwx"
    When I generate a report
    Then the Stripe key should be masked

  Scenario: Personnaliser le placeholder de masquage
    Given a custom masking placeholder "***REDACTED***"
    When I mask sensitive data
    Then secrets should be replaced with "***REDACTED***"
    And not with "[MASKED]"

  Scenario: Logs de Red Team ne doivent pas exposer de secrets
    Given a Red Team attack on "https://api.example.com/admin?token=secret"
    When the attack logs progress
    Then the console output should show "[MASKED]" instead of "secret"
    And the URL structure should remain identifiable

  Scenario: Rapports critiques masquent les données sensibles
    Given 5 high-severity alerts with tokens in URLs
    When I save the critical findings report
    Then all tokens in URLs should be masked
    And the file should contain "[MASKED]" markers
