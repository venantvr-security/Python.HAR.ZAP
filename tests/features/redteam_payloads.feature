Feature: Red Team Configurable Payloads
  En tant qu'utilisateur de la plateforme DAST
  Je veux configurer les payloads des attaques Red Team
  Afin d'adapter les tests à mon contexte spécifique

  Background:
    Given a valid HAR file with API endpoints

  Scenario: Utiliser les payloads par défaut pour Mass Assignment
    Given no custom configuration is provided
    When I execute Mass Assignment fuzzing
    Then the attack should use default payloads
    And the payloads should include "role: admin"
    And the payloads should include "is_admin: true"

  Scenario: Configurer des payloads personnalisés pour Mass Assignment
    Given a config file with custom mass_assignment payloads:
      | payload                    |
      | {"role": "superadmin"}     |
      | {"privileges": "all"}      |
      | {"account_level": "gold"}  |
    When I execute Mass Assignment fuzzing
    Then the attack should use 3 custom payloads
    And the attack should inject "superadmin" role
    And the attack should inject "all" privileges

  Scenario: Fallback aux payloads par défaut si config invalide
    Given a config file with invalid JSON payloads:
      | payload           |
      | not a json        |
      | {broken: syntax}  |
    When I execute Mass Assignment fuzzing
    Then the attack should fallback to default payloads
    And at least 5 payloads should be tested

  Scenario: Configurer des paramètres cachés personnalisés
    Given a config file with custom hidden_parameters:
      | parameter      |
      | debug=true     |
      | internal=1     |
      | trace=yes      |
    When I execute Hidden Parameter Discovery
    Then the attack should test "debug" parameter
    And the attack should test "internal" parameter
    And the attack should test "trace" parameter

  Scenario: Combiner payloads Mass Assignment et paramètres cachés
    Given a config file with both mass_assignment and hidden_parameters
    When I execute all Red Team attacks
    Then Mass Assignment should use custom payloads
    And Hidden Parameter Discovery should use custom parameters
    And both attacks should complete successfully
