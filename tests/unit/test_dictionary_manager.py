"""Tests for dictionary_manager.py."""
import pytest
import json
from pathlib import Path


class TestDictionaryManager:
    """Tests for DictionaryManager."""

    def test_init_creates_directories(self, tmp_path):
        from modules.dictionary_manager import DictionaryManager

        dm = DictionaryManager(base_dict_path=str(tmp_path))
        assert (tmp_path / 'custom').exists()
        assert (tmp_path / 'generated').exists()

    def test_create_base_dictionaries(self, tmp_path):
        from modules.dictionary_manager import DictionaryManager

        dm = DictionaryManager(base_dict_path=str(tmp_path))
        dm.create_base_dictionaries()

        assert (tmp_path / 'generated' / 'mass_assignment.json').exists()
        assert (tmp_path / 'generated' / 'hidden_parameters.json').exists()
        assert (tmp_path / 'generated' / 'injection_payloads.json').exists()

    def test_load_dictionary(self, tmp_path):
        from modules.dictionary_manager import DictionaryManager

        dm = DictionaryManager(base_dict_path=str(tmp_path))
        test_dict = {'test': 'data', 'keys': {'admin': True}}

        dm.save_dictionary('test_dict', test_dict, 'custom')
        loaded = dm.load_dictionary('test_dict')

        assert loaded['test'] == 'data'
        assert loaded['keys']['admin'] is True

    def test_save_and_load_custom(self, tmp_path):
        from modules.dictionary_manager import DictionaryManager

        dm = DictionaryManager(base_dict_path=str(tmp_path))
        data = {'metadata': {'name': 'test'}, 'keys': {'role': 'admin'}}

        dm.save_dictionary('custom_test', data, 'custom')
        loaded = dm.load_dictionary('custom_test')

        assert loaded['keys']['role'] == 'admin'

    def test_extend_dictionary(self, tmp_path):
        from modules.dictionary_manager import DictionaryManager

        dm = DictionaryManager(base_dict_path=str(tmp_path))

        base = {
            'metadata': {'name': 'test'},
            'keys': {'is_admin': True}
        }
        dm.save_dictionary('base', base, 'generated')

        extensions = {
            'keys': {'is_superuser': True},
            'new_field': 'value'
        }

        extended = dm.extend_dictionary('base', extensions)

        assert extended['keys']['is_admin'] is True
        assert extended['keys']['is_superuser'] is True
        assert extended['new_field'] == 'value'
        assert 'extensions' in extended

    def test_extend_nonexistent_dictionary(self, tmp_path):
        from modules.dictionary_manager import DictionaryManager

        dm = DictionaryManager(base_dict_path=str(tmp_path))
        extensions = {'new_key': 'new_value'}

        result = dm.extend_dictionary('nonexistent', extensions)

        assert result['new_key'] == 'new_value'
        assert 'extensions' in result

    def test_import_from_file(self, tmp_path):
        from modules.dictionary_manager import DictionaryManager

        import_file = tmp_path / 'import_test.json'
        test_data = {'metadata': {'name': 'imported'}, 'data': [1, 2, 3]}

        import_file.write_text(json.dumps(test_data))

        dm = DictionaryManager(base_dict_path=str(tmp_path / 'dicts'))
        dm.import_from_file(str(import_file))

        loaded = dm.load_dictionary('import_test')
        assert loaded['data'] == [1, 2, 3]

    def test_export_to_file(self, tmp_path):
        from modules.dictionary_manager import DictionaryManager

        dm = DictionaryManager(base_dict_path=str(tmp_path))
        test_dict = {'metadata': {'name': 'export_test'}, 'data': 'test'}

        dm.save_dictionary('export_test', test_dict, 'custom')

        export_path = tmp_path / 'exported.json'
        dm.export_to_file('export_test', str(export_path))

        assert export_path.exists()
        exported_data = json.loads(export_path.read_text())
        assert exported_data['data'] == 'test'

    def test_export_nonexistent_dictionary(self, tmp_path):
        from modules.dictionary_manager import DictionaryManager

        dm = DictionaryManager(base_dict_path=str(tmp_path))
        export_path = tmp_path / 'exported.json'

        dm.export_to_file('nonexistent', str(export_path))

        assert not export_path.exists()

    def test_list_dictionaries(self, tmp_path):
        from modules.dictionary_manager import DictionaryManager

        dm = DictionaryManager(base_dict_path=str(tmp_path))

        dm.save_dictionary('dict1', {'test': 1}, 'custom')
        dm.save_dictionary('dict2', {'test': 2}, 'generated')

        result = dm.list_dictionaries()

        assert 'dict1' in result['custom']
        assert 'dict2' in result['generated']

    def test_get_dictionary_info(self, tmp_path):
        from modules.dictionary_manager import DictionaryManager

        dm = DictionaryManager(base_dict_path=str(tmp_path))

        test_dict = {
            'metadata': {
                'name': 'info_test',
                'description': 'Test dictionary',
                'version': '1.0'
            },
            'keys': {'key1': 'val1', 'key2': 'val2'}
        }

        dm.save_dictionary('info_test', test_dict, 'custom')
        info = dm.get_dictionary_info('info_test')

        assert info['name'] == 'info_test'
        assert info['description'] == 'Test dictionary'
        assert info['version'] == '1.0'
        assert info['total_keys'] == 1  # Only 'keys' is a real key

    def test_get_dictionary_info_nonexistent(self, tmp_path):
        from modules.dictionary_manager import DictionaryManager

        dm = DictionaryManager(base_dict_path=str(tmp_path))
        info = dm.get_dictionary_info('nonexistent')

        assert info is None

    def test_merge_dictionaries(self, tmp_path):
        from modules.dictionary_manager import DictionaryManager

        dm = DictionaryManager(base_dict_path=str(tmp_path))

        dict1 = {
            'metadata': {'name': 'dict1'},
            'keys': {'admin': True},
            'payloads': ['payload1']
        }

        dict2 = {
            'metadata': {'name': 'dict2'},
            'keys': {'superuser': True},
            'payloads': ['payload2']
        }

        dm.save_dictionary('dict1', dict1, 'custom')
        dm.save_dictionary('dict2', dict2, 'custom')

        merged = dm.merge_dictionaries(['dict1', 'dict2'], 'merged')

        assert merged['keys']['admin'] is True
        assert merged['keys']['superuser'] is True
        assert 'payload1' in merged['payloads']
        assert 'payload2' in merged['payloads']

    def test_mass_assignment_dictionary_structure(self, tmp_path):
        from modules.dictionary_manager import DictionaryManager

        dm = DictionaryManager(base_dict_path=str(tmp_path))
        dm.create_base_dictionaries()

        mass_dict = dm.load_dictionary('mass_assignment')

        assert 'keys' in mass_dict
        assert 'is_admin' in mass_dict['keys']
        assert 'role' in mass_dict['keys']
        assert mass_dict['keys']['is_admin']['severity'] == 'CRITICAL'

    def test_hidden_parameters_dictionary_structure(self, tmp_path):
        from modules.dictionary_manager import DictionaryManager

        dm = DictionaryManager(base_dict_path=str(tmp_path))
        dm.create_base_dictionaries()

        hidden_dict = dm.load_dictionary('hidden_parameters')

        assert 'parameters' in hidden_dict
        assert 'debug' in hidden_dict['parameters']
        assert 'admin' in hidden_dict['parameters']

    def test_injection_payloads_dictionary_structure(self, tmp_path):
        from modules.dictionary_manager import DictionaryManager

        dm = DictionaryManager(base_dict_path=str(tmp_path))
        dm.create_base_dictionaries()

        injection_dict = dm.load_dictionary('injection_payloads')

        assert 'sqli' in injection_dict
        assert 'xss' in injection_dict
        assert 'command' in injection_dict
        assert len(injection_dict['sqli']) > 0

    def test_extend_with_list_merge(self, tmp_path):
        from modules.dictionary_manager import DictionaryManager

        dm = DictionaryManager(base_dict_path=str(tmp_path))

        base = {'items': [1, 2, 3]}
        dm.save_dictionary('list_test', base, 'generated')

        extensions = {'items': [4, 5]}
        extended = dm.extend_dictionary('list_test', extensions)

        assert extended['items'] == [1, 2, 3, 4, 5]

    def test_extend_with_dict_merge(self, tmp_path):
        from modules.dictionary_manager import DictionaryManager

        dm = DictionaryManager(base_dict_path=str(tmp_path))

        base = {'config': {'key1': 'val1'}}
        dm.save_dictionary('dict_test', base, 'generated')

        extensions = {'config': {'key2': 'val2'}}
        extended = dm.extend_dictionary('dict_test', extensions)

        assert extended['config']['key1'] == 'val1'
        assert extended['config']['key2'] == 'val2'
