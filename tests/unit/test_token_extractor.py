"""Tests for token extractor module"""
import pytest

from modules.token_extractor import TokenExtractor


@pytest.fixture
def sample_har_with_tokens():
    """HAR data with various token types"""
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/users/12345?token=abc123",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123"},
                            {"name": "Cookie", "value": "session=xyz789; token=secret"}
                        ],
                        "queryString": [
                            {"name": "token", "value": "abc123"}
                        ]
                    },
                    "response": {
                        "status": 200,
                        "content": {
                            "mimeType": "application/json",
                            "text": '{"user_id": 67890, "username": "john_doe", "email": "john@example.com"}'
                        }
                    }
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/login",
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"}
                        ],
                        "postData": {
                            "mimeType": "application/json",
                            "text": '{"username": "alice", "password": "secret123"}'
                        }
                    },
                    "response": {
                        "status": 200,
                        "content": {
                            "mimeType": "application/json",
                            "text": '{"token": "token456", "user_id": "550e8400-e29b-41d4-a716-446655440000"}'
                        }
                    }
                }
            ]
        }
    }


class TestTokenExtractor:
    """Test token extraction from HAR"""

    def test_extract_numeric_ids(self, sample_har_with_tokens):
        extractor = TokenExtractor(sample_har_with_tokens)
        tokens = extractor.extract_all()

        assert '12345' in tokens['ids']
        assert '67890' in tokens['ids']

    def test_extract_uuid_ids(self, sample_har_with_tokens):
        extractor = TokenExtractor(sample_har_with_tokens)
        tokens = extractor.extract_all()

        # UUID should be detected
        assert '550e8400-e29b-41d4-a716-446655440000' in tokens['ids']

    def test_extract_usernames(self, sample_har_with_tokens):
        extractor = TokenExtractor(sample_har_with_tokens)
        tokens = extractor.extract_all()

        assert 'john_doe' in tokens['usernames']
        assert 'alice' in tokens['usernames']

    def test_extract_emails(self, sample_har_with_tokens):
        extractor = TokenExtractor(sample_har_with_tokens)
        tokens = extractor.extract_all()

        assert 'john@example.com' in tokens['emails']

    def test_extract_session_tokens(self, sample_har_with_tokens):
        extractor = TokenExtractor(sample_har_with_tokens)
        tokens = extractor.extract_all()

        # Bearer token should be extracted
        assert any('eyJhbGciOiJIUzI1NiJ9' in token for token in tokens['session_tokens'])

    def test_extract_params(self, sample_har_with_tokens):
        extractor = TokenExtractor(sample_har_with_tokens)
        tokens = extractor.extract_all()

        assert 'token' in tokens['params']

    def test_is_id_detection(self, sample_har_with_tokens):
        extractor = TokenExtractor(sample_har_with_tokens)

        # Numeric ID
        assert extractor._is_id('12345')

        # UUID
        assert extractor._is_id('550e8400-e29b-41d4-a716-446655440000')

        # MongoDB ObjectId
        assert extractor._is_id('507f1f77bcf86cd799439011')

        # Not an ID
        assert not extractor._is_id('hello')

    def test_fuzzing_recommendations(self, sample_har_with_tokens):
        extractor = TokenExtractor(sample_har_with_tokens)
        extractor.extract_all()
        recommendations = extractor.get_fuzzing_recommendations()

        assert len(recommendations) > 0

        # Should recommend IDOR testing
        idor_recs = [r for r in recommendations if 'IDOR' in r['target']]
        assert len(idor_recs) > 0

        # Check recommendation structure
        for rec in recommendations:
            assert 'target' in rec
            assert 'params' in rec
            assert 'wordlist' in rec
            assert 'priority' in rec
            assert 'reason' in rec

    def test_export_wordlists(self, sample_har_with_tokens, tmp_path):
        extractor = TokenExtractor(sample_har_with_tokens)
        extractor.extract_all()

        output_dir = str(tmp_path / 'wordlists')
        extractor.export_for_zap_fuzzer(output_dir)

        # Check files were created
        import os

        assert os.path.exists(output_dir)

        # Check at least IDs file exists
        ids_file = os.path.join(output_dir, 'ids.txt')
        assert os.path.exists(ids_file)

        # Verify content
        with open(ids_file, 'r') as f:
            content = f.read()
            assert '12345' in content or '67890' in content

    def test_empty_har(self):
        """Test with empty HAR data"""
        empty_har = {"log": {"entries": []}}
        extractor = TokenExtractor(empty_har)
        tokens = extractor.extract_all()

        assert len(tokens['ids']) == 0
        assert len(tokens['usernames']) == 0
        assert len(tokens['emails']) == 0

    def test_malformed_json_in_response(self):
        """Test handling of malformed JSON"""
        har = {
            "log": {
                "entries": [{
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/test"
                    },
                    "response": {
                        "content": {
                            "mimeType": "application/json",
                            "text": "not valid json {["
                        }
                    }
                }]
            }
        }

        extractor = TokenExtractor(har)
        tokens = extractor.extract_all()

        # Should not crash, just skip malformed JSON
        assert isinstance(tokens, dict)
