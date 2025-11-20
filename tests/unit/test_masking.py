"""
Unit tests for masking module
Tests sensitive data detection and masking functionality
"""

from modules.utils.masking import (
    mask_sensitive_data,
    mask_string,
    mask_dict,
    mask_headers,
    mask_url,
    mask_har_entry
)


class TestMaskString:
    """Test string masking functionality"""

    def test_mask_jwt_token(self):
        text = "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        masked = mask_string(text)
        assert "[MASKED]" in masked
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in masked

    def test_mask_bearer_token(self):
        text = "Bearer abc123def456ghi789"
        masked = mask_string(text)
        assert "[MASKED]" in masked
        assert "abc123def456ghi789" not in masked

    def test_mask_aws_api_key(self):
        text = "API_KEY=AKIAIOSFODNN7EXAMPLE"
        masked = mask_string(text)
        assert "[MASKED]" in masked
        assert "AKIAIOSFODNN7EXAMPLE" not in masked

    def test_mask_stripe_key(self):
        text = "stripe_key=sk_test_abcdefghijklmnopqrstuvwx"
        masked = mask_string(text)
        assert "[MASKED]" in masked
        assert "sk_test_abcdefghijklmnopqrstuvwx" not in masked

    def test_mask_email(self):
        text = "Contact: user@example.com for support"
        masked = mask_string(text)
        assert "[MASKED]" in masked
        assert "user@example.com" not in masked

    def test_mask_credit_card(self):
        text = "Card: 4532-1234-5678-9010"
        masked = mask_string(text)
        assert "[MASKED]" in masked
        assert "4532-1234-5678-9010" not in masked

    def test_mask_ssn(self):
        text = "SSN: 123-45-6789"
        masked = mask_string(text)
        assert "[MASKED]" in masked
        assert "123-45-6789" not in masked

    def test_mask_password_in_text(self):
        text = "password=MySecretP@ssw0rd"
        masked = mask_string(text)
        assert "[MASKED]" in masked
        assert "MySecretP@ssw0rd" not in masked

    def test_no_masking_normal_text(self):
        text = "This is normal text without secrets"
        masked = mask_string(text)
        assert masked == text

    def test_custom_placeholder(self):
        text = "Bearer token123456"
        masked = mask_string(text, placeholder="***")
        assert "***" in masked
        assert "[MASKED]" not in masked


class TestMaskDict:
    """Test dictionary masking functionality"""

    def test_mask_authorization_header(self):
        data = {"Authorization": "Bearer secret123"}
        masked = mask_dict(data)
        assert masked["Authorization"] == "[MASKED]"

    def test_mask_cookie_header(self):
        data = {"Cookie": "session=abc123; token=xyz789"}
        masked = mask_dict(data)
        assert masked["Cookie"] == "[MASKED]"

    def test_mask_api_key_header(self):
        data = {"X-API-Key": "secret_key_12345"}
        masked = mask_dict(data)
        assert masked["X-API-Key"] == "[MASKED]"

    def test_mask_nested_dict(self):
        data = {
            "user": {
                "name": "John",
                "Authorization": "Bearer token123"
            }
        }
        masked = mask_dict(data)
        assert masked["user"]["name"] == "John"
        assert masked["user"]["Authorization"] == "[MASKED]"

    def test_mask_list_values(self):
        data = {
            "tokens": ["Bearer abc", "Bearer def"]
        }
        masked = mask_dict(data)
        assert "[MASKED]" in str(masked["tokens"])

    def test_preserve_non_sensitive_data(self):
        data = {
            "status": "success",
            "count": 42,
            "message": "Operation completed"
        }
        masked = mask_dict(data)
        assert masked == data


class TestMaskHeaders:
    """Test HTTP headers masking"""

    def test_mask_sensitive_headers(self):
        headers = {
            "Authorization": "Bearer token123",
            "Cookie": "session=abc",
            "Content-Type": "application/json"
        }
        masked = mask_headers(headers)
        assert masked["Authorization"] == "[MASKED]"
        assert masked["Cookie"] == "[MASKED]"
        assert masked["Content-Type"] == "application/json"

    def test_case_insensitive_header_names(self):
        headers = {
            "authorization": "Bearer token123",
            "COOKIE": "session=abc"
        }
        masked = mask_headers(headers)
        assert masked["authorization"] == "[MASKED]"
        assert masked["COOKIE"] == "[MASKED]"

    def test_mask_embedded_tokens_in_headers(self):
        headers = {
            "X-Custom-Header": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123"
        }
        masked = mask_headers(headers)
        assert "[MASKED]" in masked["X-Custom-Header"]


class TestMaskUrl:
    """Test URL masking functionality"""

    def test_mask_token_in_query_param(self):
        url = "https://api.example.com/data?token=secret123&page=1"
        masked = mask_url(url)
        assert "secret123" not in masked
        assert "token=[MASKED]" in masked
        assert "page=1" in masked

    def test_mask_api_key_in_query_param(self):
        url = "https://api.example.com/endpoint?api_key=ABC123XYZ"
        masked = mask_url(url)
        assert "ABC123XYZ" not in masked
        assert "api_key=[MASKED]" in masked

    def test_mask_password_in_url(self):
        url = "https://example.com/login?username=john&password=secret"
        masked = mask_url(url)
        assert "secret" not in masked
        assert "password=[MASKED]" in masked

    def test_preserve_url_structure(self):
        url = "https://api.example.com/users/123?sort=name"
        masked = mask_url(url)
        assert "https://api.example.com/users/123" in masked
        assert "sort=name" in masked


class TestMaskHarEntry:
    """Test HAR entry masking"""

    def test_mask_request_headers(self):
        entry = {
            "request": {
                "url": "https://api.example.com/data",
                "headers": [
                    {"name": "Authorization", "value": "Bearer token123"},
                    {"name": "Content-Type", "value": "application/json"}
                ]
            }
        }
        masked = mask_har_entry(entry)
        auth_header = next(h for h in masked["request"]["headers"] if h["name"] == "Authorization")
        assert auth_header["value"] == "[MASKED]"

    def test_mask_request_cookies(self):
        entry = {
            "request": {
                "cookies": [
                    {"name": "session", "value": "abc123"},
                    {"name": "tracking", "value": "xyz789"}
                ]
            }
        }
        masked = mask_har_entry(entry)
        for cookie in masked["request"]["cookies"]:
            assert cookie["value"] == "[MASKED]"

    def test_mask_post_data(self):
        entry = {
            "request": {
                "postData": {
                    "text": '{"password": "secret123", "email": "user@example.com"}'
                }
            }
        }
        masked = mask_har_entry(entry)
        post_text = masked["request"]["postData"]["text"]
        assert "secret123" not in post_text
        assert "user@example.com" not in post_text
        assert "[MASKED]" in post_text

    def test_mask_response_headers(self):
        entry = {
            "response": {
                "headers": [
                    {"name": "Set-Cookie", "value": "session=abc123"},
                    {"name": "Content-Type", "value": "text/html"}
                ]
            }
        }
        masked = mask_har_entry(entry)
        set_cookie = next(h for h in masked["response"]["headers"] if h["name"] == "Set-Cookie")
        assert set_cookie["value"] == "[MASKED]"

    def test_mask_response_content(self):
        entry = {
            "response": {
                "content": {
                    "text": '{"token": "eyJhbGciOiJIUzI1NiJ9.abc.def", "status": "ok"}'
                }
            }
        }
        masked = mask_har_entry(entry)
        content_text = masked["response"]["content"]["text"]
        assert "eyJhbGciOiJIUzI1NiJ9.abc.def" not in content_text
        assert "[MASKED]" in content_text
        assert "status" in content_text


class TestMaskSensitiveData:
    """Test generic sensitive data masking"""

    def test_mask_string_input(self):
        data = "Bearer token123"
        result = mask_sensitive_data(data)
        assert isinstance(result, str)
        assert "[MASKED]" in result

    def test_mask_dict_input(self):
        data = {"Authorization": "Bearer token"}
        result = mask_sensitive_data(data)
        assert isinstance(result, dict)
        assert result["Authorization"] == "[MASKED]"

    def test_mask_list_input(self):
        data = ["Bearer token1", "Bearer token2"]
        result = mask_sensitive_data(data)
        assert isinstance(result, list)
        assert all("[MASKED]" in item for item in result)

    def test_return_other_types_unchanged(self):
        assert mask_sensitive_data(123) == 123
        assert mask_sensitive_data(None) is None
        assert mask_sensitive_data(True) is True


class TestEdgeCases:
    """Test edge cases and error handling"""

    def test_empty_string(self):
        assert mask_string("") == ""

    def test_empty_dict(self):
        assert mask_dict({}) == {}

    def test_none_values(self):
        data = {"key": None}
        masked = mask_dict(data)
        assert masked["key"] is None

    def test_deeply_nested_structure(self):
        data = {
            "level1": {
                "level2": {
                    "level3": {
                        "Authorization": "Bearer secret"
                    }
                }
            }
        }
        masked = mask_dict(data)
        assert masked["level1"]["level2"]["level3"]["Authorization"] == "[MASKED]"

    def test_special_characters_in_values(self):
        text = "Token: abc!@#$%^&*()_+-=[]{}|;:',.<>?"
        masked = mask_string(text)
        assert isinstance(masked, str)

    def test_unicode_characters(self):
        text = "Message: 你好世界 with Bearer token123"
        masked = mask_string(text)
        assert "你好世界" in masked
        assert "[MASKED]" in masked
