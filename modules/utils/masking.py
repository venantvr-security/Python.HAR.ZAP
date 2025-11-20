"""
Security masking utilities for sensitive data protection
Prevents secrets from leaking in logs and reports
"""
import re
from typing import Union, Dict, Any

# Regex patterns for common secrets
PATTERNS = {
    # JWT tokens (eyJ... format)
    'jwt': re.compile(r'ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),

    # Generic bearer tokens
    'bearer': re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', re.IGNORECASE),

    # API keys (various formats)
    'api_key_basic': re.compile(r'\b[A-Za-z0-9]{32,}\b'),  # 32+ alphanumeric
    'api_key_aws': re.compile(r'\b(AKIA|ASIA)[A-Z0-9]{16}\b'),  # AWS keys
    'api_key_stripe': re.compile(r'\b(sk|pk)_(live|test)_[A-Za-z0-9]{24,}\b'),  # Stripe

    # Session tokens / cookies
    'session': re.compile(r'(session|sess|sessionid|token)[:=]\s*[A-Za-z0-9\-._~+/]{20,}', re.IGNORECASE),

    # Passwords in URLs or data
    'password': re.compile(r'("password"|"passwd"|"pwd"|password|passwd|pwd)\s*[:=]\s*"?([^",\s&}]+)"?', re.IGNORECASE),

    # Credit card numbers (basic pattern)
    'credit_card': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),

    # Email addresses (PII)
    'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),

    # Social security numbers (US format)
    'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),

    # Basic auth credentials
    'basic_auth': re.compile(r'Basic\s+[A-Za-z0-9+/]+=*', re.IGNORECASE),
}

# Sensitive header names to mask
SENSITIVE_HEADERS = {
    'authorization',
    'cookie',
    'set-cookie',
    'x-api-key',
    'x-auth-token',
    'x-csrf-token',
    'api-key',
    'apikey',
    'auth-token',
    'access-token',
    'refresh-token',
    'x-access-token',
    'x-refresh-token',
}


def mask_sensitive_data(data: Union[str, Dict, Any], placeholder: str = '[MASKED]') -> Union[str, Dict, Any]:
    """
    Mask sensitive data using regex patterns

    Args:
        data: String or dict containing potentially sensitive data
        placeholder: Replacement string for masked data

    Returns:
        Data with sensitive values replaced by placeholder
    """
    if isinstance(data, dict):
        return mask_dict(data, placeholder)
    elif isinstance(data, str):
        return mask_string(data, placeholder)
    elif isinstance(data, list):
        return [mask_sensitive_data(item, placeholder) for item in data]
    else:
        return data


def mask_string(text: str, placeholder: str = '[MASKED]') -> str:
    """Mask sensitive patterns in a string"""
    if not isinstance(text, str):
        return text

    masked = text

    # Apply all regex patterns
    for pattern_name, pattern in PATTERNS.items():
        if pattern_name == 'password':
            # Special handling for password pattern with groups
            masked = pattern.sub(rf'\1: "{placeholder}"', masked)
        else:
            masked = pattern.sub(placeholder, masked)

    return masked


def mask_dict(data: Dict[str, Any], placeholder: str = '[MASKED]') -> Dict[str, Any]:
    """Recursively mask sensitive data in dictionaries"""
    if not isinstance(data, dict):
        return data

    masked = {}

    for key, value in data.items():
        # Check if key is sensitive header
        if key.lower() in SENSITIVE_HEADERS:
            masked[key] = placeholder
        # Recursively mask nested structures
        elif isinstance(value, dict):
            masked[key] = mask_dict(value, placeholder)
        elif isinstance(value, list):
            masked[key] = [mask_sensitive_data(item, placeholder) for item in value]
        elif isinstance(value, str):
            masked[key] = mask_string(value, placeholder)
        else:
            masked[key] = value

    return masked


def mask_headers(headers: Dict[str, str], placeholder: str = '[MASKED]') -> Dict[str, str]:
    """Mask sensitive HTTP headers"""
    masked = {}

    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADERS:
            masked[key] = placeholder
        else:
            # Still check value for embedded secrets
            masked[key] = mask_string(str(value), placeholder)

    return masked


def mask_url(url: str, placeholder: str = '[MASKED]') -> str:
    """Mask sensitive data in URLs (tokens, passwords in query params)"""
    if not url:
        return url

    # Mask common sensitive query parameters
    sensitive_params = ['token', 'api_key', 'apikey', 'password', 'pwd', 'secret', 'access_token']

    masked_url = url
    for param in sensitive_params:
        # Match param=value pattern
        pattern = re.compile(rf'({param}=)[^&\s]*', re.IGNORECASE)
        masked_url = pattern.sub(rf'\1{placeholder}', masked_url)

    return masked_url


def mask_har_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Mask sensitive data in a HAR entry"""
    masked_entry = entry.copy()

    # Mask request
    if 'request' in masked_entry:
        request = masked_entry['request']

        # Mask URL
        if 'url' in request:
            request['url'] = mask_url(request['url'])

        # Mask headers
        if 'headers' in request:
            request['headers'] = [
                {'name': h['name'], 'value': mask_string(h['value']) if h['name'].lower() not in SENSITIVE_HEADERS else '[MASKED]'}
                for h in request['headers']
            ]

        # Mask cookies
        if 'cookies' in request:
            request['cookies'] = [
                {**c, 'value': '[MASKED]'} for c in request['cookies']
            ]

        # Mask POST data
        if 'postData' in request and 'text' in request['postData']:
            request['postData']['text'] = mask_string(request['postData']['text'])

    # Mask response
    if 'response' in masked_entry:
        response = masked_entry['response']

        # Mask response headers
        if 'headers' in response:
            response['headers'] = [
                {'name': h['name'], 'value': mask_string(h['value']) if h['name'].lower() not in SENSITIVE_HEADERS else '[MASKED]'}
                for h in response['headers']
            ]

        # Mask response cookies
        if 'cookies' in response:
            response['cookies'] = [
                {**c, 'value': '[MASKED]'} for c in response['cookies']
            ]

        # Mask response content
        if 'content' in response and 'text' in response['content']:
            response['content']['text'] = mask_string(response['content']['text'])

    return masked_entry
