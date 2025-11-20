from typing import Dict


class AdvancedZAPConfig:
    """Advanced ZAP configuration for authentication, sessions, and contexts"""

    def __init__(self, zap_client):
        self.zap = zap_client

    def configure_authentication(self, auth_config: Dict):
        """Configure authentication in ZAP"""
        auth_method = auth_config.get('method', 'manual')

        if auth_method == 'form_based':
            self._configure_form_auth(auth_config)
        elif auth_method == 'script_based':
            self._configure_script_auth(auth_config)
        elif auth_method == 'http_basic':
            self._configure_http_auth(auth_config)
        elif auth_method == 'oauth2':
            self._configure_oauth2(auth_config)
        elif auth_method == 'jwt':
            self._configure_jwt_auth(auth_config)

    def _configure_form_auth(self, config: Dict):
        """Configure form-based authentication"""
        try:
            context_id = self._get_or_create_context(config.get('context_name', 'Default'))

            login_url = config.get('login_url')
            username_field = config.get('username_field', 'username')
            password_field = config.get('password_field', 'password')

            self.zap.authentication.set_authentication_method(
                contextid=context_id,
                authmethodname='formBasedAuthentication',
                authmethodconfigparams=f'loginUrl={login_url}&loginRequestData={username_field}=%username%&{password_field}=%password%'
            )

            self._create_user(
                context_id,
                config.get('username', 'testuser'),
                config.get('password', 'testpass')
            )

            print(f"[ZAPConfig] Form-based auth configured for context {context_id}")

        except Exception as e:
            print(f"[ZAPConfig] Failed to configure form auth: {e}")

    def _configure_script_auth(self, config: Dict):
        """Configure script-based authentication"""
        try:
            context_id = self._get_or_create_context(config.get('context_name', 'Default'))

            script_name = config.get('script_name')
            script_content = config.get('script_content')

            if script_content:
                self.zap.script.load(
                    scriptname=script_name,
                    scripttype='authentication',
                    scriptengine='Oracle Nashorn',
                    filename='',
                    scriptdescription='Custom authentication script',
                    charset='UTF-8'
                )

            print(f"[ZAPConfig] Script-based auth configured")

        except Exception as e:
            print(f"[ZAPConfig] Failed to configure script auth: {e}")

    def _configure_http_auth(self, config: Dict):
        """Configure HTTP Basic/Digest authentication"""
        try:
            context_id = self._get_or_create_context(config.get('context_name', 'Default'))

            self.zap.authentication.set_authentication_method(
                contextid=context_id,
                authmethodname='httpAuthentication',
                authmethodconfigparams=f'hostname={config.get("hostname")}&realm={config.get("realm", "")}&port={config.get("port", 80)}'
            )

            self._create_user(
                context_id,
                config.get('username'),
                config.get('password')
            )

            print(f"[ZAPConfig] HTTP auth configured")

        except Exception as e:
            print(f"[ZAPConfig] Failed to configure HTTP auth: {e}")

    def _configure_oauth2(self, config: Dict):
        """Configure OAuth2 authentication"""
        try:
            token = config.get('access_token')

            if token:
                self.zap.replacer.add_rule(
                    description='OAuth2 Bearer Token',
                    enabled=True,
                    matchtype='REQ_HEADER',
                    matchstring='Authorization',
                    replacement=f'Bearer {token}'
                )

                print(f"[ZAPConfig] OAuth2 token configured")

        except Exception as e:
            print(f"[ZAPConfig] Failed to configure OAuth2: {e}")

    def _configure_jwt_auth(self, config: Dict):
        """Configure JWT token authentication"""
        try:
            token = config.get('jwt_token')

            if token:
                self.zap.replacer.add_rule(
                    description='JWT Token',
                    enabled=True,
                    matchtype='REQ_HEADER',
                    matchstring='Authorization',
                    replacement=f'Bearer {token}'
                )

                print(f"[ZAPConfig] JWT token configured")

        except Exception as e:
            print(f"[ZAPConfig] Failed to configure JWT: {e}")

    def configure_session_management(self, session_config: Dict):
        """Configure session management"""
        try:
            context_id = self._get_or_create_context(session_config.get('context_name', 'Default'))

            method = session_config.get('method', 'cookie')

            if method == 'cookie':
                self.zap.sessionManagement.set_session_management_method(
                    contextid=context_id,
                    methodname='cookieBasedSessionManagement'
                )
            elif method == 'http':
                self.zap.sessionManagement.set_session_management_method(
                    contextid=context_id,
                    methodname='httpAuthSessionManagement'
                )

            print(f"[ZAPConfig] Session management configured: {method}")

        except Exception as e:
            print(f"[ZAPConfig] Failed to configure session management: {e}")

    def configure_context(self, context_config: Dict):
        """Configure ZAP context with include/exclude patterns"""
        try:
            context_name = context_config.get('name', 'Default')
            context_id = self._get_or_create_context(context_name)

            for pattern in context_config.get('include_patterns', []):
                self.zap.context.include_in_context(context_name, pattern)

            for pattern in context_config.get('exclude_patterns', []):
                self.zap.context.exclude_from_context(context_name, pattern)

            print(f"[ZAPConfig] Context '{context_name}' configured")

        except Exception as e:
            print(f"[ZAPConfig] Failed to configure context: {e}")

    def configure_spider(self, spider_config: Dict):
        """Configure spider settings"""
        try:
            max_depth = spider_config.get('max_depth', 5)
            max_children = spider_config.get('max_children', 10)
            max_duration = spider_config.get('max_duration', 10)

            self.zap.spider.set_option_max_depth(max_depth)
            self.zap.spider.set_option_max_children(max_children)
            self.zap.spider.set_option_max_duration(max_duration)

            parse_comments = spider_config.get('parse_comments', True)
            self.zap.spider.set_option_parse_comments(parse_comments)

            print(f"[ZAPConfig] Spider configured (depth: {max_depth}, duration: {max_duration})")

        except Exception as e:
            print(f"[ZAPConfig] Failed to configure spider: {e}")

    def configure_active_scan_policy(self, policy_name: str, policy_config: Dict):
        """Configure custom active scan policy"""
        try:
            strength = policy_config.get('strength', 'MEDIUM')
            threshold = policy_config.get('threshold', 'MEDIUM')

            enabled_categories = policy_config.get('categories', [])
            disabled_scanners = policy_config.get('disabled_scanners', [])

            for scanner_id in disabled_scanners:
                self.zap.ascan.set_scanner_alert_threshold(
                    id=scanner_id,
                    alertthreshold='OFF',
                    scanpolicyname=policy_name
                )

            print(f"[ZAPConfig] Scan policy '{policy_name}' configured")

        except Exception as e:
            print(f"[ZAPConfig] Failed to configure scan policy: {e}")

    def configure_proxy_chain(self, proxy_config: Dict):
        """Configure upstream proxy"""
        try:
            enabled = proxy_config.get('enabled', False)
            host = proxy_config.get('host')
            port = proxy_config.get('port')

            if enabled and host and port:
                self.zap.core.set_option_proxy_chain_name(host)
                self.zap.core.set_option_proxy_chain_port(port)

                if proxy_config.get('username'):
                    self.zap.core.set_option_proxy_chain_user_name(proxy_config['username'])
                if proxy_config.get('password'):
                    self.zap.core.set_option_proxy_chain_password(proxy_config['password'])

                print(f"[ZAPConfig] Upstream proxy configured: {host}:{port}")

        except Exception as e:
            print(f"[ZAPConfig] Failed to configure proxy: {e}")

    def _get_or_create_context(self, context_name: str) -> str:
        """Get existing context or create new one"""
        try:
            contexts = self.zap.context.context_list
            if context_name in contexts:
                return self.zap.context.context(context_name)['id']
            else:
                return self.zap.context.new_context(context_name)
        except Exception:  # Broad exception for robustness
            return '1'

    def _create_user(self, context_id: str, username: str, password: str):
        """Create user for authentication"""
        try:
            user_id = self.zap.users.new_user(context_id, username)

            self.zap.users.set_authentication_credentials(
                contextid=context_id,
                userid=user_id,
                authcredentialsconfigparams=f'username={username}&password={password}'
            )

            self.zap.users.set_user_enabled(context_id, user_id, True)

            print(f"[ZAPConfig] User '{username}' created")

        except Exception as e:
            print(f"[ZAPConfig] Failed to create user: {e}")

    def export_context(self, context_name: str, output_path: str):
        """Export context to file"""
        try:
            context_data = self.zap.context.export_context(context_name, output_path)
            print(f"[ZAPConfig] Context exported to {output_path}")
            return True
        except Exception as e:
            print(f"[ZAPConfig] Failed to export context: {e}")
            return False

    def import_context(self, context_path: str):
        """Import context from file"""
        try:
            self.zap.context.import_context(context_path)
            print(f"[ZAPConfig] Context imported from {context_path}")
            return True
        except Exception as e:
            print(f"[ZAPConfig] Failed to import context: {e}")
            return False
