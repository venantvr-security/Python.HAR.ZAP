"""
Trainer - Arachni-inspired dynamic element discovery

Analyzes HTTP responses during scan to discover new forms, links, cookies
that emerge from application interaction. Maintains state to avoid redundancy.

Based on: https://github.com/Arachni/arachni/blob/master/lib/arachni/trainer.rb
"""
import hashlib
from collections import defaultdict
from typing import Dict, Set
from urllib.parse import urlparse


class ElementFilter:
    """
    Track seen elements using HashSets (Arachni ElementFilter equivalent).

    Distinguishes new elements from previously seen ones during scan.
    """

    def __init__(self):
        self.links: Set[str] = set()
        self.forms: Set[str] = set()
        self.cookies: Set[str] = set()
        self.headers: Set[str] = set()
        self.json_inputs: Set[str] = set()

    # noinspection PyMethodMayBeStatic
    def _element_id(self, element: Dict) -> str:
        """Generate unique ID for element"""
        if 'url' in element and 'method' in element:
            # Form ID: method + url + sorted params
            params = sorted(element.get('inputs', {}).keys())
            return f"{element['method']}:{element['url']}:{','.join(params)}"
        elif 'url' in element:
            # Link ID: url + query params
            return element['url']
        elif 'name' in element:
            # Cookie/header ID: name + domain
            domain = element.get('domain', '')
            return f"{element['name']}@{domain}"
        else:
            return str(hash(str(element)))

    def include_link(self, link: str) -> bool:
        """Check if link already seen"""
        return link in self.links

    def include_form(self, form_id: str) -> bool:
        """Check if form already seen"""
        return form_id in self.forms

    def include_cookie(self, cookie_id: str) -> bool:
        """Check if cookie already seen"""
        return cookie_id in self.cookies

    def update_links(self, links: list) -> int:
        """Add new links, return count of new ones"""
        before = len(self.links)
        self.links.update(links)
        return len(self.links) - before

    def update_forms(self, forms: list) -> int:
        """Add new forms, return count of new ones"""
        before = len(self.forms)
        form_ids = [self._element_id(f) for f in forms]
        self.forms.update(form_ids)
        return len(self.forms) - before

    def update_cookies(self, cookies: list) -> int:
        """Add new cookies, return count of new ones"""
        before = len(self.cookies)
        cookie_ids = [self._element_id(c) for c in cookies]
        self.cookies.update(cookie_ids)
        return len(self.cookies) - before


class Trainer:
    """
    Arachni Trainer: Learn application structure during scan.

    Analyzes HTTP responses to discover new auditable elements (forms, links, cookies).
    Expands scan scope dynamically based on application behavior.
    """

    MAX_TRAININGS_PER_URL = 25

    def __init__(self, zap_client, scope_domains: list = None):
        self.zap = zap_client
        self.scope_domains = scope_domains or []
        self.element_filter = ElementFilter()

        # Track trainings per URL to avoid infinite loops
        self.trainings_per_url = defaultdict(int)

        # Cache response hashes to avoid re-analyzing identical responses
        self.response_cache: Set[str] = set()

        # Discovered pages to audit
        self.discovered_pages = []

        print("[Trainer] Initialized with ElementFilter")

    def push(self, response: Dict) -> bool:
        """
        Analyze HTTP response for new elements (Arachni push method).

        Args:
            response: Dict with keys: url, status_code, headers, body

        Returns:
            True if analysis performed, False if skipped
        """
        url = response.get('url', '')

        # Check if we should analyze this response
        if not self._should_analyze(response):
            return False

        # Limit trainings per URL
        if self.trainings_per_url[url] >= self.MAX_TRAININGS_PER_URL:
            print(f"[Trainer] Max trainings reached for {url}")
            return False

        self.trainings_per_url[url] += 1

        # Analyze and discover new elements
        discovered = self._analyze(response)

        if discovered:
            print(f"[Trainer] Discovered {discovered} new elements from {url}")

        return True

    def _should_analyze(self, response: Dict) -> bool:
        """
        Filter responses worth analyzing (Arachni analyze_response? method).

        Skip if:
        - Not in scope
        - Already analyzed (response hash collision)
        - Not HTML/JSON content
        """
        url = response.get('url', '')
        status = response.get('status_code', 0)
        content_type = response.get('content_type', '')

        # Check scope
        if self.scope_domains:
            parsed = urlparse(url)
            if not any(domain in parsed.netloc for domain in self.scope_domains):
                return False

        # Check content type
        if not any(ct in content_type.lower() for ct in ['html', 'json', 'xml', 'javascript']):
            return False

        # Check response cache (naive optimization)
        body = response.get('body', '')
        response_hash = hashlib.md5(body.encode('utf-8', errors='ignore')).hexdigest()

        if response_hash in self.response_cache:
            return False

        self.response_cache.add(response_hash)

        # Limit cache size to avoid memory issues
        if len(self.response_cache) > 10000:
            self.response_cache.clear()
            print("[Trainer] Cleared response cache")

        return True

    def _analyze(self, response: Dict) -> int:
        """
        Core learning mechanism (Arachni analyze method).

        Parses response to extract:
        - Links (href, src attributes)
        - Forms (with inputs)
        - Cookies (Set-Cookie headers)

        Returns count of new elements discovered.
        """
        url = response.get('url', '')
        body = response.get('body', '')
        headers = response.get('headers', {})

        total_new = 0

        # Extract links (simple regex - real impl would use proper HTML parser)
        import re

        links = re.findall(r'href=["\']([^"\']+)["\']', body)
        links += re.findall(r'src=["\']([^"\']+)["\']', body)

        # Convert relative URLs to absolute
        absolute_links = []
        for link in links:
            if link.startswith('http'):
                absolute_links.append(link)
            elif link.startswith('/'):
                parsed = urlparse(url)
                absolute_links.append(f"{parsed.scheme}://{parsed.netloc}{link}")

        new_links = self.element_filter.update_links(absolute_links)
        if new_links > 0:
            print(f"[Trainer]   +{new_links} new links")
            total_new += new_links

        # Extract forms (simplified - look for <form> tags)
        forms = re.findall(r'<form[^>]*action=["\']([^"\']+)["\'][^>]*>(.*?)</form>', body, re.DOTALL)
        form_data = []
        for action, form_body in forms:
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form_body)
            form_data.append({
                'url': action,
                'method': 'POST',
                'inputs': {inp: '' for inp in inputs}
            })

        new_forms = self.element_filter.update_forms(form_data)
        if new_forms > 0:
            print(f"[Trainer]   +{new_forms} new forms")
            total_new += new_forms

            # Push forms to discovered pages for audit
            for form in form_data:
                self.discovered_pages.append({
                    'type': 'form',
                    'data': form,
                    'discovered_from': url
                })

        # Extract cookies from Set-Cookie headers
        cookies = []
        for header_name, header_value in headers.items():
            if header_name.lower() == 'set-cookie':
                cookie_parts = header_value.split(';')[0].split('=')
                if len(cookie_parts) == 2:
                    cookies.append({
                        'name': cookie_parts[0],
                        'value': cookie_parts[1],
                        'domain': urlparse(url).netloc
                    })

        new_cookies = self.element_filter.update_cookies(cookies)
        if new_cookies > 0:
            print(f"[Trainer]   +{new_cookies} new cookies")
            total_new += new_cookies

        return total_new

    def get_discovered_pages(self) -> list:
        """Return list of discovered pages to audit"""
        return self.discovered_pages

    def get_stats(self) -> Dict:
        """Return training statistics"""
        return {
            'total_links': len(self.element_filter.links),
            'total_forms': len(self.element_filter.forms),
            'total_cookies': len(self.element_filter.cookies),
            'discovered_pages': len(self.discovered_pages),
            'trained_urls': len(self.trainings_per_url),
            'response_cache_size': len(self.response_cache)
        }

    def feed_from_zap_history(self, max_messages: int = 1000):
        """
        Bootstrap trainer from ZAP history (existing traffic).

        Useful for learning from HAR import or proxy traffic.
        """
        print("[Trainer] Feeding from ZAP message history...")

        try:
            messages = self.zap.core.messages(start=0, count=max_messages)

            for msg in messages:
                response = {
                    'url': msg.get('requestHeader', '').split(' ')[1] if ' ' in msg.get('requestHeader', '') else '',
                    'status_code': msg.get('responseHeader', '').split(' ')[1] if ' ' in msg.get('responseHeader', '') else '200',
                    'headers': self._parse_headers(msg.get('responseHeader', '')),
                    'body': msg.get('responseBody', ''),
                    'content_type': msg.get('responseHeader', '').split('Content-Type: ')[-1].split('\n')[0] if 'Content-Type:' in msg.get('responseHeader',
                                                                                                                                           '') else 'text/html'
                }

                self.push(response)

            stats = self.get_stats()
            print(f"[Trainer] Bootstrap complete: {stats['total_links']} links, {stats['total_forms']} forms, {stats['total_cookies']} cookies")

        except Exception as e:
            print(f"[Trainer] Error feeding from history: {e}")

    # noinspection PyMethodMayBeStatic
    def _parse_headers(self, header_string: str) -> Dict:
        """Parse HTTP header string into dict"""
        headers = {}
        for line in header_string.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        return headers
