"""
HAR Service

Handles HAR file upload, parsing, and preprocessing.
"""
import json
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import asdict

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from modules.har_preprocessor import HARPreprocessor


class HARService:
    """Handle HAR file processing"""

    def __init__(self, upload_dir: str = "/tmp/harzap"):
        self.upload_dir = Path(upload_dir)
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.current_har: Optional[Dict] = None
        self.preprocessed: Optional[Dict] = None

    def load_har(self, content: bytes) -> Dict:
        """Load HAR from uploaded content"""
        self.current_har = json.loads(content.decode('utf-8'))
        return self.get_summary()

    def load_har_file(self, path: str) -> Dict:
        """Load HAR from file path"""
        with open(path, 'r') as f:
            self.current_har = json.load(f)
        return self.get_summary()

    def get_summary(self) -> Dict:
        """Get summary of loaded HAR"""
        if not self.current_har:
            return {'loaded': False}

        entries = self.current_har.get('log', {}).get('entries', [])
        urls = set()
        methods = {}
        domains = set()

        for entry in entries:
            req = entry.get('request', {})
            url = req.get('url', '')
            method = req.get('method', 'GET')

            urls.add(url)
            methods[method] = methods.get(method, 0) + 1

            try:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc
                if domain:
                    domains.add(domain)
            except Exception:
                pass

        return {
            'loaded': True,
            'entries': len(entries),
            'unique_urls': len(urls),
            'methods': methods,
            'domains': list(domains)
        }

    def preprocess(self, filters: Dict = None) -> Dict:
        """Preprocess HAR with optional filters"""
        if not self.current_har:
            return {'error': 'No HAR loaded'}

        preprocessor = HARPreprocessor(har_data=self.current_har)

        if filters:
            preprocessor.set_filters(**filters)

        result = preprocessor.process()
        self.preprocessed = asdict(result)

        return {
            'endpoints': len(self.preprocessed.get('endpoints', [])),
            'querystrings': sum(len(v) for v in self.preprocessed.get('querystrings', {}).values()),
            'payloads': sum(len(v) for v in self.preprocessed.get('payloads', {}).values()),
            'statistics': self.preprocessed.get('statistics', {})
        }

    def get_endpoints(self) -> List[Dict]:
        """Get preprocessed endpoints"""
        if not self.preprocessed:
            return []
        return self.preprocessed.get('endpoints', [])

    def get_urls(self) -> List[str]:
        """Get unique URLs from HAR"""
        if not self.current_har:
            return []

        urls = []
        for entry in self.current_har.get('log', {}).get('entries', []):
            url = entry.get('request', {}).get('url')
            if url and url not in urls:
                urls.append(url)
        return urls

    def get_har_data(self) -> Optional[Dict]:
        """Get raw HAR data"""
        return self.current_har
