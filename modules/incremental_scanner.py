"""
Incremental Scanner - Cache-based delta scanning for efficiency.
"""
import sqlite3
import hashlib
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any

from .utils import get_logger

logger = get_logger("incremental")

DB_SCHEMA = '''
CREATE TABLE IF NOT EXISTS scan_cache (
    request_hash TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    method TEXT NOT NULL,
    body_hash TEXT,
    scanned_at TEXT NOT NULL,
    alerts_count INTEGER DEFAULT 0,
    alerts_json TEXT,
    scan_duration_ms INTEGER
);

CREATE TABLE IF NOT EXISTS scan_sessions (
    session_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    har_file TEXT,
    total_requests INTEGER DEFAULT 0,
    new_requests INTEGER DEFAULT 0,
    cached_requests INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_url ON scan_cache(url);
CREATE INDEX IF NOT EXISTS idx_scanned_at ON scan_cache(scanned_at);
'''


class IncrementalScanner:
    """Cache-based incremental scanning to skip already-scanned requests."""

    def __init__(self, db_path: str = '.harzap_cache.db', config: Optional[Dict] = None):
        self.db_path = Path(db_path)
        self.config = config or {}
        self.conn: Optional[sqlite3.Connection] = None
        self.session_id: Optional[str] = None

        self._init_db()

    def _init_db(self):
        """Initialize the SQLite database."""
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(DB_SCHEMA)
        self.conn.commit()
        logger.debug("cache_db_initialized", path=str(self.db_path))

    def start_session(self, har_file: Optional[str] = None) -> str:
        """Start a new scan session."""
        self.session_id = hashlib.sha256(
            f"{datetime.utcnow().isoformat()}{har_file}".encode()
        ).hexdigest()[:16]

        self.conn.execute(
            '''INSERT INTO scan_sessions (session_id, started_at, har_file)
               VALUES (?, ?, ?)''',
            (self.session_id, datetime.utcnow().isoformat(), har_file)
        )
        self.conn.commit()

        logger.info("scan_session_started", session_id=self.session_id)
        return self.session_id

    def end_session(self, stats: Optional[Dict] = None):
        """End the current scan session."""
        if not self.session_id:
            return

        self.conn.execute(
            '''UPDATE scan_sessions SET completed_at = ?, total_requests = ?,
               new_requests = ?, cached_requests = ? WHERE session_id = ?''',
            (
                datetime.utcnow().isoformat(),
                stats.get('total', 0) if stats else 0,
                stats.get('new', 0) if stats else 0,
                stats.get('cached', 0) if stats else 0,
                self.session_id
            )
        )
        self.conn.commit()

        logger.info("scan_session_ended", session_id=self.session_id, stats=stats)

    @staticmethod
    def hash_request(url: str, method: str, body: Optional[str] = None) -> str:
        """Generate unique hash for a request."""
        # Normalize URL (remove query params order variance)
        content = f"{method.upper()}:{url}:{body or ''}"
        return hashlib.sha256(content.encode()).hexdigest()[:32]

    @staticmethod
    def hash_body(body: Optional[str]) -> Optional[str]:
        """Hash request body for comparison."""
        if not body:
            return None
        return hashlib.sha256(body.encode()).hexdigest()[:16]

    def is_cached(self, request_hash: str) -> bool:
        """Check if request was previously scanned."""
        cursor = self.conn.execute(
            'SELECT 1 FROM scan_cache WHERE request_hash = ?',
            (request_hash,)
        )
        return cursor.fetchone() is not None

    def get_cached_result(self, request_hash: str) -> Optional[Dict]:
        """Get cached scan result for a request."""
        cursor = self.conn.execute(
            '''SELECT url, method, alerts_count, alerts_json, scanned_at
               FROM scan_cache WHERE request_hash = ?''',
            (request_hash,)
        )
        row = cursor.fetchone()

        if row:
            return {
                'url': row['url'],
                'method': row['method'],
                'alerts_count': row['alerts_count'],
                'alerts': json.loads(row['alerts_json']) if row['alerts_json'] else [],
                'scanned_at': row['scanned_at'],
                'cached': True
            }
        return None

    def update_cache(
        self,
        request_hash: str,
        url: str,
        method: str,
        body: Optional[str],
        alerts: List[Dict],
        duration_ms: int = 0
    ):
        """Update cache with scan results."""
        self.conn.execute(
            '''INSERT OR REPLACE INTO scan_cache
               (request_hash, url, method, body_hash, scanned_at, alerts_count, alerts_json, scan_duration_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
            (
                request_hash,
                url,
                method,
                self.hash_body(body),
                datetime.utcnow().isoformat(),
                len(alerts),
                json.dumps(alerts) if alerts else None,
                duration_ms
            )
        )
        self.conn.commit()

    def get_delta_requests(self, har_data: Dict) -> Dict[str, List[Dict]]:
        """Return requests categorized as new or cached."""
        result = {
            'new': [],
            'cached': [],
            'stats': {
                'total': 0,
                'new': 0,
                'cached': 0
            }
        }

        entries = har_data.get('entries', [])
        result['stats']['total'] = len(entries)

        for entry in entries:
            request = entry.get('request', {})
            url = request.get('url', '')
            method = request.get('method', 'GET')
            body = request.get('postData', {}).get('text')

            request_hash = self.hash_request(url, method, body)

            if self.is_cached(request_hash):
                cached_result = self.get_cached_result(request_hash)
                result['cached'].append({
                    'url': url,
                    'method': method,
                    'hash': request_hash,
                    'cached_result': cached_result
                })
                result['stats']['cached'] += 1
            else:
                result['new'].append({
                    'url': url,
                    'method': method,
                    'body': body,
                    'hash': request_hash,
                    'entry': entry
                })
                result['stats']['new'] += 1

        logger.info(
            "delta_analysis",
            total=result['stats']['total'],
            new=result['stats']['new'],
            cached=result['stats']['cached']
        )

        return result

    def clear_cache(self, older_than_days: Optional[int] = None):
        """Clear scan cache, optionally only entries older than N days."""
        if older_than_days:
            from datetime import timedelta
            cutoff = (datetime.utcnow() - timedelta(days=older_than_days)).isoformat()
            cursor = self.conn.execute(
                'DELETE FROM scan_cache WHERE scanned_at < ?',
                (cutoff,)
            )
        else:
            cursor = self.conn.execute('DELETE FROM scan_cache')

        self.conn.commit()
        logger.info("cache_cleared", deleted=cursor.rowcount)

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        stats = {}

        # Total entries
        cursor = self.conn.execute('SELECT COUNT(*) FROM scan_cache')
        stats['total_entries'] = cursor.fetchone()[0]

        # Unique URLs
        cursor = self.conn.execute('SELECT COUNT(DISTINCT url) FROM scan_cache')
        stats['unique_urls'] = cursor.fetchone()[0]

        # Total alerts cached
        cursor = self.conn.execute('SELECT SUM(alerts_count) FROM scan_cache')
        stats['total_alerts'] = cursor.fetchone()[0] or 0

        # DB size
        stats['db_size_bytes'] = self.db_path.stat().st_size if self.db_path.exists() else 0

        # Recent sessions
        cursor = self.conn.execute(
            '''SELECT session_id, started_at, total_requests, new_requests
               FROM scan_sessions ORDER BY started_at DESC LIMIT 5'''
        )
        stats['recent_sessions'] = [dict(row) for row in cursor.fetchall()]

        return stats

    def export_cache(self, output_path: str) -> int:
        """Export cache to JSON file."""
        cursor = self.conn.execute(
            'SELECT url, method, alerts_count, alerts_json, scanned_at FROM scan_cache'
        )

        entries = []
        for row in cursor:
            entries.append({
                'url': row['url'],
                'method': row['method'],
                'alerts_count': row['alerts_count'],
                'alerts': json.loads(row['alerts_json']) if row['alerts_json'] else [],
                'scanned_at': row['scanned_at']
            })

        with open(output_path, 'w') as f:
            json.dump(entries, f, indent=2)

        logger.info("cache_exported", path=output_path, entries=len(entries))
        return len(entries)

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
