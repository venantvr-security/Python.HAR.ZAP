"""
LLM Pattern Store - Session-based persistence for enriched patterns.
GET/ADD/PERSIST/PUSH patterns with full traceability.
"""
import os
import json
import shutil
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any

from modules.utils import get_logger

logger = get_logger("llm.pattern_store")


@dataclass
class PatternSession:
    """A session containing enriched patterns."""
    session_id: str
    created_at: str
    domain: str
    confidence: float
    har_hash: str
    patterns: Dict[str, List[Any]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> 'PatternSession':
        return cls(**data)


class PatternStore:
    """
    Session-based pattern storage with full persistence.

    Layout (see docs for Mermaid diagram):
      patterns/sessions/<timestamp_name>/  one session per run
        session.json                        session metadata
        <pattern_type>.json                 structured patterns per type
        <pattern_type>.txt                  ZAP-compatible wordlist
      patterns/current                      symlink to latest session
      patterns/merged/                      patterns merged across sessions
      patterns/zap_export/fuzzers/          ready for ZAP container mount
      patterns/zap_export/custom_payloads/
    """

    PATTERN_TYPES = [
        'mass_assignment',
        'hidden_params',
        'idor',
        'regex_patterns',
        'race_conditions',
        'business_logic',
        'prioritized_endpoints'
    ]

    def __init__(self, base_path: str = './patterns'):
        self.base_path = Path(base_path)
        self.sessions_path = self.base_path / 'sessions'
        self.merged_path = self.base_path / 'merged'
        self.zap_export_path = self.base_path / 'zap_export'
        self._ensure_directories()

    def _ensure_directories(self):
        """Create directory structure."""
        self.sessions_path.mkdir(parents=True, exist_ok=True)
        self.merged_path.mkdir(parents=True, exist_ok=True)
        (self.zap_export_path / 'fuzzers').mkdir(parents=True, exist_ok=True)
        (self.zap_export_path / 'custom_payloads').mkdir(parents=True, exist_ok=True)

    # =========================================================================
    # SESSION MANAGEMENT
    # =========================================================================

    def create_session(self, domain: str, har_hash: str, confidence: float = 0.0) -> PatternSession:
        """Create a new session for storing patterns."""
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        safe_domain = domain.replace(' ', '_').replace('/', '_')[:20]
        session_id = f"{timestamp}_{safe_domain}"

        session = PatternSession(
            session_id=session_id,
            created_at=datetime.now().isoformat(),
            domain=domain,
            confidence=confidence,
            har_hash=har_hash,
            patterns={pt: [] for pt in self.PATTERN_TYPES},
            metadata={}
        )

        # Create session directory
        session_dir = self.sessions_path / session_id
        session_dir.mkdir(parents=True, exist_ok=True)

        # Save session metadata
        self._save_session_metadata(session)

        # Update current symlink
        self._update_current_link(session_id)

        logger.info("session_created", session_id=session_id, domain=domain)
        return session

    def _save_session_metadata(self, session: PatternSession):
        """Save session metadata to file."""
        session_dir = self.sessions_path / session.session_id
        with open(session_dir / 'session.json', 'w') as f:
            json.dump(session.to_dict(), f, indent=2, default=str)

    def _update_current_link(self, session_id: str):
        """Update 'current' symlink to latest session."""
        current_link = self.base_path / 'current'
        if current_link.is_symlink():
            current_link.unlink()
        elif current_link.exists():
            shutil.rmtree(current_link)
        current_link.symlink_to(f"sessions/{session_id}")

    def list_sessions(self) -> List[Dict]:
        """List all sessions with metadata."""
        sessions = []
        for session_dir in sorted(self.sessions_path.iterdir(), reverse=True):
            if session_dir.is_dir():
                meta_file = session_dir / 'session.json'
                if meta_file.exists():
                    with open(meta_file) as f:
                        sessions.append(json.load(f))
        return sessions

    def get_session(self, session_id: str) -> Optional[PatternSession]:
        """Load a session by ID."""
        session_dir = self.sessions_path / session_id
        meta_file = session_dir / 'session.json'
        if not meta_file.exists():
            return None
        with open(meta_file) as f:
            return PatternSession.from_dict(json.load(f))

    def get_current_session(self) -> Optional[PatternSession]:
        """Get the current (latest) session."""
        current_link = self.base_path / 'current'
        if not current_link.exists():
            return None
        session_id = current_link.resolve().name
        return self.get_session(session_id)

    # =========================================================================
    # PATTERN OPERATIONS: GET / ADD / PERSIST
    # =========================================================================

    def get_patterns(self, session_id: str, pattern_type: str) -> List[Any]:
        """GET patterns from a session."""
        session_dir = self.sessions_path / session_id
        json_file = session_dir / f'{pattern_type}.json'

        if not json_file.exists():
            return []

        with open(json_file) as f:
            return json.load(f)

    def add_patterns(
        self,
        session_id: str,
        pattern_type: str,
        patterns: List[Any],
        merge: bool = True
    ) -> int:
        """ADD patterns to a session. Returns count added."""
        if pattern_type not in self.PATTERN_TYPES:
            raise ValueError(f"Unknown pattern type: {pattern_type}")

        session_dir = self.sessions_path / session_id
        if not session_dir.exists():
            raise ValueError(f"Session not found: {session_id}")

        # Load existing patterns
        existing = self.get_patterns(session_id, pattern_type) if merge else []

        # Merge (deduplicate)
        if merge:
            existing_set = {json.dumps(p, sort_keys=True) for p in existing}
            new_patterns = [
                p for p in patterns
                if json.dumps(p, sort_keys=True) not in existing_set
            ]
            all_patterns = existing + new_patterns
            added_count = len(new_patterns)
        else:
            all_patterns = patterns
            added_count = len(patterns)

        # Save JSON
        json_file = session_dir / f'{pattern_type}.json'
        with open(json_file, 'w') as f:
            json.dump(all_patterns, f, indent=2, default=str)

        # Save TXT wordlist
        self._save_wordlist(session_dir, pattern_type, all_patterns)

        # Update session metadata
        session = self.get_session(session_id)
        if session:
            session.patterns[pattern_type] = all_patterns
            session.metadata[f'{pattern_type}_count'] = len(all_patterns)
            session.metadata['last_updated'] = datetime.now().isoformat()
            self._save_session_metadata(session)

        logger.info(
            "patterns_added",
            session_id=session_id,
            pattern_type=pattern_type,
            added=added_count,
            total=len(all_patterns)
        )

        return added_count

    def _save_wordlist(self, session_dir: Path, pattern_type: str, patterns: List[Any]):
        """Save patterns as TXT wordlist for ZAP fuzzer."""
        txt_file = session_dir / f'{pattern_type}.txt'
        lines = []

        for p in patterns:
            if isinstance(p, dict):
                # Different formats based on pattern type
                if pattern_type == 'mass_assignment':
                    field = p.get('field', '')
                    value = p.get('value', '')
                    if field:
                        lines.append(f"{field}={value}")
                elif pattern_type == 'hidden_params':
                    name = p.get('name', p.get('key', ''))
                    values = p.get('values', p.get('test_values', []))
                    for v in values:
                        lines.append(f"{name}={v}")
                elif pattern_type == 'idor':
                    mutations = p.get('mutations', [])
                    lines.extend(mutations)
                else:
                    # Generic: use string representation
                    lines.append(json.dumps(p))
            elif isinstance(p, str):
                lines.append(p)

        with open(txt_file, 'w') as f:
            f.write('\n'.join(lines))

    def persist_session(self, session_id: str) -> Dict[str, str]:
        """PERSIST - Ensure all patterns are saved and return file paths."""
        session_dir = self.sessions_path / session_id
        if not session_dir.exists():
            raise ValueError(f"Session not found: {session_id}")

        files = {}
        for pattern_type in self.PATTERN_TYPES:
            json_file = session_dir / f'{pattern_type}.json'
            txt_file = session_dir / f'{pattern_type}.txt'

            if json_file.exists():
                files[f'{pattern_type}_json'] = str(json_file)
            if txt_file.exists():
                files[f'{pattern_type}_txt'] = str(txt_file)

        files['session_metadata'] = str(session_dir / 'session.json')

        logger.info("session_persisted", session_id=session_id, files=list(files.keys()))
        return files

    # =========================================================================
    # PUSH TO ZAP
    # =========================================================================

    def push_to_zap_export(self, session_id: str) -> Dict[str, str]:
        """PUSH patterns to ZAP export directory for container mounting."""
        session_dir = self.sessions_path / session_id
        if not session_dir.exists():
            raise ValueError(f"Session not found: {session_id}")

        exported = {}

        # Copy TXT files to fuzzers directory
        for pattern_type in ['mass_assignment', 'hidden_params', 'idor']:
            txt_file = session_dir / f'{pattern_type}.txt'
            if txt_file.exists():
                dest = self.zap_export_path / 'fuzzers' / f'llm_{pattern_type}.txt'
                shutil.copy(txt_file, dest)
                exported[pattern_type] = str(dest)

        # Copy regex patterns for custom payloads
        regex_file = session_dir / 'regex_patterns.json'
        if regex_file.exists():
            dest = self.zap_export_path / 'custom_payloads' / 'llm_regex.json'
            shutil.copy(regex_file, dest)
            exported['regex'] = str(dest)

        logger.info("pushed_to_zap", session_id=session_id, exported=list(exported.keys()))
        return exported

    def get_zap_mount_paths(self) -> Dict[str, str]:
        """Get paths for Docker volume mounting."""
        return {
            'fuzzers': str(self.zap_export_path / 'fuzzers'),
            'custom_payloads': str(self.zap_export_path / 'custom_payloads'),
            'docker_mount': f"-v {self.zap_export_path}/fuzzers:/home/zap/.ZAP/fuzzers/llm:ro"
        }

    # =========================================================================
    # PULL FROM ZAP - Import existing patterns
    # =========================================================================

    def pull_from_zap(self, zap_fuzzers_path: str = '/home/zap/.ZAP/fuzzers') -> Dict[str, int]:
        """
        PULL - Import existing patterns from ZAP container fuzzers directory.
        Copies to local import directory for merging.
        """
        import_path = self.base_path / 'zap_import'
        import_path.mkdir(parents=True, exist_ok=True)

        imported = {}
        zap_path = Path(zap_fuzzers_path)

        if not zap_path.exists():
            logger.warning("zap_fuzzers_not_found", path=zap_fuzzers_path)
            return imported

        for txt_file in zap_path.glob('**/*.txt'):
            dest = import_path / txt_file.name
            shutil.copy(txt_file, dest)

            # Count lines
            with open(dest) as f:
                count = sum(1 for _ in f)
            imported[txt_file.stem] = count

        logger.info("pulled_from_zap", imported=imported)
        return imported

    def get_zap_imports(self) -> Dict[str, List[str]]:
        """Get all imported ZAP patterns."""
        import_path = self.base_path / 'zap_import'
        patterns = {}

        if not import_path.exists():
            return patterns

        for txt_file in import_path.glob('*.txt'):
            with open(txt_file) as f:
                patterns[txt_file.stem] = [line.strip() for line in f if line.strip()]

        return patterns

    # =========================================================================
    # CUMULATIVE PATTERNS - Never lose data
    # =========================================================================

    def get_cumulative_patterns(self, pattern_type: str) -> List[Any]:
        """
        Get ALL patterns of a type across ALL sessions.
        This ensures we never lose enriched patterns.
        """
        all_patterns = []
        seen = set()

        # From all sessions
        for session_info in self.list_sessions():
            patterns = self.get_patterns(session_info['session_id'], pattern_type)
            for p in patterns:
                key = json.dumps(p, sort_keys=True) if isinstance(p, dict) else str(p)
                if key not in seen:
                    seen.add(key)
                    all_patterns.append(p)

        # From merged
        merged_file = self.merged_path / f'all_{pattern_type}.json'
        if merged_file.exists():
            with open(merged_file) as f:
                for p in json.load(f):
                    key = json.dumps(p, sort_keys=True) if isinstance(p, dict) else str(p)
                    if key not in seen:
                        seen.add(key)
                        all_patterns.append(p)

        return all_patterns

    def backup_session(self, session_id: str) -> str:
        """Create a timestamped backup of a session."""
        session_dir = self.sessions_path / session_id
        if not session_dir.exists():
            raise ValueError(f"Session not found: {session_id}")

        backup_dir = self.base_path / 'backups'
        backup_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = backup_dir / f"{session_id}_{timestamp}"
        shutil.copytree(session_dir, backup_path)

        logger.info("session_backed_up", session_id=session_id, backup=str(backup_path))
        return str(backup_path)

    # =========================================================================
    # MERGE SESSIONS
    # =========================================================================

    def merge_all_sessions(self) -> Dict[str, int]:
        """Merge patterns from all sessions into merged directory."""
        merged_patterns = {pt: [] for pt in self.PATTERN_TYPES}
        seen = {pt: set() for pt in self.PATTERN_TYPES}

        for session_info in self.list_sessions():
            session_id = session_info['session_id']
            for pattern_type in self.PATTERN_TYPES:
                patterns = self.get_patterns(session_id, pattern_type)
                for p in patterns:
                    key = json.dumps(p, sort_keys=True)
                    if key not in seen[pattern_type]:
                        seen[pattern_type].add(key)
                        merged_patterns[pattern_type].append(p)

        # Save merged patterns
        counts = {}
        for pattern_type, patterns in merged_patterns.items():
            if patterns:
                json_file = self.merged_path / f'all_{pattern_type}.json'
                with open(json_file, 'w') as f:
                    json.dump(patterns, f, indent=2, default=str)

                # Also save as TXT
                self._save_wordlist(self.merged_path, f'all_{pattern_type}', patterns)
                counts[pattern_type] = len(patterns)

        logger.info("sessions_merged", counts=counts)
        return counts

    # =========================================================================
    # INTEGRATION WITH LLMZAPEnricher
    # =========================================================================

    def store_from_enrichment(self, enrichment: 'DomainEnrichment', har_hash: str) -> str:
        """
        Store all patterns from a DomainEnrichment result.
        Scope = session (isolated). Each session contains its own patterns.
        """
        # Create session
        session = self.create_session(
            domain=enrichment.domain,
            har_hash=har_hash,
            confidence=enrichment.confidence
        )

        # Add patterns (session-scoped)
        if enrichment.mass_assignment_payloads:
            self.add_patterns(session.session_id, 'mass_assignment', enrichment.mass_assignment_payloads)

        if enrichment.hidden_params:
            hidden_list = [
                {'name': k, 'values': v}
                for k, v in enrichment.hidden_params.items()
            ]
            self.add_patterns(session.session_id, 'hidden_params', hidden_list)

        if enrichment.idor_strategies:
            self.add_patterns(session.session_id, 'idor', enrichment.idor_strategies)

        if enrichment.custom_regex:
            self.add_patterns(session.session_id, 'regex_patterns', enrichment.custom_regex)

        if enrichment.race_windows:
            self.add_patterns(session.session_id, 'race_conditions', enrichment.race_windows)

        if enrichment.business_logic_tests:
            self.add_patterns(session.session_id, 'business_logic', enrichment.business_logic_tests)

        if enrichment.prioritized_endpoints:
            self.add_patterns(session.session_id, 'prioritized_endpoints', enrichment.prioritized_endpoints)

        # Persist & push this session to ZAP
        self.persist_session(session.session_id)
        self.push_to_zap_export(session.session_id)

        logger.info(
            "enrichment_stored",
            session_id=session.session_id,
            domain=enrichment.domain
        )

        return session.session_id


def create_store(base_path: str = './patterns') -> PatternStore:
    """Factory function for PatternStore."""
    return PatternStore(base_path)
