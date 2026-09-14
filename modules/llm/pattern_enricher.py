"""
Pont d'enrichissement des patterns payloads.

C'est ici que la boucle adaptative « ne jette pas ce qu'elle apprend » : les
payloads efficaces découverts à l'exécution (identifiants IDOR qui fuient, champs
d'affectation de masse acceptés) sont réinjectés dans le `PatternStore` — donc
persistés par session ET exportés vers `zap_export/fuzzers/` monté dans ZAP. Les
runs suivants, et ZAP lui-même, réutilisent ce vocabulaire au lieu de repartir de
zéro.

Dégradation gracieuse : sans PatternStore disponible, chaque méthode est un no-op
(retourne 0), pour ne jamais faire échouer un scan à cause de la persistance.
"""
from typing import Dict, List, Optional

from ..utils import get_logger

logger = get_logger("llm.pattern_enricher")


class PatternEnricher:
    """Enregistre les payloads efficaces dans le PatternStore + export ZAP."""

    def __init__(self, store=None, session_id: Optional[str] = None):
        self.store = store
        self.session_id = session_id

    @classmethod
    def for_run(cls, domain: str, har_hash: str = "", base_path: str = "./patterns") -> "PatternEnricher":
        """Construit un enricher avec sa propre session PatternStore.

        Si le PatternStore n'est pas disponible, retourne un enricher inerte
        (no-op) plutôt que d'échouer.
        """
        try:
            from .pattern_store import PatternStore
            store = PatternStore(base_path=base_path)
            session = store.create_session(domain=domain or "unknown", har_hash=har_hash)
            return cls(store=store, session_id=session.session_id)
        except Exception as e:
            logger.info("pattern_enricher_inactive", reason=str(e))
            return cls(store=None, session_id=None)

    @property
    def active(self) -> bool:
        return self.store is not None and self.session_id is not None

    def record_idor(self, findings: List) -> int:
        """Réinjecte les identifiants qui fuient comme mutations IDOR.

        Le wordlist ZAP pour `idor` consomme le champ `mutations`.
        """
        if not self.active:
            return 0
        patterns = []
        for f in findings:
            leaks = getattr(f, 'leaks', None) or ([] if not getattr(f, 'vulnerable', False)
                                                  else [getattr(f.observation, 'candidate_id', '')])
            leaks = [str(x) for x in leaks if str(x)]
            if leaks:
                patterns.append({
                    'pattern': getattr(f, 'target_url', ''),
                    'id_type': 'numeric',
                    'strategy': 'enumerate',
                    'mutations': leaks,
                })
        return self._add('idor', patterns)

    def record_mass_assignment(self, findings: List) -> int:
        """Réinjecte les champs acceptés comme payloads `field=value`."""
        if not self.active:
            return 0
        patterns = []
        for f in findings:
            for entry in getattr(f, 'accepted_fields', []) or []:
                patterns.append({
                    'field': entry.get('field'),
                    'value': entry.get('value'),
                    'reason': entry.get('reason', ''),
                })
        return self._add('mass_assignment', patterns)

    def record_hidden_params(self, findings: List) -> int:
        """Réinjecte les paramètres cachés actifs comme payloads `name=value`."""
        if not self.active:
            return 0
        patterns = []
        for f in findings:
            for entry in getattr(f, 'active_params', []) or []:
                patterns.append({
                    'name': entry.get('name'),
                    'values': [entry.get('value')],
                    'reason': entry.get('reason', ''),
                })
        return self._add('hidden_params', patterns)

    def record_payloads(self, pattern_type: str, payloads: List[str]) -> int:
        """Réinjecte des charges PROUVÉES efficaces (SSRF, path traversal, SSTI,
        XSS, open redirect) comme wordlist de fuzzer. Une ligne = une charge.

        C'est le pendant « sondes actives » de record_idor/mass_assignment : ce que
        les nouveaux moteurs confirment ne se perd pas, ZAP le rejoue."""
        if not self.active:
            return 0
        seen, patterns = set(), []
        for p in payloads:
            p = str(p or '')
            if p and p not in seen:
                seen.add(p)
                patterns.append({'payload': p})
        return self._add(pattern_type, patterns)

    def flush(self) -> Dict[str, str]:
        """Persiste la session et pousse les wordlists vers l'export ZAP."""
        if not self.active:
            return {}
        try:
            self.store.persist_session(self.session_id)
            exported = self.store.push_to_zap_export(self.session_id)
            logger.info("pattern_enricher_flushed", session_id=self.session_id,
                        exported=list(exported.keys()))
            return exported
        except Exception as e:
            logger.warning("pattern_enricher_flush_failed", error=str(e))
            return {}

    def _add(self, pattern_type: str, patterns: List[Dict]) -> int:
        if not patterns:
            return 0
        try:
            return self.store.add_patterns(self.session_id, pattern_type, patterns, merge=True)
        except Exception as e:
            logger.warning("pattern_enricher_add_failed", pattern_type=pattern_type, error=str(e))
            return 0
