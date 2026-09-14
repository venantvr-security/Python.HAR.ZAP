"""
Boucle IDOR adaptative — la version « sous stéroïdes » de la détection IDOR.

Pourquoi : la détection IDOR classique est en *boucle ouverte*. On génère une
liste figée de variantes (`id+1`, `id-1`, `id*10`, `1`, `999999`), on tire, et
on juge chaque réponse par un simple ratio de taille. L'attaquant n'apprend
jamais de ce qu'il observe.

Cette boucle est *fermée* : après chaque salve, les réponses réelles sont
réinjectées pour décider des identifiants suivants (`refine`) et pour trancher
« fuite de données d'autrui » vs « page d'erreur générique » (`interpret`).

Le LLM (`modules.llm.LLMClient`) pilote `refine`/`interpret` quand une clé est
configurée ; sinon un repli heuristique déterministe prend le relais, tagué
`source="offline"`, pour que la CI reste verte sans clé.
"""
import json
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..utils import get_logger

logger = get_logger("llm.adaptive_idor")

# execute_fn(url, method) -> {'status': int, 'content_length': int, 'body': str}
ExecuteFn = Callable[[str, str], Dict]

_UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)


@dataclass
class IDORObservation:
    candidate_id: str
    url: str
    status: int
    content_length: int
    body: str = ""


@dataclass
class IDORVerdict:
    is_leak: bool
    confidence: float
    reason: str
    source: str = "offline"


@dataclass
class IDORFinding:
    target_url: str
    observation: Optional[IDORObservation] = None
    verdict: Optional[IDORVerdict] = None
    rounds: int = 0
    tried: List[str] = field(default_factory=list)
    # Tous les identifiants confirmés en fuite : c'est ce vocabulaire découvert
    # que l'on réinjecte dans le PatternStore / export ZAP (mutations idor).
    leaks: List[str] = field(default_factory=list)

    @property
    def vulnerable(self) -> bool:
        return bool(self.verdict and self.verdict.is_leak)


class AdaptiveIDORLoop:
    """Énumération IDOR guidée par le feedback, bornée en budget."""

    def __init__(self, execute_fn: ExecuteFn, client=None, *,
                 max_rounds: int = 3, per_round: int = 6,
                 confidence_stop: float = 0.85, error_floor: float = 0.5):
        self.execute_fn = execute_fn
        self.client = client  # modules.llm.LLMClient ou None
        self.max_rounds = max_rounds
        self.per_round = per_round
        self.confidence_stop = confidence_stop
        # Sous ce ratio de taille (réponse test / référence), on suppose une page
        # d'erreur plutôt qu'une vraie ressource — plancher anti-faux-positif.
        self.error_floor = error_floor

    @property
    def _llm_available(self) -> bool:
        return self.client is not None

    def run(self, target: Dict, baseline: Optional[IDORObservation] = None) -> IDORFinding:
        """Boucle adaptative sur un endpoint porteur d'un identifiant.

        target = {'url', 'method', 'param'?, 'original_value'}. `param` présent =>
        identifiant en query ; absent => segment de chemin.
        """
        original = str(target.get('original_value', ''))
        method = target.get('method', 'GET')
        finding = IDORFinding(target_url=target['url'])

        if _UUID_RE.match(original):
            # UUIDv4 : énumération non pertinente (espace de 2^122). On n'y touche pas.
            logger.info("idor_skip_uuid", url=target['url'])
            finding.verdict = IDORVerdict(False, 1.0, "UUID id — enumeration skipped", "offline")
            return finding

        if baseline is None:
            baseline = self._observe(target, original, method)

        # L'identifiant original est la ressource du testeur lui-même : ne jamais
        # le rejouer ni le classer en fuite (sinon faux positif systématique).
        tried = {original}
        candidates = self._initial_candidates(original)
        best: Optional[IDORFinding] = None
        leaks: List[str] = []

        for rnd in range(1, self.max_rounds + 1):
            history: List = []
            fresh = [c for c in candidates if c not in tried][:self.per_round]
            if not fresh:
                break

            for cid in fresh:
                tried.add(cid)
                obs = self._observe(target, cid, method)
                verdict = self._interpret(obs, baseline)
                history.append((obs, verdict))
                finding.tried.append(cid)

                if verdict.is_leak:
                    leaks.append(cid)
                if verdict.is_leak and (best is None or verdict.confidence > best.verdict.confidence):
                    best = IDORFinding(target['url'], obs, verdict, rnd, list(finding.tried))
                if verdict.is_leak and verdict.confidence >= self.confidence_stop:
                    best.rounds = rnd
                    best.tried = list(finding.tried)
                    best.leaks = list(leaks)
                    logger.info("idor_confirmed", url=target['url'], round=rnd,
                                confidence=verdict.confidence, source=verdict.source)
                    return best

            candidates = self._refine(target, baseline, history, tried)

        if best is not None:
            best.tried = list(finding.tried)
            best.leaks = list(leaks)
            best.rounds = self.max_rounds
            return best
        finding.rounds = self.max_rounds
        finding.verdict = IDORVerdict(False, 0.6, "No cross-user leak observed", "offline")
        return finding

    # --- exécution ------------------------------------------------------------
    def _observe(self, target: Dict, candidate: str, method: str) -> IDORObservation:
        url = self._build_url(target, candidate)
        resp = self.execute_fn(url, method) or {}
        body = resp.get('body', '') or ''
        return IDORObservation(
            candidate_id=candidate,
            url=url,
            status=int(resp.get('status', 0)),
            content_length=int(resp.get('content_length', len(body))),
            body=body[:2000],
        )

    @staticmethod
    def _build_url(target: Dict, candidate: str) -> str:
        parsed = urlparse(target['url'])
        param = target.get('param')
        if param:
            q = parse_qs(parsed.query)
            q[param] = [candidate]
            new_query = urlencode(q, doseq=True)
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                               parsed.params, new_query, parsed.fragment))
        # Identifiant en segment de chemin : on remplace le segment exact.
        original = str(target.get('original_value', ''))
        segs = parsed.path.split('/')
        new_path = '/'.join(candidate if s == original else s for s in segs)
        return urlunparse((parsed.scheme, parsed.netloc, new_path,
                           parsed.params, parsed.query, parsed.fragment))

    # --- interpret : fuite vs erreur -----------------------------------------
    def _interpret(self, obs: IDORObservation, baseline: IDORObservation) -> IDORVerdict:
        if self._llm_available:
            verdict = self._interpret_llm(obs, baseline)
            if verdict is not None:
                return verdict
        return self._interpret_offline(obs, baseline)

    def _interpret_offline(self, obs: IDORObservation, baseline: IDORObservation) -> IDORVerdict:
        if obs.status in (401, 403):
            return IDORVerdict(False, 1.0, "Access properly denied", "offline")
        if obs.status == 404:
            return IDORVerdict(False, 0.9, "Object not found", "offline")
        if obs.status != 200:
            return IDORVerdict(False, 0.5, f"Unexpected status {obs.status}", "offline")

        ratio = obs.content_length / max(baseline.content_length, 1)
        if ratio < self.error_floor:
            return IDORVerdict(False, 0.3, "Response too small — likely error page", "offline")
        # 200 + taille crédible + identifiant différent = fuite cross-user probable.
        confidence = min(ratio, 1.0)
        if obs.body and baseline.body and obs.body == baseline.body:
            # Corps identique à la référence : probablement pas la ressource d'autrui.
            confidence *= 0.5
        return IDORVerdict(confidence >= 0.5, round(confidence, 2),
                           "200 with credible cross-user body", "offline")

    def _interpret_llm(self, obs: IDORObservation, baseline: IDORObservation) -> Optional[IDORVerdict]:
        from .prompts import get_prompt
        prompt = get_prompt('idor_interpret').render_user(
            baseline_id=baseline.candidate_id, baseline_status=baseline.status,
            baseline_len=baseline.content_length, baseline_body=repr(baseline.body[:600]),
            test_id=obs.candidate_id, test_status=obs.status,
            test_len=obs.content_length, test_body=repr(obs.body[:600]))
        data = self._ask_json(prompt)
        if isinstance(data, dict) and 'is_leak' in data:
            return IDORVerdict(bool(data['is_leak']),
                               float(data.get('confidence', 0.5)),
                               str(data.get('reason', '')), "llm")
        return None

    # --- refine : prochains identifiants -------------------------------------
    def _refine(self, target: Dict, baseline: IDORObservation,
                history: List, tried: set) -> List[str]:
        if self._llm_available:
            nxt = self._refine_llm(target, history, tried)
            if nxt:
                return nxt
        return self._refine_offline(history, tried)

    def _refine_offline(self, history: List, tried: set) -> List[str]:
        # Densifier autour des identifiants numériques qui ont renvoyé 200 :
        # un voisin qui fuit signale souvent une plage de ressources énumérable.
        hot = [int(o.candidate_id) for o, v in history
               if o.candidate_id.lstrip('-').isdigit() and o.status == 200]
        out: List[str] = []
        for n in hot:
            out += [str(n + d) for d in (1, -1, 2, -2, 5, 10)]
        if not out:  # aucun signal : élargir grossièrement
            nums = [int(o.candidate_id) for o, _ in history if o.candidate_id.lstrip('-').isdigit()]
            base = max(nums) if nums else 100
            out = [str(base + d) for d in (100, 1000, 10000)]
        seen, uniq = set(), []
        for c in out:
            if c not in tried and c not in seen:
                seen.add(c)
                uniq.append(c)
        return uniq

    def _refine_llm(self, target: Dict, history: List, tried: set) -> List[str]:
        summary = [{'id': o.candidate_id, 'status': o.status, 'len': o.content_length,
                    'leak': v.is_leak} for o, v in history]
        from .prompts import get_prompt
        prompt = get_prompt('idor_refine').render_user(
            url=target.get('url'), original_id=target.get('original_value'),
            results=json.dumps(summary))
        data = self._ask_json(prompt)
        if isinstance(data, list):
            return [str(x) for x in data if str(x) not in tried][:self.per_round]
        return []

    # --- utilitaire LLM -------------------------------------------------------
    def _ask_json(self, prompt: str):
        from .prompts.historical import SYS_SEC_REQUESTED
        try:
            resp = self.client.complete(prompt, system=SYS_SEC_REQUESTED)
            return _extract_json(getattr(resp, 'content', None))
        except Exception as e:
            logger.warning("adaptive_idor_llm_failed", error=str(e))
            return None

    @staticmethod
    def _initial_candidates(original: str) -> List[str]:
        if original.lstrip('-').isdigit():
            n = int(original)
            return [str(n + 1), str(n - 1), str(n + 2), '1', '0', str(n * 10), '999999']
        # Identifiant non numérique non-UUID : quelques mutations génériques.
        return [original + '1', '1', 'admin', '0']


def _extract_json(raw: Optional[str]):
    """Extraction JSON tolérante depuis une réponse LLM (peut être en ```json)."""
    if not raw:
        return None
    raw = raw.strip()
    if raw.startswith('```'):
        raw = raw.split('```', 2)[1]
        if raw.startswith('json'):
            raw = raw[4:]
        raw = raw.strip('`').strip()
    try:
        return json.loads(raw)
    except ValueError:
        for opener, closer in (('{', '}'), ('[', ']')):
            start, end = raw.find(opener), raw.rfind(closer)
            if start != -1 and end > start:
                try:
                    return json.loads(raw[start:end + 1])
                except ValueError:
                    continue
    return None


def client_from_config(config: Optional[Dict]):
    """Construit un LLMClient depuis la config, ou None si aucune clé n'est
    configurée (la boucle bascule alors en heuristique offline).

    Applique aussi le record/replay des interactions LLM si activé par
    l'environnement (voir modules.llm.replay), pour rejouer une séquence sans IA.
    """
    from .replay import wrap_for_replay
    import os
    inner = None
    try:
        from .client import LLMClient
        inner = LLMClient.from_config(config or {})
    except Exception as e:
        logger.info("adaptive_idor_client_unavailable", reason=str(e))
        inner = None
    # En mode replay, aucune clé n'est requise (servi depuis le transcript).
    if os.environ.get('HARZAP_LLM_REPLAY_MODE', '').lower() == 'replay':
        return wrap_for_replay(inner, config)
    return wrap_for_replay(inner, config) if inner is not None else None
