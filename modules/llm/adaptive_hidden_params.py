"""
Boucle Hidden Params adaptative — découvre les paramètres cachés (debug/admin)
qui modifient le comportement du serveur, dans le même moule adaptatif que les
boucles IDOR et Mass Assignment.

Principe : on ajoute un paramètre suspect (`?debug=true`, `?admin=1`…), on compare
la réponse à la référence (requête sans le paramètre), et un écart significatif
(taille, apparition de contenu de debug) signale un paramètre actif. Un paramètre
qui « mord » ouvre la voie à ses voisins (`debug` actif => `debug_level`, `verbose`,
`trace`). Les paramètres efficaces sont réinjectés dans le PatternStore
(`hidden_params` : `name=value`, exporté en wordlist ZAP).

LLM pour interpret/refine si une clé est configurée, sinon repli heuristique
déterministe (`source="offline"`).
"""
import json
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..utils import get_logger
from .adaptive_idor import _extract_json

logger = get_logger("llm.adaptive_hidden_params")

# execute_fn(url, method) -> {'status': int, 'content_length': int, 'body': str}
ExecuteFn = Callable[[str, str], Dict]

_SEED_PARAMS = [
    ("debug", "true"), ("admin", "1"), ("test", "1"), ("show_errors", "true"),
    ("verbose", "true"), ("trace", "1"), ("internal", "1"), ("dev", "1"),
    ("debug_mode", "on"), ("_debug", "1"),
]

_ADJACENCY = {
    "debug": [("debug_level", "3"), ("verbose", "true"), ("trace", "1")],
    "admin": [("is_admin", "1"), ("superuser", "1"), ("role", "admin")],
    "test": [("testing", "1"), ("sandbox", "1")],
    "internal": [("internal_api", "1"), ("staff", "1")],
}

# Indices textuels d'une bascule debug/interne dans le corps de réponse.
_DEBUG_MARKERS = ("traceback", "stack trace", "debug", "exception", "sql", "query",
                  "warning:", "notice:", "var_dump", "dumpstack")


@dataclass
class HPObservation:
    param: str
    value: str
    url: str
    status: int
    content_length: int
    body: str = ""


@dataclass
class HPVerdict:
    active: bool
    confidence: float
    reason: str
    source: str = "offline"


@dataclass
class HPFinding:
    target_url: str
    active_params: List[Dict] = field(default_factory=list)  # [{'name','value','reason'}]
    tried: List[str] = field(default_factory=list)
    rounds: int = 0

    @property
    def vulnerable(self) -> bool:
        return bool(self.active_params)


class AdaptiveHiddenParamsLoop:
    """Découverte adaptative des paramètres cachés qui changent le comportement."""

    def __init__(self, execute_fn: ExecuteFn, client=None, *,
                 max_rounds: int = 3, per_round: int = 6, delta_ratio: float = 0.05):
        self.execute_fn = execute_fn
        self.client = client
        self.max_rounds = max_rounds
        self.per_round = per_round
        # Écart relatif de taille au-delà duquel on considère un changement de comportement.
        self.delta_ratio = delta_ratio

    @property
    def _llm_available(self) -> bool:
        return self.client is not None

    def run(self, target: Dict, baseline: Optional[HPObservation] = None) -> HPFinding:
        """target = {'url', 'method'?}. Ajoute des paramètres suspects et compare."""
        method = target.get('method', 'GET')
        finding = HPFinding(target_url=target['url'])
        if baseline is None:
            baseline = self._observe(target, '__baseline__', '', method, add=False)

        tried: set = set()
        candidates: List = list(_SEED_PARAMS)

        for rnd in range(1, self.max_rounds + 1):
            fresh = [(p, v) for (p, v) in candidates if p not in tried][:self.per_round]
            if not fresh:
                break
            active_now: List[str] = []
            for name, val in fresh:
                tried.add(name)
                finding.tried.append(name)
                obs = self._observe(target, name, val, method)
                verdict = self._interpret(obs, baseline)
                if verdict.active:
                    finding.active_params.append(
                        {'name': name, 'value': val, 'reason': verdict.reason})
                    active_now.append(name)
                    logger.info("hidden_param_active", url=target['url'],
                                param=name, source=verdict.source)
            candidates = self._refine(target, active_now, tried)
            finding.rounds = rnd

        return finding

    # --- exécution ------------------------------------------------------------
    def _observe(self, target, name, value, method, add=True) -> HPObservation:
        url = self._build_url(target['url'], name, value) if add else target['url']
        resp = self.execute_fn(url, method) or {}
        body = (resp.get('body', '') or '')
        return HPObservation(param=name, value=value, url=url,
                             status=int(resp.get('status', 0)),
                             content_length=int(resp.get('content_length', len(body))),
                             body=body[:2000])

    @staticmethod
    def _build_url(url: str, name: str, value: str) -> str:
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        q[name] = [value]
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                           parsed.params, urlencode(q, doseq=True), parsed.fragment))

    # --- interpret : paramètre actif ? ---------------------------------------
    def _interpret(self, obs: HPObservation, baseline: HPObservation) -> HPVerdict:
        if self._llm_available:
            v = self._interpret_llm(obs, baseline)
            if v is not None:
                return v
        return self._interpret_offline(obs, baseline)

    def _interpret_offline(self, obs: HPObservation, baseline: HPObservation) -> HPVerdict:
        if obs.status == 0:
            return HPVerdict(False, 0.5, "No response", "offline")
        # Marqueur de debug apparu et absent de la référence = signal fort.
        low, base_low = obs.body.lower(), baseline.body.lower()
        new_markers = [m for m in _DEBUG_MARKERS if m in low and m not in base_low]
        if new_markers:
            return HPVerdict(True, 0.9, f"Debug marker appeared: {new_markers[0]}", "offline")
        # Écart de taille significatif = comportement modifié par le paramètre.
        delta = abs(obs.content_length - baseline.content_length)
        if delta > max(baseline.content_length * self.delta_ratio, 50):
            return HPVerdict(True, 0.6, f"Response size changed by {delta} bytes", "offline")
        if obs.status != baseline.status:
            return HPVerdict(True, 0.6, f"Status changed {baseline.status}->{obs.status}", "offline")
        return HPVerdict(False, 0.7, "No behavioral change", "offline")

    def _interpret_llm(self, obs: HPObservation, baseline: HPObservation) -> Optional[HPVerdict]:
        prompt = (
            "A hidden parameter was added to a request. Decide if it changed server "
            "behavior in a security-relevant way (debug output, admin mode, extra data). "
            'Return JSON {"active": bool, "confidence": number(0-1), "reason": str}.\n'
            f"BASELINE: status={baseline.status} len={baseline.content_length} "
            f"body={baseline.body[:400]!r}\n"
            f"WITH {obs.param}={obs.value}: status={obs.status} len={obs.content_length} "
            f"body={obs.body[:400]!r}"
        )
        data = self._ask_json(prompt)
        if isinstance(data, dict) and 'active' in data:
            return HPVerdict(bool(data['active']), float(data.get('confidence', 0.5)),
                             str(data.get('reason', '')), "llm")
        return None

    # --- refine : paramètres adjacents ---------------------------------------
    def _refine(self, target: Dict, active: List[str], tried: set) -> List:
        if self._llm_available and active:
            nxt = self._refine_llm(target, active, tried)
            if nxt:
                return nxt
        out: List = []
        for name in active:
            for pair in _ADJACENCY.get(name, []):
                if pair[0] not in tried:
                    out.append(pair)
        return out

    def _refine_llm(self, target: Dict, active: List[str], tried: set) -> List:
        prompt = (
            "These hidden parameters changed server behavior. Propose adjacent debug/admin "
            'parameters likely to also be active. Return JSON as an array of '
            '{"name": str, "value": str}.\n'
            f"Endpoint: {target.get('url')}\nActive so far: {json.dumps(active)}"
        )
        data = self._ask_json(prompt)
        out: List = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and item.get('name') and item['name'] not in tried:
                    out.append((item['name'], str(item.get('value', '1'))))
        return out[:self.per_round]

    def _ask_json(self, prompt: str):
        try:
            resp = self.client.complete(
                prompt, system="You are a security engineer. Answer only with the requested JSON.")
            return _extract_json(getattr(resp, 'content', None))
        except Exception as e:
            logger.warning("adaptive_hp_llm_failed", error=str(e))
            return None
