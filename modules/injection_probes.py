"""
Sondes d'injection SQL / NoSQL — angle A03:2021 (Injection) absent jusqu'ici.

Trois signatures, du plus sûr au plus subtil :
  1. Error-based (DÉTERMINISTE) : une apostrophe fait remonter une erreur SGBD
     reconnaissable (MySQL/Postgres/SQLite/MSSQL/Oracle/Mongo) -> CONFIRMED.
  2. Time-based (DÉTERMINISTE, différentiel) : une charge `SLEEP(n)` retarde la
     réponse alors qu'un contrôle `SLEEP(0)` répond vite -> CONFIRMED. Le
     différentiel écarte les cibles lentes par nature (pas de FP au seuil fixe).
  3. Boolean-based (SUSPECTED) : TRUE vs FALSE donnent des réponses nettement
     différentes sans erreur -> signal probable, laissé en SUSPECTED (une appli
     légitime peut aussi varier selon la valeur) ; l'IA arbitre si dispo.

NoSQL : injection d'OPÉRATEUR (`{"$ne": null}`, `field[$ne]=`), erreurs Mongo, et
`$where` time-based. Même discipline : marqueur/différentiel = CONFIRMED, sinon
SUSPECTED (jamais de FP hors ligne).

Exécuteur : `execute(url, method, body=None) -> {status, body, ...}` (le même que
web_probes). On mesure le temps autour de l'appel pour le time-based.
"""
import copy
import re
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .utils import get_logger
from .web_probes import injectable_targets, _iter_string_leaves, _set_in, _get

logger = get_logger("injection.probes")

# --- marqueurs d'erreur SGBD (déterministes, très faible FP) -----------------
_SQL_ERRORS = re.compile(
    r"(you have an error in your sql syntax|warning:\s*mysqli?|unclosed quotation mark|"
    r"quoted string not properly terminated|pg_query\(\)|org\.postgresql\.util\.psqlexception|"
    r"postgresql.*error|sqlite3?::|sqlite3\.operationalerror|near \".*\": syntax error|"
    r"microsoft sql server|odbc sql server driver|native client.*error|"
    r"ora-\d{5}|oracle error|sqlstate\[|syntax error at or near|"
    r"conversion failed when converting)", re.I)
_NOSQL_ERRORS = re.compile(
    r"(mongoerror|mongoservererror|e11000|bsonerror|casterror|"
    r"\$where|unknown operator|failed to parse|couldn't parse|"
    r"unterminated string|json parse error.*mongo)", re.I)

# --- charges ----------------------------------------------------------------
_SQL_ERROR_PAYLOADS = ["'", '"', "')", "';", "'\"`"]
_SQL_BOOL_TRUE = ["' OR '1'='1", " OR 1=1-- -", "') OR ('1'='1"]
_SQL_BOOL_FALSE = ["' AND '1'='2", " AND 1=2-- -", "') AND ('1'='2"]
# time-based multi-SGBD (n=5 s). Un contrôle SLEEP(0) sert de baseline rapide.
_SQL_TIME = [
    ("' OR SLEEP(5)-- -", "' OR SLEEP(0)-- -"),
    ("'; WAITFOR DELAY '0:0:5'-- -", "'; WAITFOR DELAY '0:0:0'-- -"),
    ("' OR pg_sleep(5)-- -", "' OR pg_sleep(0)-- -"),
]
_NOSQL_OPERATORS = [{"$ne": None}, {"$gt": ""}, {"$regex": ".*"}]
_NOSQL_TIME = {"$where": "sleep(5000)"}
_NOSQL_TIME_CTRL = {"$where": "sleep(0)"}

_TIME_THRESHOLD = 4.0        # delta mini attaque-contrôle pour un SLEEP(5)
_TIME_CTRL_MAX = 2.0         # le contrôle doit rester rapide
_TIME_BUDGET = 6             # nb max de sondes time-based par run (borne le coût)


@dataclass
class InjectionFinding:
    category: str            # SQLI | NOSQLI
    severity: str
    title: str
    url: str
    detail: str = ''
    source: str = 'deterministic'
    confidence: float = 0.9
    payload: str = ''

    def flat(self) -> Dict:
        v = self.verdict
        return {'source': f'inj_{self.category.lower()}', 'risk': self.severity,
                'name': self.title, 'url': self.url, 'owasp': 'API8:2023',
                'payload': self.payload, 'status': v.status, 'adjudication': v.source}

    @property
    def verdict(self):
        from .llm.investigation import Verdict, Evidence, CONFIRMED, SUSPECTED
        status = CONFIRMED if self.source == 'deterministic' else SUSPECTED
        return Verdict(status, self.detail or self.title, self.confidence, self.source,
                       Evidence(request=self.url, note=self.detail))


# --- points d'injection (query + feuilles JSON), avec valeur d'origine -------
def _points(target: Dict):
    """(label, key, method, mutate) où mutate(value) rend (url, body) en
    REMPLAÇANT le paramètre. `value` peut être une chaîne OU un objet (NoSQL)."""
    url, method = target.get('url', ''), target.get('method', 'GET')
    parsed = urlparse(url)
    for p in parse_qs(parsed.query):
        def mutate(value, _p=p, _parsed=parsed):
            q = {k: v[:] for k, v in parse_qs(_parsed.query).items()}
            q[_p] = [value if isinstance(value, str) else str(value)]
            return urlunparse((_parsed.scheme, _parsed.netloc, _parsed.path,
                               _parsed.params, urlencode(q, doseq=True),
                               _parsed.fragment)), None
        yield f"query '{p}'", p, method, mutate
    body = target.get('body')
    if isinstance(body, (dict, list)):
        for bpath, _ in _iter_string_leaves(body):
            def mutate(value, _bp=bpath, _body=body, _url=url):
                return _url, _set_in(_body, _bp, value)
            yield "body '" + '.'.join(map(str, bpath)) + "'", str(bpath[-1]), method, mutate


def _nosql_query_points(target: Dict):
    """Injection d'opérateur en query string : `field[$ne]=x` (Express/Mongo)."""
    url, method = target.get('url', ''), target.get('method', 'GET')
    parsed = urlparse(url)
    for p in parse_qs(parsed.query):
        def mutate(op, _p=p, _parsed=parsed):
            q = {f'{k}': v[:] for k, v in parse_qs(_parsed.query).items() if k != _p}
            q[f'{_p}[{op}]'] = ['x' if op != '$regex' else '.*']
            return urlunparse((_parsed.scheme, _parsed.netloc, _parsed.path,
                               _parsed.params, urlencode(q, doseq=True),
                               _parsed.fragment)), None
        yield f"query '{p}[op]'", p, method, mutate


def _similar(a: str, b: str) -> float:
    import difflib
    return difflib.SequenceMatcher(None, a or '', b or '').ratio()


def _timed(execute_fn, url, method, body):
    t = time.monotonic()
    r = _get(execute_fn, url, method, body)
    return r, time.monotonic() - t


def _adjudicate(adjudicator, kind, url, payload, body, hint):
    if adjudicator is None or not getattr(adjudicator, 'available', False):
        return None
    v = adjudicator.classify_owasp(
        {'alert': f'Possible {kind}: {hint} (payload={payload})', 'url': url,
         'evidence': (body or '')[:400]}, {'API8:2023': kind})
    if v:
        return v.get('reason', hint) if isinstance(v, dict) else hint
    return None


# =============================================================================
# SQL injection
# =============================================================================
def probe_sqli(execute_fn: Callable, targets: List[Dict],
               adjudicator=None, time_budget: int = _TIME_BUDGET) -> List[InjectionFinding]:
    findings: List[InjectionFinding] = []
    budget = [time_budget]
    for t in targets:
        hit = None
        for label, key, method, mutate in _points(t):
            hit = (_sqli_error(execute_fn, method, mutate, label)
                   or _sqli_time(execute_fn, method, mutate, label, budget)
                   or _sqli_boolean(execute_fn, method, mutate, label, adjudicator))
            if hit:
                findings.append(hit)
                break                        # une preuve par cible suffit
    return findings


def _sqli_error(execute_fn, method, mutate, label) -> Optional[InjectionFinding]:
    for payload in _SQL_ERROR_PAYLOADS:
        url, body = mutate(payload)
        r = _get(execute_fn, url, method, body)
        if _SQL_ERRORS.search(r.get('body', '') or ''):
            return InjectionFinding('SQLI', 'Critical',
                f"SQL injection (error-based) via {label}", url,
                f"DB error signature triggered by {payload!r}", payload=payload)
    return None


def _sqli_time(execute_fn, method, mutate, label, budget) -> Optional[InjectionFinding]:
    if budget[0] <= 0:
        return None
    for sleep_p, ctrl_p in _SQL_TIME:
        if budget[0] <= 0:
            break
        budget[0] -= 1
        u_c, b_c = mutate(ctrl_p)
        _, t_ctrl = _timed(execute_fn, u_c, method, b_c)
        if t_ctrl > _TIME_CTRL_MAX:          # cible lente par nature -> pas fiable
            continue
        u_s, b_s = mutate(sleep_p)
        _, t_sleep = _timed(execute_fn, u_s, method, b_s)
        if t_sleep - t_ctrl >= _TIME_THRESHOLD:
            return InjectionFinding('SQLI', 'Critical',
                f"SQL injection (time-based) via {label}", u_s,
                f"SLEEP delay {t_sleep:.1f}s vs control {t_ctrl:.1f}s", payload=sleep_p)
    return None


def _sqli_boolean(execute_fn, method, mutate, label, adjudicator) -> Optional[InjectionFinding]:
    # baseline bénin + TRUE + FALSE ; TRUE proche baseline, FALSE nettement différent.
    ub, bb = mutate('hzbaseline_zzz')
    base = _get(execute_fn, ub, method, bb)
    base_body, base_status = base.get('body', '') or '', int(base.get('status', 0))
    for tp, fp in zip(_SQL_BOOL_TRUE, _SQL_BOOL_FALSE):
        ut, bt = mutate(tp)
        rt = _get(execute_fn, ut, method, bt)
        uf, bf = mutate(fp)
        rf = _get(execute_fn, uf, method, bf)
        tb, fb = rt.get('body', '') or '', rf.get('body', '') or ''
        if _SQL_ERRORS.search(tb) or _SQL_ERRORS.search(fb):
            continue                          # géré par error-based
        sim_tf = _similar(tb, fb)
        sim_tbase = _similar(tb, base_body)
        # TRUE ~ baseline (page normale) ET FALSE nettement divergent
        strong = (sim_tbase > 0.95 and sim_tf < 0.9 and
                  int(rt.get('status', 0)) == base_status)
        if strong:
            # Le booléen reste SUSPECTED (une appli légitime peut varier selon la
            # valeur) : source 'heuristic' (ou 'llm' si adjugé) -> jamais CONFIRMED.
            reason = _adjudicate(adjudicator, 'SQL injection', ut, tp, tb,
                                 'boolean TRUE/FALSE responses diverge')
            src = 'llm' if reason else 'heuristic'
            return InjectionFinding('SQLI', 'High',
                f"SQL injection (boolean-based) via {label}", ut,
                reason or f"TRUE≈baseline, FALSE diverges (sim {sim_tf:.2f})",
                source=src, confidence=0.55, payload=tp)
    return None


# =============================================================================
# NoSQL injection
# =============================================================================
def probe_nosqli(execute_fn: Callable, targets: List[Dict],
                 adjudicator=None, time_budget: int = _TIME_BUDGET) -> List[InjectionFinding]:
    findings: List[InjectionFinding] = []
    budget = [time_budget]
    for t in targets:
        hit = _nosqli_error(execute_fn, t) or _nosqli_operator(execute_fn, t, adjudicator) \
            or _nosqli_time(execute_fn, t, budget)
        if hit:
            findings.append(hit)
    return findings


def _nosqli_error(execute_fn, t) -> Optional[InjectionFinding]:
    for label, key, method, mutate in _points(t):
        url, body = mutate("'\"{`;$")
        r = _get(execute_fn, url, method, body)
        if _NOSQL_ERRORS.search(r.get('body', '') or ''):
            return InjectionFinding('NOSQLI', 'Critical',
                f"NoSQL injection (error-based) via {label}", url,
                "Mongo/NoSQL error signature triggered", payload="'\"{`;$")
    return None


def _nosqli_operator(execute_fn, t, adjudicator) -> Optional[InjectionFinding]:
    # baseline bénin, puis opérateur ($ne/$gt/$regex) : si la réponse CHANGE
    # nettement (accès élargi), c'est une injection d'opérateur.
    for label, key, method, mutate in _points(t):
        if not isinstance(t.get('body'), (dict, list)):
            continue                          # opérateur JSON = corps seulement
        ub, bb = mutate('hzbaseline_zzz')
        base = _get(execute_fn, ub, method, bb)
        base_body = base.get('body', '') or ''
        for op in _NOSQL_OPERATORS:
            u, b = mutate(op)
            r = _get(execute_fn, u, method, b)
            rb = r.get('body', '') or ''
            changed = (int(r.get('status', 0)) != int(base.get('status', 0)) or
                       _similar(rb, base_body) < 0.85)
            if changed and 200 <= int(r.get('status', 0)) < 300:
                reason = _adjudicate(adjudicator, 'NoSQL injection', u, str(op), rb,
                                     'operator injection changed the result set')
                src = 'llm' if reason else 'deterministic'
                return InjectionFinding('NOSQLI', 'High',
                    f"NoSQL operator injection via {label}", u,
                    reason or f"{op} altered the response vs baseline",
                    source=src, confidence=0.6, payload=str(op))
    # query-string operator form
    for label, key, method, mutate in _nosql_query_points(t):
        ub, _ = mutate('$eq')
        base = _get(execute_fn, ub, method, None)
        for op in ('$ne', '$gt', '$regex'):
            u, _ = mutate(op)
            r = _get(execute_fn, u, method, None)
            if (200 <= int(r.get('status', 0)) < 300 and
                    _similar(r.get('body', '') or '', base.get('body', '') or '') < 0.85):
                return InjectionFinding('NOSQLI', 'High',
                    f"NoSQL operator injection via {label}", u,
                    f"{op} in query string altered the response", payload=f'{key}[{op}]')
    return None


def _nosqli_time(execute_fn, t, budget) -> Optional[InjectionFinding]:
    if budget[0] <= 0:
        return None
    for label, key, method, mutate in _points(t):
        if not isinstance(t.get('body'), (dict, list)) or budget[0] <= 0:
            continue
        budget[0] -= 1
        u_c, b_c = mutate(_NOSQL_TIME_CTRL)
        _, t_ctrl = _timed(execute_fn, u_c, method, b_c)
        if t_ctrl > _TIME_CTRL_MAX:
            continue
        u_s, b_s = mutate(_NOSQL_TIME)
        _, t_sleep = _timed(execute_fn, u_s, method, b_s)
        if t_sleep - t_ctrl >= _TIME_THRESHOLD:
            return InjectionFinding('NOSQLI', 'Critical',
                f"NoSQL injection (time-based $where) via {label}", u_s,
                f"$where sleep delay {t_sleep:.1f}s vs control {t_ctrl:.1f}s",
                payload=str(_NOSQL_TIME))
    return None


# =============================================================================
# Orchestrateur
# =============================================================================
def run_injection_probes(execute_fn: Callable, har_data: Dict,
                         targets: Optional[List[Dict]] = None,
                         adjudicator=None) -> List[Dict]:
    """Lance SQLi + NoSQLi et rend des findings à plat."""
    targets = targets if targets is not None else injectable_targets(har_data)
    out: List[InjectionFinding] = []
    out += probe_sqli(execute_fn, targets, adjudicator=adjudicator)
    out += probe_nosqli(execute_fn, targets, adjudicator=adjudicator)
    flat = [f.flat() for f in out]
    logger.info("injection_probes_done", findings=len(flat))
    return flat
