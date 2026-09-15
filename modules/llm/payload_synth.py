"""
Synthèse de payloads par endpoint (Phase 3b) — l'IA propose des charges adaptées
au stack de la cible ; le code les valide, les borne et les mémorise.

Les sondes d'injection utilisent des listes de payloads FIXES. Contre une cible
Node/Mongo, les charges MySQL sont du bruit ; contre PHP/MySQL, les opérateurs
Mongo sont inutiles. Ici l'IA regarde une empreinte (Server/X-Powered-By, cookies
de session, indices de SGBD) et PROPOSE des charges ciblées, en PLUS des charges
déterministes (jamais à leur place).

Discipline du projet :
- l'IA PROPOSE, le code DISPOSE : chaque charge est validée (chaîne, longueur
  bornée, dédup) et FILTRÉE des motifs destructifs (DROP/DELETE/TRUNCATE/rm…) —
  on reste sur des charges de DÉTECTION (erreur/booléen/temps), jamais d'altération ;
- « propose une fois » : les charges sont persistées par (domaine, classe) dans
  patterns/synth/ et relues aux runs suivants — plus d'appel modèle ;
- sans client LLM -> [] : les sondes gardent leurs charges déterministes.
"""
import json
import os
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

from ..utils import get_logger

logger = get_logger("llm.payload_synth")

# Motifs interdits : on ne synthétise que de la DÉTECTION, jamais de la destruction.
# Familles réellement dangereuses : écriture (DROP/TRUNCATE/DELETE/UPDATE/INSERT),
# écriture de fichier / RCE (INTO OUTFILE/DUMPFILE, COPY ... TO PROGRAM, xp_cmdshell,
# EXEC), exfiltration fichier (LOAD_FILE), et DoS (BENCHMARK, gros SLEEP/pg_sleep).
# Matché APRÈS normalisation (commentaires SQL supprimés, espaces réduits) pour
# résister à l'obfuscation type DROP/**/TABLE.
_DESTRUCTIVE = re.compile(
    r"(drop\s+table|drop\s+database|dropdatabase|truncate|delete\s+from|"
    r"update\s+.+\s+set|insert\s+into|replace\s+into|"
    r"into\s+(out|dump)file|load_file|copy\s+.+\s+to\s+program|"
    r"xp_cmdshell|sp_configure|sp_executesql|\bexec(ute)?\s*[\(@]|"
    r"benchmark\s*\(|(pg_)?sleep\s*\(\s*\d{3,}|"
    r"waitfor\s+delay\s*'0*:0*[1-9]\d|"
    r"shutdown|xp_|\brm\s+-rf|;\s*rm\b|mkfs|:\s*>\s*/|format\s+c:|"
    r"remove\s*\(|deleteone|deletemany|drop\s*\()", re.I)


def _normalize(s: str) -> str:
    """Neutralise l'obfuscation avant le filtre : commentaires SQL retirés,
    espaces/tabs/newlines réduits à un seul. `DROP/**/TABLE` -> `drop table`."""
    s = re.sub(r"/\*.*?\*/", " ", s, flags=re.S)   # commentaires bloc
    s = re.sub(r"\s+", " ", s)                       # espaces multiples
    return s

# Allowlist par MOTS-CLÉS (défense en profondeur, complète le blocklist). Une
# charge SQL n'est acceptée que si TOUT mot-clé SQL reconnu qu'elle contient est
# « sûr » (détection/lecture). Un mot-clé reconnu mais hors set sûr -> rejet, même
# si le blocklist l'a manqué. Les identifiants (admin, users, colonnes) ne sont
# pas des mots-clés -> ignorés, donc admin'-- - reste accepté.
_SAFE_SQL_KW = frozenset((
    "or and not union select null from where sleep pg_sleep waitfor delay version "
    "user current_user session_user database schema information_schema concat "
    "group_concat char chr cast convert ascii substring substr mid length count "
    "limit offset order group by as all distinct case when then else end like in "
    "between is exists true false having desc asc rlike regexp on join").split())
_DANGEROUS_SQL_KW = frozenset((
    "drop delete update insert replace truncate alter create exec execute outfile "
    "dumpfile load_file benchmark copy shutdown grant revoke merge call into "
    "sp_configure sp_executesql xp_cmdshell pg_read_file pg_ls_dir lo_import "
    "lo_export lo_get openrowset opendatasource").split())
_ALL_SQL_KW = _SAFE_SQL_KW | _DANGEROUS_SQL_KW


def _sql_shape_ok(norm_lower: str) -> bool:
    """Allowlist : rejette si un mot-clé SQL RECONNU est hors du set sûr."""
    words = set(re.findall(r'[a-z_]{2,}', norm_lower))
    return not (words & _ALL_SQL_KW) - _SAFE_SQL_KW


_MAX_PAYLOADS = 12
_MAX_LEN = 200

# Empreintes -> familles probables (aide au prompt, non contraignant).
_COOKIE_HINTS = {
    'phpsessid': 'php', 'jsessionid': 'java', 'connect.sid': 'node/express',
    'laravel_session': 'php/laravel', 'csrftoken': 'python/django',
    'asp.net_sessionid': 'asp.net', '_rails': 'ruby/rails',
}


def fingerprint(har_data: Dict) -> Dict[str, str]:
    """Devine le stack depuis les en-têtes de réponse et les cookies observés."""
    server = powered = db = stack = ''
    for e in (har_data or {}).get('log', {}).get('entries', []) or []:
        for h in (e.get('response', {}) or {}).get('headers', []) or []:
            n, v = h.get('name', '').lower(), h.get('value', '')
            if n == 'server' and not server:
                server = v
            if n == 'x-powered-by' and not powered:
                powered = v
            if n == 'set-cookie':
                for cookie, fam in _COOKIE_HINTS.items():
                    if cookie in v.lower():
                        stack = stack or fam
    blob = f"{server} {powered} {stack}".lower()
    if 'express' in blob or 'node' in blob:
        db = 'mongodb (probable)'
    elif 'php' in blob or 'laravel' in blob:
        db = 'mysql (probable)'
    elif 'django' in blob or 'python' in blob:
        db = 'postgresql (probable)'
    return {'server': server, 'x_powered_by': powered, 'stack': stack, 'db_guess': db}


class SynthStore:
    """Cache persistant des charges synthétisées (propose une fois)."""

    def __init__(self, base_path: str = './patterns'):
        self.path = os.path.join(base_path, 'synth')
        self._cache: Dict[str, Dict[str, List[str]]] = {}
        try:
            os.makedirs(self.path, exist_ok=True)
        except Exception:
            pass

    def _file(self, domain: str) -> str:
        safe = re.sub(r'[^\w.-]', '_', domain or 'unknown')
        return os.path.join(self.path, f'{safe}.json')

    def get(self, domain: str, vuln_class: str) -> Optional[List[str]]:
        if domain not in self._cache:
            try:
                with open(self._file(domain)) as f:
                    self._cache[domain] = json.load(f)
            except Exception:
                self._cache[domain] = {}
        return self._cache[domain].get(vuln_class)

    def put(self, domain: str, vuln_class: str, payloads: List[str]):
        self._cache.setdefault(domain, {})[vuln_class] = payloads
        try:
            with open(self._file(domain), 'w') as f:
                json.dump(self._cache[domain], f, indent=2)
        except Exception as e:
            logger.warning("synth_store_write_failed", error=str(e))


def _sanitize(items, vuln_class: str = 'sqli') -> List[str]:
    """Valide/borne/filtre une liste de charges proposées : blocklist (motifs
    destructifs dé-obfusqués) + allowlist par mots-clés SQL (pour la classe sqli)."""
    out, seen = [], set()
    if not isinstance(items, list):
        return out
    for it in items:
        s = str(it).strip()
        if not s or len(s) > _MAX_LEN or s in seen:
            continue
        norm = _normalize(s)
        if _DESTRUCTIVE.search(norm):               # blocklist : charge destructive
            logger.info("synth_dropped_destructive", payload=s[:40])
            continue
        if vuln_class == 'sqli' and not _sql_shape_ok(norm.lower()):
            logger.info("synth_dropped_off_allowlist", payload=s[:40])
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= _MAX_PAYLOADS:
            break
    return out


def synthesize(vuln_class: str, fp: Dict, client=None,
               store: Optional[SynthStore] = None, domain: str = 'unknown') -> List[str]:
    """Rend des charges ciblées pour `vuln_class` (sqli|nosqli|xss|ssti|lfi). Cache
    d'abord ; sinon l'IA propose (validée) et on persiste. Sans client -> []."""
    if store is not None:
        cached = store.get(domain, vuln_class)
        if cached is not None:
            return cached
    if client is None:
        return []
    system = ("You are a payload generator for AUTHORIZED DAST. Given a target "
              "fingerprint and a vulnerability class, propose up to 10 additional "
              "DETECTION payloads (error-based, boolean, time-based) tailored to the "
              "stack. STRICTLY non-destructive: never DROP/DELETE/UPDATE/INSERT/"
              "shutdown/exec/rm. Return ONLY a JSON array of strings.")
    user = f"class={vuln_class}\nfingerprint={json.dumps(fp)}"
    try:
        resp = client.complete(user, system=system)
        data = _first_json_array(getattr(resp, 'content', '') or '')
    except Exception as e:
        logger.warning("synthesize_failed", vuln_class=vuln_class, error=str(e))
        data = None
    payloads = _sanitize(data, vuln_class)
    if store is not None:
        store.put(domain, vuln_class, payloads)     # persiste même si vide (évite de re-demander)
    logger.info("payloads_synthesized", vuln_class=vuln_class, count=len(payloads))
    return payloads


def synthesize_for(har_data: Dict, classes, client=None, base_path: str = './patterns') -> Dict[str, List[str]]:
    """Confort : empreinte + synthèse pour plusieurs classes, avec cache par domaine."""
    if client is None:
        return {}
    fp = fingerprint(har_data)
    domain = _domain(har_data)
    store = SynthStore(base_path)
    return {c: synthesize(c, fp, client, store, domain) for c in classes}


def _domain(har_data: Dict) -> str:
    for e in (har_data or {}).get('log', {}).get('entries', []) or []:
        netloc = urlparse(e.get('request', {}).get('url', '')).netloc
        if netloc:
            return netloc
    return 'unknown'


def _first_json_array(text: str):
    m = re.search(r'\[.*\]', text or '', re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None
