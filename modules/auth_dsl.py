"""
DSL de recettes d'authentification — mémoire persistante de la ré-auth.

Idée : l'IA ne doit déduire la mécanique de login (où est le nonce, comment
revient la session) qu'UNE fois. Sa découverte est écrite dans un fichier `.dsl`
lisible/éditable ; les runs suivants la relisent et n'appellent plus le modèle.
C'est « l'IA propose une fois, le code exécute pour toujours ».

Le DSL décrit, par hôte, une recette qui correspond 1-pour-1 aux stratégies
enfichables de modules.reauth. Exemple :

    # découvert par l'IA le 2026-09-15
    auth "app.example" {
      login POST /login
      nonce-field csrf
      nonce   regex url=/login pattern="name=\\"csrf\\" value=\\"([^\\"]+)\\""
      session cookie names=sid,jwt
      rotate  cookie
      expire  cookie_ttl skew=30
      expire  redirect login_path=/login
    }

SÉCURITÉ : le DSL ne stocke QUE la structure (extraction, rotation, expiration).
Jamais les identifiants — ils restent en config/env. `serialize` refuse `credentials`.

`parse(text) -> {host: recipe_spec}` et `serialize(host, spec) -> str` font
l'aller-retour ; `recipe_spec` a la même forme que le bloc `reauth:` de la config
(dicts {strategy: name, ...}), donc directement consommable par ReAuthenticator.
"""
import re
from typing import Dict, List, Optional

from .utils import get_logger

logger = get_logger("auth_dsl")

_DIRECTIVES = ('login', 'nonce-field', 'nonce', 'session', 'rotate', 'expire')
_SLOT_KEY = {'nonce': 'nonce', 'session': 'session', 'rotate': 'rotation'}


# --- valeurs : encodage/décodage --------------------------------------------
def _enc_value(v) -> str:
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, (list, tuple)):
        return ','.join(_enc_value(x) for x in v)
    s = str(v)
    if s and re.fullmatch(r'[^\s"=,]+', s):
        return s
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def _dec_value(tok: str):
    if tok.startswith('"'):
        return tok[1:-1].replace('\\"', '"').replace('\\\\', '\\')
    if ',' in tok:
        return [_dec_value(x) for x in tok.split(',')]
    if tok in ('true', 'false'):
        return tok == 'true'
    if re.fullmatch(r'-?\d+', tok):
        return int(tok)
    if re.fullmatch(r'-?\d+\.\d+', tok):
        return float(tok)
    return tok


def _tokenize(line: str) -> List[str]:
    """Découpe une ligne en respectant les guillemets (avec échappements)."""
    toks, i, n = [], 0, len(line)
    while i < n:
        if line[i].isspace():
            i += 1
            continue
        if line[i] == '"':
            j = i + 1
            buf = ['"']
            while j < n:
                if line[j] == '\\' and j + 1 < n:
                    buf.append(line[j:j + 2])
                    j += 2
                    continue
                buf.append(line[j])
                if line[j] == '"':
                    j += 1
                    break
                j += 1
            toks.append(''.join(buf))
            i = j
        else:
            j = i
            while j < n and not line[j].isspace():
                if line[j] == '"':                       # guillemet collé (key="v v")
                    k = j + 1
                    while k < n and not (line[k] == '"' and line[k - 1] != '\\'):
                        k += 1
                    j = k + 1
                    continue
                j += 1
            toks.append(line[i:j])
            i = j
    return toks


def _kv(tokens: List[str]) -> Dict:
    """Transforme des tokens `key=value` en dict typé."""
    out = {}
    for t in tokens:
        if '=' not in t:
            continue
        k, v = t.split('=', 1)
        out[k] = _dec_value(v)
    return out


# --- parse ------------------------------------------------------------------
def parse(text: str) -> Dict[str, Dict]:
    """Lit le DSL → {host: recipe_spec}. Tolérant : ignore lignes vides/# et
    directives inconnues (loggées)."""
    recipes: Dict[str, Dict] = {}
    host: Optional[str] = None
    cur: Optional[Dict] = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line == '}':
            if host is not None:
                recipes[host] = cur
            host, cur = None, None
            continue
        m = re.match(r'^auth\s+(?:"([^"]+)"|(\S+))\s*\{$', line)
        if m:
            host = m.group(1) or m.group(2)
            cur = {'login': {}, 'expiry': {'strategies': []}}
            continue
        if cur is None:
            continue
        toks = _tokenize(line)
        directive = toks[0]
        if directive == 'login':                         # login <METHOD> <path>
            cur['login']['method'] = toks[1] if len(toks) > 1 else 'POST'
            cur['login']['url'] = toks[2] if len(toks) > 2 else '/login'
        elif directive == 'nonce-field':
            cur['login']['nonce_field'] = toks[1] if len(toks) > 1 else None
        elif directive in ('nonce', 'session', 'rotate'):
            spec = {'strategy': toks[1]}
            spec.update(_kv(toks[2:]))
            cur[_SLOT_KEY[directive]] = spec
        elif directive == 'expire':
            spec = {'strategy': toks[1]}
            spec.update(_kv(toks[2:]))
            cur['expiry']['strategies'].append(spec)
        else:
            logger.info("auth_dsl_unknown_directive", directive=directive)
    if host is not None:                                 # bloc non fermé toléré
        recipes[host] = cur
    return recipes


# --- serialize --------------------------------------------------------------
def _spec_line(verb: str, spec: Dict) -> str:
    parts = [verb, str(spec.get('strategy', ''))]
    for k, v in spec.items():
        if k == 'strategy' or v is None:
            continue
        if k == 'client':                                # ne jamais sérialiser un objet runtime
            continue
        parts.append(f'{k}={_enc_value(v)}')
    return '  ' + ' '.join(parts)


def serialize(host: str, spec: Dict, header: Optional[str] = None) -> str:
    """Recette d'un hôte → texte DSL. Refuse d'écrire des credentials."""
    login = dict(spec.get('login', {}))
    if 'credentials' in login:
        login.pop('credentials')                         # SÉCURITÉ : jamais de secret dans le DSL
    lines = []
    if header:
        lines.append(f'# {header}')
    lines.append(f'auth "{host}" {{')
    method = login.get('method', 'POST')
    url = login.get('url', '/login')
    lines.append(f'  login {method} {url}')
    if login.get('nonce_field'):
        lines.append(f"  nonce-field {login['nonce_field']}")
    if spec.get('nonce'):
        lines.append(_spec_line('nonce', spec['nonce']))
    if spec.get('session'):
        lines.append(_spec_line('session', spec['session']))
    if spec.get('rotation'):
        lines.append(_spec_line('rotate', spec['rotation']))
    for e in (spec.get('expiry', {}) or {}).get('strategies', []):
        lines.append(_spec_line('expire', e))
    lines.append('}')
    return '\n'.join(lines)


def serialize_all(recipes: Dict[str, Dict]) -> str:
    return '\n\n'.join(serialize(h, s) for h, s in recipes.items())


# --- store persistant -------------------------------------------------------
class AuthRecipeStore:
    """Charge/écrit un fichier DSL et fournit les recettes par hôte. C'est la
    MÉMOIRE : une fois qu'une recette est écrite, l'IA n'est plus sollicitée."""

    def __init__(self, path: str = './.harzap_auth.dsl'):
        self.path = path
        self._recipes: Dict[str, Dict] = {}
        self.load()

    def load(self) -> Dict[str, Dict]:
        import os
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    self._recipes = parse(f.read())
            except Exception as e:
                logger.warning("auth_dsl_load_failed", path=self.path, error=str(e))
                self._recipes = {}
        return self._recipes

    def get(self, host: str) -> Optional[Dict]:
        return self._recipes.get(host)

    def has_slot(self, host: str, slot: str) -> bool:
        """Un slot (nonce/session) est-il DÉJÀ résolu concrètement (≠ ai) ?"""
        rec = self._recipes.get(host) or {}
        spec = rec.get(slot)
        return bool(spec and spec.get('strategy') and spec.get('strategy') != 'ai')

    def record_slot(self, host: str, slot: str, spec: Dict):
        """Persiste une spec concrète déduite par l'IA pour un slot donné."""
        rec = self._recipes.setdefault(host, {'login': {}, 'expiry': {'strategies': []}})
        rec[slot] = spec
        self.save()
        logger.info("auth_dsl_recorded", host=host, slot=slot, strategy=spec.get('strategy'))

    def put(self, host: str, spec: Dict):
        self._recipes[host] = spec
        self.save()

    def save(self):
        try:
            import datetime
            stamp = datetime.date.today().isoformat()
            blocks = [serialize(h, s, header=f'découvert/édité — {stamp}')
                      for h, s in self._recipes.items()]
            with open(self.path, 'w') as f:
                f.write('\n\n'.join(blocks) + '\n')
        except Exception as e:
            logger.warning("auth_dsl_save_failed", path=self.path, error=str(e))
