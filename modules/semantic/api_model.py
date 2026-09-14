"""
APIModel — le modèle sémantique sous-jacent de l'API.

Chaque moteur avait sa propre façon de redeviner « à quoi correspond cette
route » : l'investigator cherchait l'oracle de relecture, la matrice ignorait
quels endpoints sont publics, le BOLA ne savait pas quel champ porte la
propriété. On construit ce savoir UNE fois, ici, et tous consomment le même
modèle.

Répartition (discipline du projet) :
- DÉTERMINISTE (l'essentiel) : à partir du HAR, on groupe par route templatée et
  on déduit ressource, rôle CRUD, paramètre d'identité, schémas requête/réponse,
  collection vs item, vu-sans-authentification, sensibilité par mots-clés/forme
  de réponse, et surtout la CORRÉLATION écriture↔lecture (la carte des oracles).
- IA (optionnelle, avec repli) : `enrich_semantics(client)` nomme l'entité
  métier, confirme la sensibilité et mappe un champ injecté vers l'attribut
  réellement stocké. Sans modèle, tout fonctionne en déterministe.

Le modèle ne touche jamais le réseau à la construction (il lit le HAR déjà
capturé) → reproductible et auditable.
"""
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..utils import get_logger
from ..regression_gate import endpoint_template

logger = get_logger("semantic.api_model")

# Segments « techniques » à ignorer pour nommer la ressource.
_VERSION_RE = re.compile(r'^v\d+$', re.I)
_NONRESOURCE = {'api', 'rest', 'v1', 'v2', 'v3', 'public', 'internal'}

# Un segment templaté ({id}) marque un accès à un objet précis.
_PARAM_RE = re.compile(r'^\{.+\}$')

# Sensibilité : un SEGMENT de chemin ENTIER égal à l'un de ces mots (pas une
# sous-chaîne). Le matching en sous-chaîne signalait `/oauth/token`,
# `/environments`, voire `/greenvalley` — faux positifs. On matche donc segment
# par segment. Les mots trop ambigus (token, password, export : souvent des
# endpoints publics comme /oauth/token ou /reset-password) sont exclus ; on garde
# les marqueurs sans équivoque d'un état privilégié/interne.
_SENSITIVE_SEGMENTS = frozenset((
    '_debug', 'debug', 'dump', 'actuator', 'admin', 'config', 'configuration',
    'internal', 'backup', 'secret', 'secrets', 'credential', 'credentials',
    'swagger', 'metrics', 'env', 'phpinfo', '.git', '.env',
))
# Champs dont la présence en réponse trahit une exposition de données sensibles.
_SENSITIVE_FIELDS = ('password', 'passwd', 'secret', 'token', 'ssn', 'credit',
                     'api_key', 'apikey', 'private_key')
# Actions PURES en dernier segment (ni collection, ni item, ni création de la
# ressource) : elles restent 'action'. À distinguer des actions de création
# (register, signup) qui, en POST, sont bien des 'create'.
_ACTIONS = {'login', 'logout', 'search', 'reset', 'refresh',
            'verify', 'activate', 'createdb', 'upload', 'download'}
# Clés candidates pour l'identité d'un objet (ce qu'on contrôle et qui est ré-exposé).
_IDENTITY_KEYS = ('username', 'user', 'login', 'id', 'uuid', 'email', 'name', 'slug')
# Clés qui trahissent le PROPRIÉTAIRE d'un objet (clé du BOLA : un objet renvoyé
# à B mais dont ce champ nomme A prouve la fuite d'accès).
_OWNERSHIP_KEYS = ('owner', 'user_id', 'userid', 'user', 'username', 'author',
                   'account', 'account_id', 'created_by', 'uid', 'owner_id')


def route_is_sensitive(path: str) -> bool:
    """Sensible si un SEGMENT ENTIER du chemin est un marqueur privilégié/interne.
    Matching par segment (pas sous-chaîne) pour éviter les faux positifs du type
    `/oauth/token`, `/environments`, `/greenvalley`, `/tokenizer`."""
    for seg in (path or '').split('/'):
        if seg.lower() in _SENSITIVE_SEGMENTS:
            return True
    return False


def _auth_present(headers: List[Dict]) -> bool:
    for h in headers or []:
        n = (h.get('name') or '').lower()
        if n in ('authorization', 'cookie') or 'token' in n or n == 'x-api-key':
            if h.get('value'):
                return True
    return False


@dataclass
class RouteInfo:
    template: str                 # "GET /users/v1/{id}"
    method: str
    path_template: str            # "/users/v1/{id}"
    resource: str                 # "users"
    crud: str                     # create|read|list|update|delete|action
    sample_url: str
    id_params: List[str] = field(default_factory=list)
    req_keys: List[str] = field(default_factory=list)
    resp_keys: List[str] = field(default_factory=list)
    statuses: List[int] = field(default_factory=list)
    seen_without_auth: bool = False
    sensitive: bool = False
    entity: Optional[str] = None  # nom métier, rempli par l'IA (optionnel)

    @property
    def is_item(self) -> bool:
        return bool(self.id_params) and self.crud in ('read', 'update', 'delete')

    @property
    def is_collection(self) -> bool:
        return self.crud == 'list'

    def to_dict(self) -> Dict:
        return {'template': self.template, 'resource': self.resource, 'crud': self.crud,
                'sensitive': self.sensitive, 'seen_without_auth': self.seen_without_auth,
                'id_params': self.id_params, 'entity': self.entity}


class APIModel:
    def __init__(self):
        self.routes: Dict[str, RouteInfo] = {}

    # --- construction déterministe -------------------------------------------
    @classmethod
    def from_har(cls, har: Dict, openapi: Optional[Dict] = None,
                 client=None) -> "APIModel":
        model = cls()
        for e in (har or {}).get('log', {}).get('entries', []) or []:
            model._ingest(e)
        model._mark_sensitive_by_response()
        if client is not None:
            try:
                model.enrich_semantics(client)
            except Exception as ex:
                logger.warning("api_model_enrich_failed", error=str(ex))
        logger.info("api_model_built", routes=len(model.routes))
        return model

    def _ingest(self, entry: Dict):
        req = entry.get('request', {})
        method = (req.get('method') or 'GET').upper()
        url = req.get('url', '')
        if not url:
            return
        tpl_path = endpoint_template(url)          # normalise les ids -> {id}
        template = f"{method} {tpl_path}"

        ri = self.routes.get(template)
        if ri is None:
            ri = RouteInfo(template=template, method=method, path_template=tpl_path,
                           resource=self._resource_of(tpl_path), crud='',
                           sample_url=url, id_params=self._params_of(tpl_path))
            ri.crud = self._crud_of(method, tpl_path, ri.id_params)
            ri.sensitive = route_is_sensitive(tpl_path)
            self.routes[template] = ri

        # Sans authentification + réponse OK => preuve empirique de route publique.
        resp = entry.get('response', {})
        status = int(resp.get('status', 0) or 0)
        if status:
            ri.statuses.append(status)
        if 200 <= status < 400 and not _auth_present(req.get('headers', [])):
            ri.seen_without_auth = True

        # Clés du corps de requête (surface d'affectation de masse).
        for k in self._json_keys(req.get('postData', {}).get('text', '')):
            if k not in ri.req_keys:
                ri.req_keys.append(k)
        # Clés de la réponse (ce que l'oracle ré-expose).
        for k in self._json_keys(resp.get('content', {}).get('text', ''), records=True):
            if k not in ri.resp_keys:
                ri.resp_keys.append(k)

    @staticmethod
    def _params_of(tpl_path: str) -> List[str]:
        return [s for s in tpl_path.split('/') if _PARAM_RE.match(s)]

    @staticmethod
    def _resource_of(tpl_path: str) -> str:
        for seg in tpl_path.strip('/').split('/'):
            if not seg or _PARAM_RE.match(seg) or _VERSION_RE.match(seg) \
                    or seg.lower() in _NONRESOURCE:
                continue
            return seg.lower()
        return tpl_path.strip('/').split('/')[0].lower() if tpl_path.strip('/') else 'root'

    @staticmethod
    def _crud_of(method: str, tpl_path: str, params: List[str]) -> str:
        last = tpl_path.rstrip('/').split('/')[-1].lower()
        if last in _ACTIONS or last.startswith('_'):
            return 'action'
        if method == 'POST':
            return 'create'
        if method in ('PUT', 'PATCH'):
            return 'update'
        if method == 'DELETE':
            return 'delete'
        # GET : item si le dernier segment est un paramètre, sinon collection.
        if params and _PARAM_RE.match(tpl_path.rstrip('/').split('/')[-1]):
            return 'read'
        return 'list'

    @staticmethod
    def _json_keys(text: str, records: bool = False) -> List[str]:
        if not text:
            return []
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            return []
        keys: List[str] = []
        if isinstance(data, dict):
            keys.extend(data.keys())
            if records:  # dict {clé: [ {record}, ... ]} : on lit aussi le record
                for v in data.values():
                    if isinstance(v, list) and v and isinstance(v[0], dict):
                        keys.extend(v[0].keys())
        elif isinstance(data, list) and data and isinstance(data[0], dict):
            keys.extend(data[0].keys())
        return list(dict.fromkeys(keys))

    def _mark_sensitive_by_response(self):
        for ri in self.routes.values():
            if any(any(s in (k or '').lower() for s in _SENSITIVE_FIELDS)
                   for k in ri.resp_keys):
                ri.sensitive = True

    # --- requêtes du modèle (consommées par les moteurs) ---------------------
    def routes_for(self, resource: str) -> List[RouteInfo]:
        return [r for r in self.routes.values() if r.resource == resource]

    def is_sensitive(self, template: str) -> bool:
        ri = self.routes.get(template)
        return bool(ri and ri.sensitive)

    def is_public(self, template: str) -> bool:
        """Route empiriquement publique : atteinte avec succès sans identifiants."""
        ri = self.routes.get(template)
        return bool(ri and ri.seen_without_auth)

    def readback_for(self, write_route: RouteInfo) -> List[RouteInfo]:
        """Étant donné une écriture (create/update) sur une ressource, les GET qui
        la relisent — la carte des oracles. Ordre : sensible/debug d'abord (le
        plus révélateur), puis collection, puis item."""
        reads = [r for r in self.routes_for(write_route.resource) if r.method == 'GET']

        def rank(r: RouteInfo) -> int:
            if r.sensitive:
                return 0
            if r.is_collection:
                return 1
            if r.is_item:
                return 2
            return 3
        return sorted(reads, key=rank)

    def oracle_candidate_urls(self, resource: str) -> List[str]:
        """URLs d'échantillon des GET pouvant servir d'oracle pour une ressource."""
        reads = [r for r in self.routes_for(resource) if r.method == 'GET']
        reads.sort(key=lambda r: (not r.sensitive, not r.is_collection))
        return [r.sample_url for r in reads]

    def identity_field_for(self, resource: str) -> Optional[str]:
        """Meilleure clé d'identité pour une ressource, d'après les corps observés."""
        keys: List[str] = []
        for r in self.routes_for(resource):
            keys.extend(r.req_keys)
        for cand in _IDENTITY_KEYS:
            if cand in keys:
                return cand
        return None

    def ownership_field_for(self, resource: str) -> Optional[str]:
        """Champ de réponse désignant le propriétaire d'un objet de la ressource.
        Sert au BOLA : si B reçoit un objet dont ce champ nomme A, l'accès a fui."""
        keys: List[str] = []
        for r in self.routes_for(resource):
            keys.extend(r.resp_keys)
        low = {k.lower(): k for k in keys}
        for cand in _OWNERSHIP_KEYS:
            if cand in low:
                return low[cand]
        return None

    def item_routes(self) -> List[RouteInfo]:
        """Routes d'accès à un objet précis (surface BOLA)."""
        return [r for r in self.routes.values() if r.is_item]

    # --- enrichissement IA optionnel -----------------------------------------
    def enrich_semantics(self, client) -> None:
        """L'IA nomme l'entité métier et confirme la sensibilité. Repli : no-op
        (le déterministe fait déjà foi)."""
        from ..llm.adaptive_idor import _extract_json
        summary = [{'template': r.template, 'resource': r.resource, 'crud': r.crud,
                    'resp_keys': r.resp_keys[:12]} for r in self.routes.values()]
        prompt = ("Given these API routes, return JSON mapping each 'template' to "
                  "{\"entity\": business entity name, \"sensitive\": bool}. Routes:\n"
                  + json.dumps(summary)[:4000])
        try:
            resp = client.complete(
                prompt, system="You are a security engineer. Answer only with JSON.")
            data = _extract_json(getattr(resp, 'content', None))
        except Exception as e:
            logger.warning("api_model_enrich_llm_failed", error=str(e))
            return
        if not isinstance(data, dict):
            return
        for tpl, meta in data.items():
            ri = self.routes.get(tpl)
            if ri and isinstance(meta, dict):
                ri.entity = meta.get('entity') or ri.entity
                if meta.get('sensitive') is True:
                    ri.sensitive = True
