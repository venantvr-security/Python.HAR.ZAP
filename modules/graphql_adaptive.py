"""
Couche GraphQL adaptative (complète le graphql_scanner statique).

IA : l'introspection et sa détection sont déterministes (requête standard, statut).
L'IA sert au seul endroit qui le mérite — générer des requêtes d'attaque ciblées à
partir du schéma introspecté (génération sous contexte) ; sinon des gabarits
d'abus connus (batching/aliasing, imbrication profonde) prennent le relais.
"""
import json
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from .utils import get_logger

logger = get_logger("graphql.adaptive")

# Requête d'introspection minimale (déterministe, standard GraphQL).
INTROSPECTION_QUERY = '{"query":"{__schema{queryType{name} types{name kind}}}"}'


@dataclass
class GraphQLFinding:
    severity: str
    title: str
    url: str
    detail: str = ''

    def flat(self) -> Dict:
        return {'source': 'graphql', 'risk': self.severity, 'name': self.title, 'url': self.url}


def detect_introspection(execute_fn: Callable[[str, str, str], Dict], url: str) -> Optional[GraphQLFinding]:
    """Introspection activée en production = fuite de surface d'attaque (déterministe).

    execute_fn(url, method, body) -> {'status', 'body'}.
    """
    r = execute_fn(url, 'POST', INTROSPECTION_QUERY) or {}
    body = r.get('body', '') or ''
    if r.get('status') == 200 and '__schema' in body and 'queryType' in body:
        return GraphQLFinding('Medium', 'GraphQL introspection enabled', url,
                              'Full schema exposed — maps the attack surface for an attacker')
    return None


# Gabarits d'abus connus (repli offline, sans modèle).
def _template_queries() -> List[str]:
    return [
        '{"query":"query{__typename @a:__typename @b:__typename @c:__typename}"}',  # aliasing DoS
        '{"query":"{a:__schema{types{name}} b:__schema{types{name}}}"}',            # batching
    ]


def generate_attack_queries(schema_json: str, client=None, limit: int = 8) -> List[str]:
    """Requêtes d'attaque ciblées. LLM à partir du schéma si dispo, sinon gabarits."""
    if client is not None and schema_json:
        prompt = (
            f"From this GraphQL schema, propose up to {limit} attack queries (deep nesting, "
            "aliasing/batching DoS, sensitive-field access, mutation abuse). "
            "Return JSON as an array of GraphQL query strings.\n"
            f"Schema: {schema_json[:4000]}"
        )
        try:
            resp = client.complete(
                prompt, system="You are a GraphQL security expert. Answer only with the requested JSON.")
            from .llm.adaptive_idor import _extract_json
            data = _extract_json(getattr(resp, 'content', None))
            if isinstance(data, list) and data:
                return [str(q) for q in data][:limit]
        except Exception as e:
            logger.warning("graphql_llm_failed", error=str(e))
    return _template_queries()
