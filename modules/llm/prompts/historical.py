"""
Prompts des moteurs « historiques » (adaptatifs + classifieurs) — SORTIS du code.

Complète prompts/investigations.py : ici les prompts des boucles adaptatives
IDOR / hidden-params, de l'adjudicateur de faux positifs passifs, du compositeur
de chaînes d'exploitation et du classifieur OWASP. Même principe : uniquement le
TEXTE envoyé à l'IA, la logique et les replis restent dans les modules.
"""
from .base import PromptTemplate

# Personas système (préservées à l'identique pour ne pas changer le comportement).
SYS_SEC_REQUESTED = "You are a security engineer. Answer only with the requested JSON."
SYS_OFFENSIVE = "You are a senior offensive security engineer. Answer only with the requested JSON."

# --- IDOR (API1) : interprétation d'une relecture croisée -------------------
IDOR_INTERPRET = PromptTemplate(
    name="idor_interpret", description="Decide if an IDOR test leaked another user's data",
    system=SYS_SEC_REQUESTED,
    user="""You are adjudicating an IDOR test. Decide if the TEST response is another user's data (a real leak) or a generic error/empty/own-data page. Return JSON {"is_leak": bool, "confidence": number(0-1), "reason": str}.
BASELINE (authorized, id=$baseline_id): status=$baseline_status len=$baseline_len body=$baseline_body
TEST (id=$test_id): status=$test_status len=$test_len body=$test_body""",
)

IDOR_REFINE = PromptTemplate(
    name="idor_refine", description="Propose next object ids to enumerate for IDOR",
    system=SYS_SEC_REQUESTED,
    user="""Given these IDOR enumeration results, propose the next object ids most likely to expose another user's data. Return JSON as an array of string ids.
Endpoint: $url
Original id: $original_id
Results so far: $results""",
)

# --- Hidden params (API5) --------------------------------------------------
HIDDEN_PARAMS_INTERPRET = PromptTemplate(
    name="hidden_params_interpret", description="Decide if a hidden param changed behavior",
    system=SYS_SEC_REQUESTED,
    user="""A hidden parameter was added to a request. Decide if it changed server behavior in a security-relevant way (debug output, admin mode, extra data). Return JSON {"active": bool, "confidence": number(0-1), "reason": str}.
BASELINE: status=$baseline_status len=$baseline_len body=$baseline_body
WITH $param=$value: status=$obs_status len=$obs_len body=$obs_body""",
)

HIDDEN_PARAMS_REFINE = PromptTemplate(
    name="hidden_params_refine", description="Propose adjacent debug/admin params",
    system=SYS_SEC_REQUESTED,
    user="""These hidden parameters changed server behavior. Propose adjacent debug/admin parameters likely to also be active. Return JSON as an array of {"name": str, "value": str}.
Endpoint: $url
Active so far: $active""",
)

# --- Adjudicateur de faux positifs passifs ---------------------------------
FP_ADJUDICATE = PromptTemplate(
    name="fp_adjudicate", description="True vs false positive for a passive finding",
    system=SYS_SEC_REQUESTED,
    user="""Decide if this passive security finding is a TRUE positive or a false positive (e.g. a regex matching sample/placeholder data, or a header flagged on a response where it does not apply). Return JSON {"is_true_positive": bool, "confidence": number(0-1), "reason": str}.
Finding: $finding""",
)

# --- Compositeur de chaînes d'exploitation ---------------------------------
EXPLOIT_CHAIN = PromptTemplate(
    name="exploit_chain", description="Compose multi-step exploit chains from findings",
    system=SYS_OFFENSIVE,
    user="""Given these confirmed API security findings, compose realistic multi-step exploit chains (combine findings into an attack path). Only chains that the findings actually support. Return JSON as an array of {"title": str, "steps": [str], "rationale": str, "confidence": number(0-1)}.
Findings: $findings""",
)

# --- Classifieur OWASP ------------------------------------------------------
OWASP_CLASSIFY = PromptTemplate(
    name="owasp_classify", description="Map a finding to one OWASP category id",
    system=SYS_SEC_REQUESTED,
    user="""Map this security finding to exactly one category id from the list, or null if none fits. Return JSON {"category": str|null, "reason": str}.
Categories: $categories
Finding: $finding""",
)

# --- GraphQL : requêtes d'attaque depuis le schéma -------------------------
GRAPHQL_ATTACK = PromptTemplate(
    name="graphql_attack", description="Propose GraphQL attack queries from a schema",
    system="You are a GraphQL security expert. Answer only with the requested JSON.",
    user="""From this GraphQL schema, propose up to $limit attack queries (deep nesting, aliasing/batching DoS, sensitive-field access, mutation abuse). Return JSON as an array of GraphQL query strings.
Schema: $schema""",
)

HISTORICAL_PROMPTS = {
    p.name: p for p in (
        IDOR_INTERPRET, IDOR_REFINE, HIDDEN_PARAMS_INTERPRET, HIDDEN_PARAMS_REFINE,
        FP_ADJUDICATE, EXPLOIT_CHAIN, OWASP_CLASSIFY, GRAPHQL_ATTACK)
}
