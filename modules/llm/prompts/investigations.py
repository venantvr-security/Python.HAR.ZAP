"""
Prompts de la couche d'investigation (second ordre) — SORTIS du code.

Tous les prompts LLM des moteurs d'investigation vivent ici, en `PromptTemplate`
(placeholders `$var`), au lieu d'être noyés dans la logique. Avantages : relecture
et audit sécurité en un seul endroit, réutilisation, et itération sur le prompt
sans toucher au code métier. Le code déterministe et les replis hors-ligne restent
dans les modules ; ici, uniquement le texte envoyé à l'IA.
"""
from .base import PromptTemplate

# Systèmes réutilisables (persona + contrainte de format).
SYS_SECURITY_JSON = "You are a senior security engineer. Answer only with JSON."
SYS_PENTEST_JSON = "You are a web pentester. Answer only with the JSON list."

# --- Décision mixte (faux positifs) : arbitre le SUSPECTED ------------------
MIX_ADJUDICATE = PromptTemplate(
    name="mix_adjudicate",
    description="Adjudicate an ambiguous (SUSPECTED) deterministic finding",
    system=SYS_SECURITY_JSON,
    user="""A deterministic security check could not decide (SUSPECTED). Adjudicate: is this a REAL finding or a FALSE POSITIVE? Judge only from the evidence; when genuinely unclear, say uncertain.
Finding type: $kind
URL: $url
Why undecided: $reason
Evidence: $evidence
Return JSON {"decision": "real"|"false_positive"|"uncertain", "reason": str, "confidence": number(0-1)}.""",
)

# --- BOLA : cas opaque (deux sessions, même corps) --------------------------
BOLA_ADJUDICATE = PromptTemplate(
    name="bola_adjudicate",
    description="Decide if two users receiving the same object body proves BOLA",
    system=SYS_SECURITY_JSON,
    user="""Two different authenticated users received the SAME object body from an object-by-id endpoint. Decide if this proves a broken object-level authorization (one user reading another's private object) rather than a shared/public resource.
Caller A id: $caller_id, Caller B id: $other_id
Object body: $body
Return JSON {"bola": bool, "reason": str}.""",
)

# --- Mass assignment : interprétation d'une injection -----------------------
MA_INTERPRET = PromptTemplate(
    name="ma_interpret",
    description="Decide if an injected mass-assignment field was accepted",
    system=SYS_SECURITY_JSON,
    user="""A mass-assignment field was injected into an API write. Decide if the server ACCEPTED it (privilege escalation) or rejected/ignored it. Return JSON {"accepted": bool, "confidence": number(0-1), "reason": str}.
Injected: $field=$value
Response: status=$status body=$body""",
)

# --- Mass assignment : champs adjacents à tenter ----------------------------
MA_REFINE = PromptTemplate(
    name="ma_refine",
    description="Propose adjacent mass-assignment fields likely also accepted",
    system=SYS_SECURITY_JSON,
    user="""These mass-assignment fields were ACCEPTED by the API. Propose adjacent privilege-escalation fields likely to also be accepted. Return JSON as an array of {"field": str, "value": any}.
Context: $context
Accepted so far: $accepted""",
)

# --- Investigator : plan de confirmation (oracle de relecture) --------------
INVESTIGATOR_PLAN = PromptTemplate(
    name="investigator_plan",
    description="Choose oracle/identity/effect to confirm a mass-assignment",
    system=SYS_SECURITY_JSON,
    user="""You are confirming a mass-assignment vulnerability by a second request.
Write endpoint: $method $url
Write body keys: $body_keys
Candidate GET oracle endpoints (which one reflects stored state?):
$oracles
Return JSON: {"oracle_url": str, "identity_field": str (a write-body key echoed back by the oracle), "record_path": str|null (json key holding the list of records, null if the oracle returns a bare list), "effect_field": str|null (the STORED attribute that proves the injection took effect, e.g. an injected 'is_admin' may be stored as 'admin'; null to check the injected field verbatim)}.""",
)

# --- Extrapolation de routes : deviner la surface non observée --------------
ROUTE_EXTRAPOLATE = PromptTemplate(
    name="route_extrapolate",
    description="Propose likely-existing but unobserved routes to probe",
    system=SYS_PENTEST_JSON,
    user="""You are mapping a REST API from partial traffic. Given the OBSERVED routes, propose likely-existing but UNOBSERVED routes an attacker should probe (hidden/undocumented endpoints, missing CRUD verbs, admin/debug/export variants) based on naming conventions and the business domain.
Resources: $resources
Observed routes:
$observed
Return a JSON list of {"method": str, "path": str (concrete path, use {id} for identifiers), "why": str, "risk": "low|medium|high"}. Do not repeat observed routes. Max 25.""",
)

# --- Modèle sémantique : nommer l'entité + confirmer la sensibilité ---------
API_MODEL_ENRICH = PromptTemplate(
    name="api_model_enrich",
    description="Name the business entity and confirm sensitivity per route",
    system="You are a security engineer. Answer only with JSON.",
    user="""Given these API routes, return JSON mapping each 'template' to {"entity": business entity name, "sensitive": bool}. Routes:
$routes""",
)

INVESTIGATION_PROMPTS = {
    p.name: p for p in (
        MIX_ADJUDICATE, BOLA_ADJUDICATE, MA_INTERPRET, MA_REFINE,
        INVESTIGATOR_PLAN, ROUTE_EXTRAPOLATE, API_MODEL_ENRICH)
}
