"""
Follow-up dirigé (Phase 4) — transformer un finding en action ciblée.

Un scan classique s'arrête au constat (« SSRF présente », « endpoint debug
joignable »). Un pentester, lui, ENCHAÎNE : il va chercher ce que la faille
donne. Ici on automatise ce rebond, de façon bornée et déterministe :

  - harvest_secrets : un endpoint « shadow » CONFIRMÉ (debug/config/actuator) est
    relu et on en extrait les secrets exposés -> escalade en finding Critical ;
  - directed_followups : recommandations d'actions ciblées (non exécutées) déduites
    des findings (SSRF -> pivot interne, fuite de clé -> rejeu privilégié, BOLA ->
    exfiltration) — surfacées dans le rapport pour l'opérateur.

Discipline : purement déterministe (aucune décision IA ; les preuves restent des
marqueurs). L'exécuteur est celui du transport partagé (session vivante ou auth
statique). Rien de destructif : on LIT ce qui fuit, on ne modifie pas.
"""
import re
from typing import Callable, Dict, List
from urllib.parse import urlparse

from ..utils import get_logger

logger = get_logger("llm.followup")

# Secret « clé: valeur » dans un corps de réponse (JSON ou texte).
_SECRET = re.compile(
    r'(secret[_-]?key|api[_-]?key|service[_-]?token|access[_-]?token|'
    r'client[_-]?secret|private[_-]?key|password)"?\s*[:=]\s*"?'
    r'([A-Za-z0-9._\-/+]{6,})', re.I)

_SHADOW_HINT = re.compile(r'(shadow|debug|/config|actuator|inventory|/env)', re.I)

# Valeurs manifestement NON secrètes (placeholders de schéma/doc) : écarte les FP
# du type {"password":"required"} ou {"secret":"string"}.
_PLACEHOLDERS = frozenset({
    'required', 'optional', 'true', 'false', 'null', 'none', 'string', 'number',
    'integer', 'boolean', 'object', 'array', 'example', 'changeme', 'redacted',
    'hidden', 'value', 'todo', 'xxx', 'yourkey', 'yourtoken', 'undefined'})


def _looks_secret(v: str) -> bool:
    """Un vrai secret a de l'entropie : au moins 8 caractères, et pas un simple
    mot minuscule / placeholder de schéma."""
    v = (v or '').strip()
    if len(v) < 8 or v.lower() in _PLACEHOLDERS:
        return False
    if re.fullmatch(r'[a-z]+', v):        # mot purement minuscule -> pas un secret
        return False
    return True


def harvest_secrets(findings: List[Dict], execute_fn: Callable) -> List[Dict]:
    """Relit les endpoints shadow CONFIRMÉS et escalade les secrets exposés."""
    out: List[Dict] = []
    seen = set()
    for f in findings:
        if f.get('status') != 'confirmed':
            continue
        name = (f.get('name') or '') + ' ' + (f.get('owasp') or '')
        if not _SHADOW_HINT.search(name):
            continue
        url = f.get('url')
        if not url or url in seen:
            continue
        seen.add(url)
        r = execute_fn(url, 'GET', None) or {}
        body = r.get('body', '') or ''
        for m in _SECRET.finditer(body):
            field, value = m.group(1), m.group(2)
            if not _looks_secret(value):        # écarte les valeurs placeholder (FP)
                continue
            out.append({
                'source': 'followup', 'risk': 'Critical', 'owasp': 'API8:2023',
                'name': f"Secret exposed via {urlparse(url).path}: {field}",
                'url': url, 'status': 'confirmed', 'adjudication': 'deterministic',
                'payload': ''})
            logger.info("followup_secret_harvested", path=urlparse(url).path, field=field)
    # dédup par nom
    uniq, names = [], set()
    for f in out:
        if f['name'] not in names:
            names.add(f['name'])
            uniq.append(f)
    return uniq


def directed_followups(findings: List[Dict]) -> List[Dict]:
    """Recommandations d'actions ciblées (non exécutées) déduites des findings."""
    recs: List[Dict] = []
    for f in findings:
        name = (f.get('name') or '').lower()
        src = (f.get('source') or '').lower()
        if 'ssrf' in name or 'ssrf' in src:
            recs.append({'trigger': f.get('name'),
                         'action': "Pivoter la SSRF vers les cibles internes "
                                   "(169.254.169.254, /internal/metadata) pour récolter des jetons"})
        if 'alg=none' in name or ('jwt' in name and 'bypass' in name):
            recs.append({'trigger': f.get('name'),
                         'action': "Forger un jeton role=admin et énumérer les fonctions privilégiées (BFLA)"})
        if 'bola' in src or 'bola' in name or 'object accessible' in name \
                or 'api_key' in name or 'access-control break' in name:
            recs.append({'trigger': f.get('name'),
                         'action': "Énumérer les identifiants d'objets et rejouer avec la clé/objet fuité"})
        if 'sql' in name and 'injection' in name:
            recs.append({'trigger': f.get('name'),
                         'action': "Extraire le schéma puis les données via UNION/booléen (dump borné)"})
    # dédup par ACTION (une action identique déclenchée par plusieurs findings ->
    # une seule recommandation, sur le premier déclencheur).
    uniq, seen = [], set()
    for r in recs:
        if r['action'] not in seen:
            seen.add(r['action'])
            uniq.append(r)
    return uniq


def run_followups(findings: List[Dict], execute_fn: Callable):
    """Exécute les follow-ups bornés + rend les recommandations. Retourne
    (nouveaux_findings, recommandations)."""
    harvested = harvest_secrets(findings, execute_fn)
    recs = directed_followups(findings + harvested)
    if harvested or recs:
        logger.info("followups_done", harvested=len(harvested), recommendations=len(recs))
    return harvested, recs
