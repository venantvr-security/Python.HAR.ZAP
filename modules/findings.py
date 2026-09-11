"""
Sortie « findings-first ».

Au lieu d'un dump multi-onglets de données brutes, une seule vue triée par
sévérité où chaque finding porte les 4 choses qu'un développeur veut : l'impact
(une phrase), la preuve rejouable (une commande curl), le correctif, et son
étiquette OWASP API. C'est ce qui fait qu'on croit un finding et qu'on le corrige.

Unifie les findings « à plat » de diagnose et les findings adaptatifs à forte
valeur (IDOR/API1, mass-assignment/API3, hidden-params/API5).
"""
import json
import html as _html
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

_SEV_RANK = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4, 'Informational': 4}
_SEV_NORM = {'CRITICAL': 'Critical', 'HIGH': 'High', 'MEDIUM': 'Medium',
             'LOW': 'Low', 'INFO': 'Info', 'INFORMATIONAL': 'Info'}

# Base de connaissance par vecteur : (tag OWASP, impact, correctif).
_KB = {
    'idor': ('API1:2023 BOLA',
             "Cross-tenant access — a user can read or modify another user's object.",
             "Enforce per-request object ownership; use unpredictable ids."),
    'mass_assignment': ('API3:2023 BOPLA',
             "Privilege escalation — the API binds unexpected request properties.",
             "Allowlist writable fields; reject unknown properties."),
    'hidden_params': ('API5:2023 BFLA',
             "A hidden debug/admin parameter changes server behavior.",
             "Remove debug switches in prod; enforce function-level authorization."),
    'jwt': ('API2:2023 Broken Authentication',
             "Token forgery or account takeover via weak JWT handling.",
             "Validate signature/alg/exp; reject alg=none."),
    'cors': ('API8:2023 Security Misconfiguration',
             "Cross-origin data theft from an over-permissive CORS policy.",
             "Restrict origins; never wildcard with credentials."),
    'cache': ('API8:2023 Security Misconfiguration',
             "Cache poisoning — an unkeyed input is reflected from cache.",
             "Vary on all inputs; validate cache keys."),
    'smuggling': ('API8:2023 Security Misconfiguration',
             "HTTP request smuggling via ambiguous message framing.",
             "Normalize/deny conflicting Content-Length/Transfer-Encoding."),
    'passive': ('API8:2023 Security Misconfiguration',
             "Missing hardening (security headers, cookies).",
             "Set HSTS/CSP/X-Content-Type-Options; secure cookies."),
}
_REDTEAM_MAP = [('unauth', 'jwt'), ('mass', 'mass_assignment'),
                ('hidden', 'hidden_params'), ('auth', 'jwt')]


@dataclass
class Finding:
    severity: str
    title: str
    vector: str
    endpoint: str
    owasp: str = ''
    impact: str = ''
    fix: str = ''
    proof: str = ''
    method: str = 'GET'
    confidence: Optional[float] = None

    def to_dict(self) -> Dict:
        return {k: getattr(self, k) for k in
                ('severity', 'title', 'vector', 'endpoint', 'owasp',
                 'impact', 'fix', 'proof', 'method', 'confidence')}


def curl_for(method: str, url: str, body: Optional[Dict] = None, auth: bool = True) -> str:
    """Commande curl rejouable. `auth` ajoute un en-tête token à remplacer."""
    parts = ['curl -i -s']
    if method and method.upper() != 'GET':
        parts.append(f'-X {method.upper()}')
    if auth:
        parts.append("-H 'Authorization: <your-token>'")
    if body:
        parts.append("-H 'Content-Type: application/json'")
        parts.append(f"-d '{json.dumps(body)}'")
    parts.append(f"'{url}'")
    return ' '.join(parts)


def _kb(key: str):
    return _KB.get(key, ('', 'Potential security weakness detected by the scanner.',
                         'Review the affected endpoint against OWASP guidance.'))


def _with_query(url: str, name: str, value: str) -> str:
    p = urlparse(url)
    q = parse_qs(p.query)
    q[name] = [value]
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(q, doseq=True), p.fragment))


def build_findings(all_findings: List[Dict], adaptive_result=None, target: str = '') -> List[Finding]:
    out: List[Finding] = []

    # 1) Findings adaptatifs (les plus riches : vraie preuve, forte valeur).
    if adaptive_result is not None:
        for f in getattr(adaptive_result, 'idor', []) or []:
            if not getattr(f, 'vulnerable', False):
                continue
            url = getattr(getattr(f, 'observation', None), 'url', '') or f.target_url
            owasp, impact, fix = _kb('idor')
            out.append(Finding('High', f"BOLA — object accessible across users",
                               'idor', url, owasp, impact, fix,
                               curl_for('GET', url), 'GET',
                               getattr(getattr(f, 'verdict', None), 'confidence', None)))
        for f in getattr(adaptive_result, 'mass_assignment', []) or []:
            for e in getattr(f, 'accepted_fields', []) or []:
                owasp, impact, fix = _kb('mass_assignment')
                body = {e.get('field'): e.get('value')}
                out.append(Finding('High', f"Mass assignment — '{e.get('field')}' accepted",
                                   'mass_assignment', f.target_url, owasp, impact, fix,
                                   curl_for('PATCH', f.target_url, body), 'PATCH'))
        for f in getattr(adaptive_result, 'hidden_params', []) or []:
            for e in getattr(f, 'active_params', []) or []:
                owasp, impact, fix = _kb('hidden_params')
                url = _with_query(f.target_url, e.get('name', ''), e.get('value', '1'))
                out.append(Finding('Medium', f"Hidden parameter active — '{e.get('name')}'",
                                   'hidden_params', url, owasp, impact, fix,
                                   curl_for('GET', url), 'GET'))

    # 2) Findings « à plat » de diagnose.
    for f in all_findings or []:
        source = f.get('source', 'finding')
        key = source
        if source == 'redteam':
            low = str(f.get('name', '')).lower()
            key = next((v for kw, v in _REDTEAM_MAP if kw in low), 'passive')
        owasp, impact, fix = _kb(key)
        sev = _SEV_NORM.get(str(f.get('risk', 'Low')).upper(), 'Low')
        url = f.get('url', target)
        out.append(Finding(sev, f.get('name', 'Finding'), source, url,
                           owasp, impact, fix, curl_for('GET', url, auth=False), 'GET'))

    out.sort(key=lambda x: (_SEV_RANK.get(x.severity, 5), x.vector, x.title))
    return out


def render_cli(findings: List[Finding]) -> str:
    if not findings:
        return "\nFINDINGS: none.\n"
    lines = [f"\n{'='*64}", f"FINDINGS ({len(findings)}) — severity-sorted", '='*64]
    for f in findings:
        tag = f"  {f.owasp}" if f.owasp else ""
        lines.append(f"\n[{f.severity.upper():<8}] {f.title}{tag}")
        lines.append(f"  endpoint  {f.method} {f.endpoint}")
        lines.append(f"  impact    {f.impact}")
        lines.append(f"  proof     {f.proof}")
        lines.append(f"  fix       {f.fix}")
    return '\n'.join(lines) + '\n'


_SEV_COLOR = {'Critical': '#A8321A', 'High': '#C8461E', 'Medium': '#9A6B12',
              'Low': '#2C7A70', 'Info': '#6A6E76'}


def render_html(findings: List[Finding], meta: Optional[Dict] = None) -> str:
    meta = meta or {}
    counts = {s: sum(1 for f in findings if f.severity == s)
              for s in ('Critical', 'High', 'Medium', 'Low', 'Info')}
    e = _html.escape
    cards = []
    for f in findings:
        col = _SEV_COLOR.get(f.severity, '#6A6E76')
        owasp = f'<span class="owasp">{e(f.owasp)}</span>' if f.owasp else ''
        cards.append(f"""
      <article class="card" style="--sev:{col}">
        <div class="chead">
          <span class="sev">{e(f.severity)}</span>
          <h3>{e(f.title)}</h3>{owasp}
        </div>
        <div class="ep"><span>{e(f.method)}</span> {e(f.endpoint)}</div>
        <p class="impact">{e(f.impact)}</p>
        <div class="label">Proof</div><pre class="proof">{e(f.proof)}</pre>
        <div class="label">Fix</div><p class="fix">{e(f.fix)}</p>
      </article>""")
    tiles = ''.join(
        f'<div class="tile" style="--c:{_SEV_COLOR[s]}"><b>{counts[s]}</b><span>{s}</span></div>'
        for s in ('Critical', 'High', 'Medium', 'Low', 'Info'))
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Findings — {e(str(meta.get('target', 'HAR-ZAP')))}</title>
<style>
:root{{--bg:#F4F2EE;--surface:#FBFAF8;--ink:#1B1A17;--muted:#726C61;--line:#E1DCD2;--accent:#C8461E}}
@media(prefers-color-scheme:dark){{:root{{--bg:#141310;--surface:#1C1B16;--ink:#EDE9E0;--muted:#A39A88;--line:#2E2B22;--accent:#E8643A}}}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:860px;margin:0 auto;padding:32px 20px 56px}}
h1{{font-size:1.5rem;margin:0 0 4px}} .sub{{color:var(--muted);font-size:.9rem;margin-bottom:20px}}
.tiles{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:26px}}
.tile{{flex:1;min-width:96px;border:1px solid var(--line);border-left:4px solid var(--c);border-radius:10px;padding:12px 14px;background:var(--surface)}}
.tile b{{font-size:1.6rem;display:block;font-variant-numeric:tabular-nums}} .tile span{{color:var(--muted);font-size:.8rem}}
.card{{border:1px solid var(--line);border-left:5px solid var(--sev);border-radius:12px;background:var(--surface);padding:18px;margin-bottom:14px}}
.chead{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
.chead h3{{margin:0;font-size:1.05rem;flex:1;min-width:200px}}
.sev{{font-size:.7rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:#fff;background:var(--sev);padding:3px 8px;border-radius:999px}}
.owasp{{font-family:ui-monospace,monospace;font-size:.72rem;color:var(--muted);border:1px solid var(--line);border-radius:6px;padding:2px 7px}}
.ep{{font-family:ui-monospace,monospace;font-size:.82rem;color:var(--muted);margin:10px 0}} .ep span{{color:var(--accent);font-weight:600}}
.impact{{margin:8px 0 12px}}
.label{{font-size:.68rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:4px}}
.proof{{font-family:ui-monospace,monospace;font-size:.78rem;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px 12px;overflow-x:auto;margin:0 0 12px}}
.fix{{margin:0}}
</style></head><body><div class="wrap">
<h1>Findings — {e(str(meta.get('target', '')))}</h1>
<p class="sub">{len(findings)} findings · {e(str(meta.get('har_file', '')))} · generated by HAR-ZAP</p>
<div class="tiles">{tiles}</div>
{''.join(cards) if cards else '<p>No findings.</p>'}
</div></body></html>"""
