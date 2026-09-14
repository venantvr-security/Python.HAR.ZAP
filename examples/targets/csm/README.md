# CSM — cible API délibérément vulnérable

⚠️ **Délibérément vulnérable. À NE LANCER QU'EN LOCAL, jamais exposée sur un
réseau accessible.** Sert de mode adversarial à HAR-ZAP (usage défensif/éducatif,
cf. `CLAUDE.md`).

Petite API SaaS de « Customer Success » (comptes, utilisateurs, tickets,
factures, webhooks), **100 % bibliothèque standard** (aucune dépendance) — image
Alpine ~90 Mo, état en mémoire (redémarrage = neuf).

```bash
./examples/targets/csm.sh              # build + run + scénarios, puis nettoie
KEEP=1 ./examples/targets/csm.sh       # laisse le conteneur debout
```

Comptes seedés : `alice/alice123` · `bob/bob123` · `carol/carol123` (manager) · `admin/admin123`.

## Vulnérabilités (scénarisées)

| # | Faille | OWASP | Endpoint |
|---|--------|-------|----------|
| BOLA | lecture transverse d'objets d'autrui | API1 | `/users/{id}`, `/accounts/{id}`, `/tickets/{id}`, `/invoices/{id}` |
| Mass assignment | `PATCH /me` sans liste blanche → `role=admin` | API3 | `/me` |
| BFLA | `manager` ou jeton de service passent pour admin | API5 | `/admin/users` |
| SSRF | requête serveur vers URL fournie | API7 | `/webhooks/test` |
| JWT alg=none | signature non vérifiée, pas d'`exp` | API2 | tout endpoint authentifié |
| Business-flow | remboursement sans plafond ni idempotence | API6 | `/invoices/{id}/refund` |
| Exposition/shadow | secret + jeton de service divulgués | API9 | `/debug/config` |

## Chaînes (rebonds)

- **A. SSRF → interne → admin** : `POST /webhooks/test {url:"http://localhost:5000/internal/metadata"}`
  fuit le `service_token` (l'endpoint interne est filtré par IP source — seule une
  SSRF le satisfait) → `GET /admin/users -H "X-Service-Token: <token>"` dumpe tout.
- **B. Mass assignment → escalade** : login `alice` → `PATCH /me {role:"admin"}` →
  `/admin/users`.
- **C. BOLA → clé API → takeover** : `GET /users/4` fuit `AK-admin-999` →
  `GET /me -H "X-API-Key: AK-admin-999"` = contexte admin.
- **D. Business-flow** : `POST /invoices/1/refund {amount:99999}` répété → remboursé
  bien au-delà du montant payé.
- **E. JWT alg=none** : forger `{"alg":"none"}` `role=admin` → `/admin/users`.

## Ce que ça exerce dans HAR-ZAP

Confirmateur d'auth (alg=none **confirmé** par forge+rejeu), extrapolation de
routes (`/debug/config`, `/internal/metadata`), BOLA multi-sessions, matrice
d'accès (BFLA), sondes SSRF, business-flow. `/internal/metadata` renvoie 403 en
direct (accessible uniquement par SSRF) : bon test de faux positif.
