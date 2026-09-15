# CMS — cible API délibérément vulnérable

⚠️ **Délibérément vulnérable. À NE LANCER QU'EN LOCAL, jamais exposée sur un
réseau accessible.** Sert de mode adversarial à HAR-ZAP (usage défensif/éducatif,
cf. `CLAUDE.md`).

Fausse application de **gestion de contenu** (articles brouillon/publié, pages,
médias, commentaires, rôles éditoriaux `subscriber < author < editor < admin`),
**100 % bibliothèque standard** (aucune dépendance) — image Alpine ~90 Mo, état
en mémoire (redémarrage = neuf).

```bash
./examples/targets/cms.sh              # build + run + scénarios, puis nettoie
KEEP=1 ./examples/targets/cms.sh       # laisse le conteneur debout
```

Comptes seedés : `alice/alice123` (author) · `bob/bob123` (author) · `carol/carol123` (editor) · `admin/admin123` (admin).

## Vulnérabilités

Deux familles cohabitent volontairement.

### Déjà investiguées par HAR-ZAP (vérifier qu'il confirme)

| Faille | OWASP | Endpoint |
|--------|-------|----------|
| BOLA | API1 | `/users/{id}`, `/articles/{id}` (brouillon + `secret_notes` d'autrui) |
| Excessive data exposure | API1/3 | `GET /articles?status=draft` (brouillons de tous les auteurs) |
| Mass assignment | API3 | `PATCH /me`, `POST /auth/register`, `POST /articles` (`role`/`author_id`/`status`) |
| BFLA | API5 | `/admin/users`, `DELETE /articles/{id}`, `/export/subscribers.csv` |
| Business-flow | API6 | `POST /articles/{id}/publish` (publication sans revue éditoriale) |
| SSRF | API7 | `POST /media/fetch` |
| JWT alg=none | API2 | tout endpoint authentifié |
| Exposition/shadow | API9 | `/debug/config`, `/actuator/env` |

### Classes web (désormais couvertes par `diagnose --web`)

Historiquement des angles morts DAST ; un moteur dédié (`modules/web_probes.py`)
les prouve maintenant par marqueur (path traversal, SSTI, XSS réfléchi/stocké,
open redirect, reset prédictible, injection CSV).

| Faille | Endpoint | Preuve |
|--------|----------|--------|
| Path traversal / LFI | `GET /media/raw?path=` | `?path=../../etc/passwd` |
| SSTI (format string) | `POST /preview` | `{"template":"{config[secret_key]}"}` |
| XSS réfléchi | `GET /search?q=` | `?q=<script>alert(1)</script>` |
| XSS stocké | commentaire → `GET /articles/{id}/render` | corps `<script>…</script>` |
| Open redirect | `GET /go?to=` | `?to=https://evil.example` |
| Jeton de reset prédictible | `/auth/reset-request` → `/auth/reset-confirm` | `token = md5(username)[:8]` |
| CORS permissif | tout endpoint | `Origin` reflété + `Allow-Credentials: true` |
| Injection de formule CSV | `GET /export/subscribers.csv` | pseudo commençant par `=`/`+`/`-`/`@` |
| SQLi (simulée) | `GET /articles/search?q=` | `q=%27` (erreur), `' OR '1'='1` (booléen), `SLEEP(5)` (time-based) |
| NoSQLi (simulée) | `POST /articles/query` | `{"title":{"$ne":null}}` (opérateur), `{"$where":"sleep(5000)"}` (time-based) |

## Chaînes (rebonds)

- **A. SSRF → interne → admin** : `POST /media/fetch {url:"http://localhost:5000/internal/metadata"}`
  fuit le `service_token` (endpoint filtré par IP source — seule une SSRF le satisfait)
  → `GET /admin/users -H "X-Service-Token: <token>"` dumpe tout.
- **B. Mass assignment → escalade** : login `alice` → `PATCH /me {role:"admin"}` → `/admin/users`.
- **C. BOLA → clé API → takeover** : `GET /users/4` fuit `AK-admin-999` →
  `GET /me -H "X-API-Key: AK-admin-999"` = contexte admin.
- **D. JWT alg=none** : forger `{"alg":"none"}` `role=admin` → `/admin/users`.
- **E. Reset prédictible → takeover** : `token=md5("admin")[:8]` → `POST /auth/reset-confirm
  {username:"admin", token, new_password:"x"}` → login admin.
- **F. SSTI → secret → JWT signé** : `/preview {template:"{config[secret_key]}"}` révèle
  `SECRET` → forger un HS256 valide `role=admin` (au-delà d'alg=none).
- **G. Path traversal → code/secret** : `GET /media/raw?path=../app.py` lit la source (donc
  le `SECRET` en dur), ou `../../etc/passwd`.
- **H. Business-flow** : `POST /articles/2/publish` publie le brouillon embargo sans éditeur.
- **I. XSS stocké** : commentaire `<script>` sur un article → exécuté au `/render`.

## Ce que ça exerce dans HAR-ZAP

Confirmateur d'auth (alg=none **confirmé** par forge+rejeu), extrapolation de
routes (`/debug/config`, `/actuator/env`, `/internal/metadata`), BOLA
multi-sessions, matrice d'accès (BFLA), sondes SSRF (query **et** corps JSON),
business-flow (transition `publish` confirmée par readback), et les sondes web
(`--web` : path traversal, SSTI, XSS réfléchi/stocké, open redirect, reset
prédictible, CSV). `/internal/metadata` renvoie 403 en direct (accessible
uniquement par SSRF) : bon test de faux positif.
