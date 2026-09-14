# Cibles Docker vulnérables

Launchers prêts à l'emploi pour des applications/API **délibérément vulnérables**,
afin de valider HAR-ZAP en conditions réelles. Chaque script démarre la cible,
attend qu'elle réponde, affiche l'URL de base et une commande de scan suggérée,
puis nettoie en sortie (sauf `KEEP=1`).

```bash
./examples/targets/vampi.sh              # démarre, affiche, attend, nettoie
KEEP=1 ./examples/targets/juiceshop.sh   # laisse le conteneur debout
PORT=3001 ./examples/targets/juiceshop.sh
```

## Catalogue

| Script | Image | Port | Type | Ce que ça exerce dans HAR-ZAP |
|--------|-------|------|------|-------------------------------|
| `vampi.sh` | `erev0s/vampi` | 5001 | API REST | matrice d'accès, BOLA, mass assignment, forge auth (API1/2/3/5) |
| `juiceshop.sh` | `bkimminich/juice-shop` | 3000 | Web + REST | extrapolation de routes, JWT, BOLA (paniers/avis) |
| `dvga.sh` | `dolevf/dvga` | 5013 | GraphQL | module `graphql` (introspection, batching, profondeur) |
| `csm.sh` | build local (`csm/`) | 5005 | API REST | **chaînes** : SSRF→interne→admin, BOLA→clé API→takeover, mass assignment, JWT alg=none, business-flow, shadow |
| `crapi.sh` | `OWASP/crAPI` (compose) | 8888 | Plateforme API | tout l'OWASP API Top 10 ; **lourde** (~8 services) |

Les trois premières sont des **conteneurs uniques** vérifiés bootables ; `crapi.sh`
utilise le `docker compose` officiel upstream (plusieurs Go, plusieurs minutes).

## `lib.sh`

Helpers partagés : `need_docker`, `wait_http URL [regex] [essais] [pause]`,
`on_cleanup CMD` (nettoyage LIFO en sortie), gestion de `KEEP`.

## Rappel éthique

Ces cibles sont volontairement vulnérables : à ne lancer qu'en local, jamais
exposées sur un réseau accessible. Voir `CLAUDE.md` (sécurité offensive responsable).
