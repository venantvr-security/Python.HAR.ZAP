#!/usr/bin/env bash
# Damn Vulnerable GraphQL Application (DVGA) — API GraphQL vulnérable
# (introspection, injection, DoS par batching/profondeur). Pour le module
# GraphQL du scanner (`cli.py graphql`).
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$HERE/lib.sh"
NAME=${NAME:-dvga}; PORT=${PORT:-5013}
need_docker
log "DVGA (dolevf/dvga)"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:5013" -e WEB_HOST=0.0.0.0 dolevf/dvga:latest >/dev/null
on_cleanup "docker rm -f $NAME >/dev/null 2>&1"
wait_http "http://localhost:${PORT}/" '^200$' 30 2 || exit 1
BASE="http://localhost:${PORT}"
log "Prêt"
info "Base URL : $BASE   ·   GraphQL : $BASE/graphql"
cat <<TIP

Introspection (souvent laissée ouverte = fuite de schéma) :
  curl -s $BASE/graphql -H 'Content-Type: application/json' \\
    -d '{"query":"{__schema{types{name}}}"}'
Scan : enregistre des requêtes GraphQL en HAR, puis
  python cli.py graphql trafic.har --introspection --batch-test --depth-test
TIP
[ "${KEEP:-0}" = "1" ] || read -rp $'\nEntrée pour arrêter... ' _ || true
