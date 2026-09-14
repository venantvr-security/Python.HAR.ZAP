#!/usr/bin/env bash
# VAmPI — API REST délibérément vulnérable (OWASP API Top 10 : BOLA, mass
# assignment, exposition de données, auth cassée). Idéal pour `cli.py matrix`
# et les moteurs d'investigation.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$HERE/lib.sh"
NAME=${NAME:-vampi}; PORT=${PORT:-5001}
need_docker
log "VAmPI (erev0s/vampi)"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:5000" erev0s/vampi:latest >/dev/null
on_cleanup "docker rm -f $NAME >/dev/null 2>&1"
wait_http "http://localhost:${PORT}/" || exit 1
curl -sS -m8 "http://localhost:${PORT}/createdb" >/dev/null && info "  base peuplée (/createdb)"
BASE="http://localhost:${PORT}"
log "Prêt"
info "Base URL : $BASE"
cat <<TIP

Identifiants seedés : name1/pass1 · name2/pass2 · admin/pass1
Scan suggéré (matrice d'accès multi-rôles + BOLA) :
  ./examples/vampi/run_vampi_test.sh          # harnais complet clé en main
  # ou, manuellement, voir examples/vampi/genhar.py pour générer les HAR par rôle
TIP
[ "${KEEP:-0}" = "1" ] || read -rp $'\nEntrée pour arrêter... ' _ || true
