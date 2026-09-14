#!/usr/bin/env bash
# OWASP Juice Shop — application vulnérable moderne (REST /api & /rest, JWT,
# BOLA sur les paniers/avis, injection). Surface API riche pour l'extrapolation
# de routes, le forge d'auth JWT et le BOLA.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$HERE/lib.sh"
NAME=${NAME:-juice}; PORT=${PORT:-3000}
need_docker
log "Juice Shop (bkimminich/juice-shop)"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:3000" bkimminich/juice-shop:latest >/dev/null
on_cleanup "docker rm -f $NAME >/dev/null 2>&1"
# /api/Products passe à 200 une fois la base initialisée.
wait_http "http://localhost:${PORT}/api/Products" '^200$' 45 3 || exit 1
BASE="http://localhost:${PORT}"
log "Prêt"
info "Base URL : $BASE"
cat <<TIP

Endpoints utiles :
  GET  $BASE/api/Products                 (liste publique)
  GET  $BASE/api/Users/1                  (BOLA — objet utilisateur)
  POST $BASE/rest/user/login             {email,password}  -> JWT
  POST $BASE/api/Users                    (register ; tenter role=admin — mass assignment)
Comptes : enregistre le tien via /api/Users, ou admin@juice-sh.op / admin123 (selon version).
Scan : enregistre le trafic (navigateur -> HAR) puis
  python cli.py diagnose trafic.har --target $BASE --no-docker --skip-zap --investigate
TIP
[ "${KEEP:-0}" = "1" ] || read -rp $'\nEntrée pour arrêter... ' _ || true
