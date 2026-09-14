#!/usr/bin/env bash
# crAPI (completely ridiculous API) — plateforme OWASP de pentest d'API la plus
# complète (BOLA, mass assignment, JWT, SSRF, exposition de données, flux métier).
# LOURDE : ~8 services via docker compose (Postgres, Mongo, MailHog, etc.).
# Non bootée par les tests légers ; utilise le compose officiel upstream.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$HERE/lib.sh"
need_docker
command -v docker >/dev/null && docker compose version >/dev/null 2>&1 || {
  warn "docker compose requis"; exit 1; }
COMPOSE_URL=${COMPOSE_URL:-https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/docker-compose.yml}
WORK=${WORK:-/tmp/crapi}; mkdir -p "$WORK"
log "crAPI (OWASP/crAPI) — téléchargement du compose"
curl -sS -m30 -o "$WORK/docker-compose.yml" "$COMPOSE_URL" || { warn "téléchargement du compose échoué"; exit 1; }
log "Démarrage (peut prendre plusieurs minutes / télécharger plusieurs Go)"
( cd "$WORK" && docker compose pull -q && docker compose up -d )
on_cleanup "( cd $WORK && docker compose down -v )"
# L'UI web écoute en général sur 8888.
wait_http "http://localhost:8888/" '^(2..|3..)$' 60 5 || warn "  crAPI met du temps à démarrer ; réessaie l'URL"
log "Prêt (voir la doc crAPI pour les identifiants et le flux d'inscription)"
info "Web UI : http://localhost:8888   ·   API sous /identity, /workshop, /community"
cat <<TIP

crAPI expose un OpenAPI — pratique pour le diff shadow-endpoints (API9) :
  python cli.py diagnose trafic.har --target http://localhost:8888 \\
    --no-docker --skip-zap --openapi <openapi.json> --investigate
TIP
[ "${KEEP:-0}" = "1" ] || read -rp $'\nEntrée pour arrêter (docker compose down -v)... ' _ || true
