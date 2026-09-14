#!/usr/bin/env bash
# Helpers partagés pour lancer des cibles Docker délibérément vulnérables.
# Sourcé par chaque launcher examples/targets/<image>.sh.
#
# Convention : chaque launcher démarre sa cible, attend qu'elle réponde, affiche
# l'URL de base + une commande de scan suggérée, puis nettoie en sortie — sauf
# KEEP=1 (garde les conteneurs debout pour lancer le scan à la main).
set -euo pipefail

_KEEP=${KEEP:-0}
_CLEANUP_CMDS=()

log()  { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
info() { printf '\033[0;32m%s\033[0m\n' "$*"; }
warn() { printf '\033[0;33m%s\033[0m\n' "$*" >&2; }

need_docker() {
  command -v docker >/dev/null || { warn "docker introuvable"; exit 1; }
  docker info >/dev/null 2>&1 || { warn "daemon docker injoignable"; exit 1; }
}

# Enregistre une commande de nettoyage (exécutée à la sortie sauf KEEP=1).
on_cleanup() { _CLEANUP_CMDS+=("$*"); }

_run_cleanup() {
  if [ "$_KEEP" = "1" ]; then
    log "KEEP=1 — conteneurs laissés debout ; arrête-les toi-même quand tu as fini"
    return
  fi
  log "Nettoyage"
  for ((i=${#_CLEANUP_CMDS[@]}-1; i>=0; i--)); do eval "${_CLEANUP_CMDS[$i]}" || true; done
}
trap _run_cleanup EXIT

# wait_http URL [expected_regex] [tries] [sleep]
# Attend que URL renvoie un code HTTP matchant expected_regex (défaut : 2xx/3xx/401/403).
wait_http() {
  local url="$1" want="${2:-^(2..|3..|401|403)$}" tries="${3:-40}" nap="${4:-3}"
  for ((i=1; i<=tries; i++)); do
    local code
    code=$(curl -sS -m4 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo 000)
    if [[ "$code" =~ $want ]]; then info "  ready: $url -> $code"; return 0; fi
    sleep "$nap"
  done
  warn "  timeout: $url n'a pas répondu ($want)"; return 1
}
