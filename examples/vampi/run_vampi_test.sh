#!/usr/bin/env bash
#
# Test terrain reproductible : HAR-ZAP contre une API délibérément vulnérable.
# ---------------------------------------------------------------------------
# Ce script monte tout ce qu'il faut, joue la matrice d'accès multi-rôles, puis
# nettoie. Il sert de test d'intégration « bout-en-bout » et de démonstration.
#
# Cible : VAmPI (https://github.com/erev0s/VAmPI), une API REST volontairement
# vulnérable (BOLA, mass assignment, exposition de données). Terrain idéal pour
# les moteurs OWASP API Top 10 de HAR-ZAP.
#
# Flux :
#   VAmPI (conteneur) ─┐
#                      ├── réseau Docker commun ── ZAP (conteneur, sendRequest)
#   HAR-ZAP (hôte) ────┘        (ZAP doit joindre la cible par son nom)
#
# Prérequis : docker, python3 + le venv/déps du projet (requests, zapv2…).
# Usage :
#   ./examples/vampi/run_vampi_test.sh          # monte, teste, démonte
#   KEEP=1 ./examples/vampi/run_vampi_test.sh   # laisse les conteneurs debout
#   VIA_ZAP=1 ./...                             # route la matrice à travers ZAP
#
set -euo pipefail

# --- Paramètres (surchargeables par variables d'environnement) ---------------
NET=${NET:-harzap-vampi-net}
VAMPI_NAME=${VAMPI_NAME:-vampi}
ZAP_NAME=${ZAP_NAME:-zap}
VAMPI_PORT=${VAMPI_PORT:-5001}     # port hôte -> 5000 dans le conteneur
ZAP_PORT=${ZAP_PORT:-8080}
VAMPI_IMAGE=${VAMPI_IMAGE:-erev0s/vampi:latest}
ZAP_IMAGE=${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}
HAR_DIR=${HAR_DIR:-/tmp/vampi-har}
OUT_DIR=${OUT_DIR:-/tmp/vampi-out}
KEEP=${KEEP:-0}
VIA_ZAP=${VIA_ZAP:-0}

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
ZAP_KEY="$(python3 -c 'import secrets;print(secrets.token_hex(16))')"

log() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }

cleanup() {
  if [ "$KEEP" = "1" ]; then
    log "KEEP=1 — conteneurs laissés debout ($VAMPI_NAME, $ZAP_NAME)"
    return
  fi
  log "Nettoyage"
  docker rm -f "$ZAP_NAME" "$VAMPI_NAME" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- Vérifs -----------------------------------------------------------------
command -v docker >/dev/null || { echo "docker introuvable"; exit 1; }
docker info >/dev/null 2>&1 || { echo "daemon docker injoignable"; exit 1; }

# --- 1. Réseau + cible vulnérable -------------------------------------------
log "Réseau Docker"
docker network create "$NET" >/dev/null 2>&1 || true

log "Démarrage VAmPI ($VAMPI_IMAGE)"
docker rm -f "$VAMPI_NAME" >/dev/null 2>&1 || true
docker run -d --name "$VAMPI_NAME" --network "$NET" \
  -p "127.0.0.1:${VAMPI_PORT}:5000" "$VAMPI_IMAGE" >/dev/null

log "Attente de VAmPI"
for i in $(seq 1 30); do
  curl -sS -m 4 "http://localhost:${VAMPI_PORT}/" >/dev/null 2>&1 && break
  sleep 2
done
# VAmPI démarre avec une base vide : /createdb la peuple (users, books, secrets).
curl -sS -m 8 "http://localhost:${VAMPI_PORT}/createdb" >/dev/null
echo "VAmPI prête, base peuplée."

# --- 2. ZAP en démon --------------------------------------------------------
log "Démarrage ZAP ($ZAP_IMAGE)"
docker rm -f "$ZAP_NAME" >/dev/null 2>&1 || true
docker run -d --name "$ZAP_NAME" --network "$NET" \
  -p "127.0.0.1:${ZAP_PORT}:${ZAP_PORT}" "$ZAP_IMAGE" \
  zap.sh -daemon -host 0.0.0.0 -port "$ZAP_PORT" -config api.key="$ZAP_KEY" \
  -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true >/dev/null

log "Attente de l'API ZAP"
for i in $(seq 1 40); do
  curl -sS -m 4 "http://localhost:${ZAP_PORT}/JSON/core/view/version/?apikey=${ZAP_KEY}" >/dev/null 2>&1 && break
  sleep 3
done
curl -sS -m 6 "http://localhost:${ZAP_PORT}/JSON/core/view/version/?apikey=${ZAP_KEY}" || true
echo

# --- 3. HAR multi-rôles (jetons frais) --------------------------------------
log "Génération des HAR multi-rôles"
VAMPI_URL="http://localhost:${VAMPI_PORT}" python3 "$HERE/genhar.py" "$HAR_DIR"

# --- 4. Matrice d'accès (le chemin produit) ---------------------------------
# On enchaîne immédiatement : les jetons expirent en ~60 s.
log "Matrice d'accès multi-rôles (anon + user + admin)"
cd "$ROOT"
MTX_ARGS=(--role "user=${HAR_DIR}/user.har" --role "admin=${HAR_DIR}/admin.har"
          --anon --workers 6 --output "$OUT_DIR")
if [ "$VIA_ZAP" = "1" ]; then
  # Via ZAP : la cible doit être joignable PAR ZAP -> nom de conteneur.
  # (Régénère alors les HAR avec VAMPI_URL=http://${VAMPI_NAME}:5000.)
  MTX_ARGS+=(--via-zap --zap-url "http://localhost:${ZAP_PORT}" --api-key "$ZAP_KEY")
fi
python3 cli.py matrix "${MTX_ARGS[@]}"

log "Terminé"
echo "Rapports : ${OUT_DIR}/access_matrix.{json,html}"
echo
echo "Lecture des résultats (vérité terrain VAmPI) :"
echo "  VRAIS positifs attendus :"
echo "    - anon atteint /users/v1/_debug (dump users + mots de passe)"
echo "    - user atteint /users/v1/_debug"
echo "    - user atteint le livre d'admin /books/v1/<titre> — BOLA"
echo "  FAUX positifs attendus (endpoints publics vus seulement dans un HAR authentifié) :"
echo "    - anon atteint /users/v1 et /books/v1"
echo "  -> Pour les supprimer : fournir aussi un HAR anonyme de référence"
echo "     couvrant les endpoints réellement publics (plancher = anon)."
