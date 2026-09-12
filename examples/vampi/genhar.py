#!/usr/bin/env python3
"""
Génère des HAR multi-rôles réels contre VAmPI, pour alimenter la matrice
d'accès (`cli.py matrix`).

Pourquoi un générateur dédié plutôt qu'un HAR figé : les jetons JWT de VAmPI
expirent en ~60 s. Un HAR enregistré une fois pour toutes contiendrait des
jetons morts et la matrice tournerait sans authentification (toutes les
requêtes authentifiées → 401). On (re)génère donc les HAR juste avant de
lancer la matrice, avec des jetons frais.

Chaque rôle reçoit un HAR décrivant SON trafic légitime : c'est cette
attribution qui fixe le « plancher de privilège » de chaque endpoint dans la
matrice. Un endpoint réellement public doit donc apparaître dans le HAR du
rôle le moins privilégié, sinon la matrice le croira réservé (faux positif).
"""
import json
import os
import sys

import requests

BASE = os.environ.get("VAMPI_URL", "http://localhost:5001")
OUT = sys.argv[1] if len(sys.argv) > 1 else "/tmp/har"


def login(username: str, password: str) -> str:
    r = requests.post(f"{BASE}/users/v1/login",
                      json={"username": username, "password": password}, timeout=8)
    r.raise_for_status()
    return r.json()["auth_token"]


def entry(method: str, url: str, headers=None, body=None) -> dict:
    """Exécute la requête et l'emballe au format HAR (request + response réels)."""
    headers = dict(headers or {})
    kw = {"timeout": 8, "allow_redirects": False}
    if body is not None:
        headers.setdefault("Content-Type", "application/json")
        kw["data"] = json.dumps(body)
    r = requests.request(method, url, headers=headers, **kw)
    e = {
        "startedDateTime": "2026-01-01T00:00:00.000Z", "time": 1,
        "request": {
            "method": method, "url": url, "httpVersion": "HTTP/1.1",
            "headers": [{"name": k, "value": v} for k, v in headers.items()],
            "queryString": [], "cookies": [], "headersSize": -1,
            "bodySize": len(json.dumps(body)) if body else 0,
        },
        "response": {
            "status": r.status_code, "statusText": r.reason, "httpVersion": "HTTP/1.1",
            "headers": [{"name": k, "value": v} for k, v in r.headers.items()],
            "cookies": [], "redirectURL": "", "headersSize": -1, "bodySize": len(r.content),
            "content": {"size": len(r.content),
                        "mimeType": r.headers.get("Content-Type", "application/json"),
                        "text": r.text[:2000]},
        },
        "cache": {}, "timings": {"send": 0, "wait": 1, "receive": 0},
    }
    if body is not None:
        e["request"]["postData"] = {"mimeType": "application/json", "text": json.dumps(body)}
    return e


def har(entries: list) -> dict:
    return {"log": {"version": "1.2", "creator": {"name": "vampi-genhar", "version": "1"},
                    "entries": entries}}


def book_owned_by(owner: str) -> str:
    """Retrouve dynamiquement un titre de livre appartenant à `owner`.

    `/createdb` de VAmPI attribue des titres ALÉATOIRES à chaque appel : coder
    les titres en dur donnerait des 404. On lit donc `/books/v1`, qui expose le
    propriétaire de chaque livre, et on choisit un titre réel.
    """
    books = requests.get(f"{BASE}/books/v1", timeout=8).json().get("Books", [])
    for b in books:
        if b.get("user") == owner:
            return b["book_title"]
    raise RuntimeError(f"aucun livre trouvé pour '{owner}' (base peuplée ?)")


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    h_user = {"Authorization": f"Bearer {login('name1', 'pass1')}"}
    h_admin = {"Authorization": f"Bearer {login('admin', 'pass1')}"}

    user_book = book_owned_by("name1")    # livre du user normal
    admin_book = book_owned_by("admin")   # livre d'admin -> cible du BOLA

    # Rôle « user » : un utilisateur normal (name1) consulte des ressources,
    # dont son PROPRE livre.
    user_entries = [
        entry("GET", f"{BASE}/users/v1"),
        entry("GET", f"{BASE}/books/v1", h_user),
        entry("GET", f"{BASE}/books/v1/{user_book}", h_user),
    ]
    # Rôle « admin » : trafic d'administration touchant des endpoints sensibles
    # (dump de tous les utilisateurs, livre appartenant à admin). Le livre
    # d'admin, atteint plus tard par le rôle user, révèle le BOLA.
    admin_entries = [
        entry("GET", f"{BASE}/users/v1"),
        entry("GET", f"{BASE}/books/v1", h_admin),
        entry("GET", f"{BASE}/users/v1/_debug", h_admin),
        entry("GET", f"{BASE}/books/v1/{admin_book}", h_admin),
    ]

    json.dump(har(user_entries), open(f"{OUT}/user.har", "w"), indent=2)
    json.dump(har(admin_entries), open(f"{OUT}/admin.har", "w"), indent=2)
    print(f"HARs écrits dans {OUT}/ (user.har, admin.har) — jetons frais (~60 s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
