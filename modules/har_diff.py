"""
HAR diff — compare two HAR captures (typically user A vs user B) to surface
the endpoints and parameters that one user touched but not the other.

Typical use:
    diff = diff_hars(alice_har, admin_har)
    # → endpoints only admin reached (likely privileged), params only admin sent,
    #   status codes differing per endpoint, candidate IDOR targets

This is the data-prep layer for IDOR / privilege-escalation testing.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Set, Tuple
from urllib.parse import parse_qs, urlparse


@dataclass
class HarDiff:
    only_in_a: Set[str] = field(default_factory=set)
    only_in_b: Set[str] = field(default_factory=set)
    shared: Set[str] = field(default_factory=set)
    status_deltas: List[Dict[str, Any]] = field(default_factory=list)
    param_deltas: List[Dict[str, Any]] = field(default_factory=list)
    idor_candidates: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "only_in_a": sorted(self.only_in_a),
            "only_in_b": sorted(self.only_in_b),
            "shared": sorted(self.shared),
            "status_deltas": self.status_deltas,
            "param_deltas": self.param_deltas,
            "idor_candidates": self.idor_candidates,
            "summary": {
                "only_a": len(self.only_in_a),
                "only_b": len(self.only_in_b),
                "shared": len(self.shared),
                "status_deltas": len(self.status_deltas),
                "idor_candidates": len(self.idor_candidates),
            },
        }


def _entries(har: Dict[str, Any]) -> List[Dict[str, Any]]:
    return (har or {}).get("log", {}).get("entries", [])


def _endpoint_key(entry: Dict[str, Any]) -> str:
    """Normalise an entry to METHOD + path (drop host and query)."""
    req = entry.get("request", {})
    url = req.get("url", "")
    path = urlparse(url).path or "/"
    return f"{req.get('method', 'GET')} {path}"


def _query_params(url: str) -> Set[str]:
    qs = urlparse(url).query
    return set(parse_qs(qs).keys())


def _post_params(entry: Dict[str, Any]) -> Set[str]:
    post = entry.get("request", {}).get("postData", {}) or {}
    params = post.get("params") or []
    keys = {p.get("name") for p in params if p.get("name")}
    # Best-effort JSON body parsing
    text = post.get("text")
    if text and post.get("mimeType", "").startswith("application/json"):
        try:
            import json
            body = json.loads(text)
            if isinstance(body, dict):
                keys |= set(body.keys())
        except Exception:
            pass
    return keys


def _group_by_endpoint(har: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for e in _entries(har):
        groups[_endpoint_key(e)].append(e)
    return groups


def _looks_like_id(segment: str) -> bool:
    """Heuristique : ce segment de chemin ressemble-t-il à un identifiant ?

    On capture les deux cas qui dominent en pratique pour l'IDOR :
    - IDs séquentiels (`/users/42`, `/orders/12345`) — isdigit() suffit
    - IDs opaques (UUID, nanoid, slug base64, token hex) — >= 16 caractères
      alphanumériques + `-_` évite les faux positifs du type `/about` ou
      `/profile` qui ne sont pas des IDs mais des noms de routes.

    Le seuil à 16 est empirique : plus court ça attrape des mots comme
    `settings`, plus long ça rate des nanoids de 12-15 caractères.
    """
    if not segment:
        return False
    if segment.isdigit():
        return True
    if len(segment) >= 16 and all(c.isalnum() or c in "-_" for c in segment):
        return True
    return False


def diff_hars(har_a: Dict[str, Any], har_b: Dict[str, Any]) -> HarDiff:
    """Produce a structured diff between two HAR captures."""
    groups_a = _group_by_endpoint(har_a)
    groups_b = _group_by_endpoint(har_b)
    keys_a, keys_b = set(groups_a), set(groups_b)

    diff = HarDiff(
        only_in_a=keys_a - keys_b,
        only_in_b=keys_b - keys_a,
        shared=keys_a & keys_b,
    )

    for key in diff.shared:
        entry_a = groups_a[key][0]
        entry_b = groups_b[key][0]
        status_a = entry_a.get("response", {}).get("status")
        status_b = entry_b.get("response", {}).get("status")
        if status_a != status_b:
            diff.status_deltas.append({
                "endpoint": key,
                "status_a": status_a,
                "status_b": status_b,
            })

        url_a = entry_a.get("request", {}).get("url", "")
        url_b = entry_b.get("request", {}).get("url", "")
        params_a = _query_params(url_a) | _post_params(entry_a)
        params_b = _query_params(url_b) | _post_params(entry_b)
        only_a, only_b = params_a - params_b, params_b - params_a
        if only_a or only_b:
            diff.param_deltas.append({
                "endpoint": key,
                "params_only_a": sorted(only_a),
                "params_only_b": sorted(only_b),
            })

    diff.idor_candidates = _detect_idor_candidates(groups_a, groups_b)
    return diff


def _detect_idor_candidates(
    groups_a: Dict[str, List[Dict[str, Any]]],
    groups_b: Dict[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    """An endpoint with an id-like path segment and 2xx response for at least one user
    is a prime IDOR target to replay with the other user's session."""
    candidates = []
    all_keys = set(groups_a) | set(groups_b)
    for key in all_keys:
        method, path = key.split(" ", 1) if " " in key else ("GET", key)
        segments = [s for s in path.split("/") if s]
        id_segments = [s for s in segments if _looks_like_id(s)]
        if not id_segments:
            continue
        entry = (groups_a.get(key) or groups_b.get(key) or [None])[0]
        if entry is None:
            continue
        status = entry.get("response", {}).get("status", 0)
        if 200 <= status < 300:
            candidates.append({
                "endpoint": key,
                "id_segments": id_segments,
                "observed_status": status,
                "seen_in": ("a" if key in groups_a else "") + ("b" if key in groups_b else ""),
            })
    return candidates
