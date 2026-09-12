"""
Record / Replay des interactions LLM.

Objectif : rejouer une séquence qui a utilisé l'IA SANS rappeler l'IA. En mode
« record », chaque complétion (system + prompt → réponse) est sauvegardée dans un
transcript JSON. En mode « replay », les complétions sont servies depuis ce
transcript — aucune requête réseau, aucun coût, résultat déterministe — et
`available` reste vrai même sans clé API. Un prompt absent du transcript renvoie
None, laissant le repli heuristique offline prendre le relais.

Clé = hash(system + prompt), indépendante du fournisseur/modèle, pour qu'un
transcript enregistré avec un modèle rejoue tel quel.

⚠️ Le transcript peut contenir des données sensibles (extraites du HAR) : il reste
local. Redacter avant tout partage.
"""
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Dict, Optional

from ..utils import get_logger

logger = get_logger("llm.replay")


@dataclass
class ReplayResponse:
    """Réponse minimale compatible avec l'usage `resp.content` des appelants."""
    content: str


def interaction_key(system: str, prompt: str) -> str:
    return hashlib.sha256(f"{system or ''}\x00{prompt or ''}".encode('utf-8')).hexdigest()[:40]


class ReplayCache:
    """Transcript JSON persistant des interactions LLM."""

    def __init__(self, path: str):
        self.path = path
        self.data: Dict[str, str] = {}
        try:
            if os.path.exists(path):
                self.data = json.loads(open(path, encoding='utf-8').read()).get('interactions', {})
        except (OSError, ValueError):
            self.data = {}

    def get(self, key: str) -> Optional[str]:
        return self.data.get(key)

    def put(self, key: str, content: str) -> None:
        self.data[key] = content
        try:
            d = os.path.dirname(self.path)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(self.path, 'w', encoding='utf-8') as f:
                json.dump({'version': 1, 'interactions': self.data}, f, indent=2)
        except OSError as e:
            logger.warning("replay_write_failed", error=str(e))

    def __len__(self):
        return len(self.data)


class ReplayableClient:
    """Enveloppe un LLMClient pour enregistrer ou rejouer ses complétions.

    - mode 'record' : appelle le client réel, sauvegarde chaque réponse.
    - mode 'replay' : sert depuis le transcript, sans client réel ni réseau.
    """

    def __init__(self, inner, cache: ReplayCache, mode: str):
        self.inner = inner            # LLMClient réel, ou None en replay
        self.cache = cache
        self.mode = mode              # 'record' | 'replay'

    @property
    def available(self) -> bool:
        if self.mode == 'replay':
            return True               # servi depuis le transcript, aucune clé requise
        return self.inner is not None and getattr(self.inner, 'available', True)

    def complete(self, prompt: str, system: str = ''):
        key = interaction_key(system, prompt)
        if self.mode == 'replay':
            content = self.cache.get(key)
            if content is None:
                logger.info("replay_miss", key=key)
                return None           # laisse l'appelant basculer en offline
            return ReplayResponse(content)
        # record : appel réel puis sauvegarde
        resp = self.inner.complete(prompt, system=system) if self.inner else None
        content = getattr(resp, 'content', None)
        if content:
            self.cache.put(key, content)
        return resp


def wrap_for_replay(inner, config: Optional[Dict] = None):
    """Applique record/replay selon l'environnement (HARZAP_LLM_REPLAY_MODE /
    HARZAP_LLM_REPLAY_FILE). Retourne `inner` inchangé si aucun mode n'est actif."""
    mode = os.environ.get('HARZAP_LLM_REPLAY_MODE', '').lower()
    path = os.environ.get('HARZAP_LLM_REPLAY_FILE', '')
    if mode not in ('record', 'replay') or not path:
        return inner
    if mode == 'replay':
        return ReplayableClient(None, ReplayCache(path), 'replay')
    if inner is None:
        return None                   # rien à enregistrer sans client réel
    return ReplayableClient(inner, ReplayCache(path), 'record')
