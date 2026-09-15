"""
Contexte d'exécution isolé — « 1 HAR-ZAP par user » sans interférence.

Deux runs simultanés (un par utilisateur/rôle) NE DOIVENT PAS interagir. Or
HAR-ZAP porte de l'état partagé qui, sinon isolé, crée de la diaphonie :

  1. Le daemon ZAP est STATEFUL : une instance = UNE session (arbre des sites,
     historique, alertes, contextes, jetons). Deux runs sur le même ZAP mélangent
     tout. -> il faut UN PORT ZAP par run.
  2. `os.environ` est GLOBAL au process (donc partagé entre threads) :
     HARZAP_AI_AUTHORIZED, HARZAP_LLM_REPLAY_*. Un thread qui atteste l'autorisation
     la fait fuiter à l'autre. -> isolation = 1 PROCESS par user (env propre), pas
     1 thread ; ou passer l'autorisation par config, jamais par l'env global.
  3. Des fichiers à chemin FIXE : patterns/, .llm_cache/, .harzap_*.json,
     .harzap_auth.dsl, cache incrémental. Deux runs dans le même cwd s'écrasent.
     -> un jeu de chemins par run.

`RunContext` matérialise cet isolement : des chemins dédiés + un port ZAP + un
overlay de config, et l'ENV à passer à un sous-process (la seule isolation sûre
pour l'autorisation). Threads dans le même process = PAS isolé (env/cwd partagés).
"""
import copy
import os
from dataclasses import dataclass
from typing import Dict, Optional

BASE_ZAP_PORT = 8090


@dataclass
class RunContext:
    run_id: str
    base_dir: str
    zap_port: int
    authorized: bool = False

    # --- chemins dédiés (aucun défaut global partagé) ---
    @property
    def patterns_dir(self) -> str:
        return os.path.join(self.base_dir, 'patterns')

    @property
    def llm_cache_dir(self) -> str:
        return os.path.join(self.base_dir, '.llm_cache')

    @property
    def fp_path(self) -> str:
        return os.path.join(self.base_dir, '.harzap_false_positives.json')

    @property
    def session_path(self) -> str:
        return os.path.join(self.base_dir, '.harzap_session.json')

    @property
    def webhooks_path(self) -> str:
        return os.path.join(self.base_dir, '.harzap_webhooks.json')

    @property
    def incremental_db(self) -> str:
        return os.path.join(self.base_dir, '.harzap_cache.db')

    @property
    def auth_dsl_path(self) -> str:
        return os.path.join(self.base_dir, '.harzap_auth.dsl')

    @property
    def output_dir(self) -> str:
        return os.path.join(self.base_dir, 'out')

    @classmethod
    def for_run(cls, run_id: str, base_root: str = './.harzap_runs',
                index: int = 0, authorized: bool = False) -> 'RunContext':
        """Fabrique un contexte isolé : dossier dédié + port ZAP unique par index."""
        base_dir = os.path.join(base_root, run_id)
        os.makedirs(base_dir, exist_ok=True)
        return cls(run_id=run_id, base_dir=base_dir,
                   zap_port=BASE_ZAP_PORT + index, authorized=authorized)

    def config_overlay(self, config: Optional[Dict] = None) -> Dict:
        """Retourne une COPIE de `config` où tous les chemins/états pointent vers
        ce run. L'autorisation passe par la config (pas par l'env global) →
        n'affecte que ce run, même en multi-thread."""
        cfg = copy.deepcopy(config or {})
        cfg.setdefault('llm', {})
        cfg['llm']['authorized'] = self.authorized
        cfg['llm'].setdefault('cache', {})
        cfg['llm']['cache']['directory'] = self.llm_cache_dir
        cfg['zap_port'] = self.zap_port
        cfg['reauth'] = {**cfg.get('reauth', {}), 'recipe_file': self.auth_dsl_path}
        # Chemins que les stores acceptent en paramètre (à passer au montage).
        cfg['_paths'] = {
            'patterns': self.patterns_dir, 'fp': self.fp_path,
            'session': self.session_path, 'webhooks': self.webhooks_path,
            'incremental_db': self.incremental_db, 'auth_dsl': self.auth_dsl_path,
            'output': self.output_dir,
        }
        return cfg

    def env_for_subprocess(self, base_env: Optional[Dict] = None) -> Dict:
        """ENV à passer à un SOUS-PROCESS pour une isolation réelle de
        l'autorisation/replay (jamais muter os.environ du process courant, ce
        serait partagé par tous les threads)."""
        env = dict(base_env if base_env is not None else os.environ)
        # On repart d'un état propre pour les variables globales sensibles.
        for k in ('HARZAP_AI_AUTHORIZED', 'HARZAP_LLM_REPLAY_MODE', 'HARZAP_LLM_REPLAY_FILE'):
            env.pop(k, None)
        if self.authorized:
            env['HARZAP_AI_AUTHORIZED'] = '1'
        return env


def isolation_report() -> Dict[str, str]:
    """Décrit les vecteurs de diaphonie et le remède — pour la doc/diagnostic."""
    return {
        'zap_session': "ZAP daemon = 1 session partagée (sites/historique/alertes). "
                       "Remède : 1 port/instance par run (RunContext.zap_port).",
        'process_env': "os.environ (HARZAP_AI_AUTHORIZED, replay) est global au process. "
                       "Remède : 1 process/user (env_for_subprocess) ou autorisation par config.",
        'shared_files': "patterns/, .llm_cache/, .harzap_*.json, .harzap_auth.dsl à chemin fixe. "
                        "Remède : chemins dédiés par run (config_overlay).",
    }
