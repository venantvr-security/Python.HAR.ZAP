"""
ZAP Script Manager - Load, enable, and manage custom ZAP scripts.
"""
from pathlib import Path
from typing import Dict, List, Optional, Any

from zapv2 import ZAPv2

from .utils import get_logger, retry_zap_call, RateLimiter

logger = get_logger("zap.scripts")

SCRIPT_TYPES = {
    'active': 'active',
    'passive': 'passive',
    'authentication': 'authentication',
    'httpsender': 'httpsender',
    'standalone': 'standalone',
    'targeted': 'targeted',
}

SCRIPT_ENGINES = {
    '.js': 'ECMAScript / Nashorn',
    '.py': 'python : Jython',
    '.rb': 'ruby : JRuby',
    '.groovy': 'Groovy',
    '.zest': 'Zest',
}


class ZAPScriptManager:
    """Manager for ZAP custom scripts."""

    def __init__(
        self,
        zap: ZAPv2,
        scripts_dir: str = './scripts',
        config: Optional[Dict] = None
    ):
        self.zap = zap
        self.scripts_dir = Path(scripts_dir)
        self.config = config or {}
        self.loaded_scripts: Dict[str, Dict] = {}

        self.rate_limiter = RateLimiter(
            requests_per_second=self.config.get('rate_limit', 10.0),
            burst=self.config.get('rate_burst', 20)
        )

    def ensure_scripts_dir(self):
        """Create scripts directory structure."""
        for script_type in SCRIPT_TYPES.keys():
            (self.scripts_dir / script_type).mkdir(parents=True, exist_ok=True)
        logger.debug("scripts_dir_ready", path=str(self.scripts_dir))

    @retry_zap_call(max_retries=2)
    def list_scripts(self) -> Dict[str, List[Dict]]:
        """List all scripts in ZAP."""
        self.rate_limiter.acquire()
        scripts = self.zap.script.list_scripts

        result = {}
        for script in scripts:
            script_type = script.get('type', 'unknown')
            if script_type not in result:
                result[script_type] = []
            result[script_type].append({
                'name': script.get('name'),
                'engine': script.get('engine'),
                'enabled': script.get('enabled') == 'true',
                'error': script.get('error', False)
            })

        return result

    @retry_zap_call(max_retries=2)
    def load_script(
        self,
        script_path: str,
        script_type: str,
        script_name: Optional[str] = None,
        description: str = ''
    ) -> bool:
        """Load a script into ZAP."""
        path = Path(script_path)

        if not path.exists():
            logger.error("script_not_found", path=str(path))
            return False

        if script_type not in SCRIPT_TYPES:
            logger.error("invalid_script_type", type=script_type)
            return False

        # Determine engine
        engine = SCRIPT_ENGINES.get(path.suffix)
        if not engine:
            logger.error("unsupported_script_engine", suffix=path.suffix)
            return False

        name = script_name or path.stem

        self.rate_limiter.acquire()

        try:
            result = self.zap.script.load(
                scriptname=name,
                scripttype=SCRIPT_TYPES[script_type],
                scriptengine=engine,
                filename=str(path.absolute()),
                scriptdescription=description
            )

            if result == 'OK':
                self.loaded_scripts[name] = {
                    'path': str(path),
                    'type': script_type,
                    'engine': engine,
                    'enabled': False
                }
                logger.info("script_loaded", name=name, type=script_type)
                return True
            else:
                logger.error("script_load_failed", name=name, result=result)
                return False

        except Exception as e:
            logger.error("script_load_error", name=name, error=str(e))
            return False

    @retry_zap_call(max_retries=2)
    def enable_script(self, script_name: str) -> bool:
        """Enable a loaded script."""
        self.rate_limiter.acquire()

        try:
            result = self.zap.script.enable(scriptname=script_name)
            if result == 'OK':
                if script_name in self.loaded_scripts:
                    self.loaded_scripts[script_name]['enabled'] = True
                logger.info("script_enabled", name=script_name)
                return True
            return False

        except Exception as e:
            logger.error("script_enable_error", name=script_name, error=str(e))
            return False

    @retry_zap_call(max_retries=2)
    def disable_script(self, script_name: str) -> bool:
        """Disable a script."""
        self.rate_limiter.acquire()

        try:
            result = self.zap.script.disable(scriptname=script_name)
            if result == 'OK':
                if script_name in self.loaded_scripts:
                    self.loaded_scripts[script_name]['enabled'] = False
                logger.info("script_disabled", name=script_name)
                return True
            return False

        except Exception as e:
            logger.error("script_disable_error", name=script_name, error=str(e))
            return False

    @retry_zap_call(max_retries=2)
    def remove_script(self, script_name: str) -> bool:
        """Remove a script from ZAP."""
        self.rate_limiter.acquire()

        try:
            result = self.zap.script.remove(scriptname=script_name)
            if result == 'OK':
                self.loaded_scripts.pop(script_name, None)
                logger.info("script_removed", name=script_name)
                return True
            return False

        except Exception as e:
            logger.error("script_remove_error", name=script_name, error=str(e))
            return False

    def load_all_from_directory(self) -> Dict[str, int]:
        """Load all scripts from the scripts directory."""
        logger.info("loading_scripts_from_dir", path=str(self.scripts_dir))
        self.ensure_scripts_dir()

        stats = {t: 0 for t in SCRIPT_TYPES}

        for script_type in SCRIPT_TYPES:
            type_dir = self.scripts_dir / script_type
            if not type_dir.exists():
                continue

            for script_path in type_dir.iterdir():
                if script_path.suffix in SCRIPT_ENGINES:
                    if self.load_script(str(script_path), script_type):
                        stats[script_type] += 1

        logger.info("scripts_loaded", stats=stats)
        return stats

    def create_active_scan_script(
        self,
        name: str,
        description: str,
        check_patterns: List[str],
        risk: str = 'Medium',
        confidence: str = 'Medium'
    ) -> str:
        """Generate an active scan script from template."""
        risk_map = {"Low": 1, "Medium": 2, "High": 3}
        risk_int = risk_map.get(risk, 2)
        confidence_int = risk_map.get(confidence, 2)
        template = f'''
// Active Scan Script: {name}
// {description}

function scanNode(as, msg) {{
    var uri = msg.getRequestHeader().getURI().toString();
    var body = msg.getResponseBody().toString();

    var patterns = {check_patterns};

    for (var i = 0; i < patterns.length; i++) {{
        if (body.indexOf(patterns[i]) >= 0) {{
            as.raiseAlert(
                {risk_int},
                {confidence_int},
                "{name}",
                "{description}",
                uri,
                "",
                patterns[i],
                "",
                "",
                "",
                0,
                msg
            );
        }}
    }}
}}

function scan(as, msg, param, value) {{
    scanNode(as, msg);
}}
'''
        script_path = self.scripts_dir / 'active' / f'{name.lower().replace(" ", "_")}.js'
        self.ensure_scripts_dir()

        with open(script_path, 'w') as f:
            f.write(template)

        logger.info("script_created", name=name, path=str(script_path))
        return str(script_path)

    def create_passive_scan_script(
        self,
        name: str,
        description: str,
        response_patterns: List[str],
        risk: str = 'Informational'
    ) -> str:
        """Generate a passive scan script from template."""
        risk_map = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}
        risk_int = risk_map.get(risk, 0)
        template = f'''
// Passive Scan Script: {name}
// {description}

function scan(ps, msg, src) {{
    var body = msg.getResponseBody().toString();
    var uri = msg.getRequestHeader().getURI().toString();

    var patterns = {response_patterns};

    for (var i = 0; i < patterns.length; i++) {{
        var regex = new RegExp(patterns[i], 'gi');
        var matches = body.match(regex);

        if (matches) {{
            ps.raiseAlert(
                {risk_int},
                1,
                "{name}",
                "{description}",
                uri,
                "",
                matches[0],
                "",
                "",
                "",
                0,
                msg
            );
        }}
    }}
}}
'''
        script_path = self.scripts_dir / 'passive' / f'{name.lower().replace(" ", "_")}.js'
        self.ensure_scripts_dir()

        with open(script_path, 'w') as f:
            f.write(template)

        logger.info("script_created", name=name, path=str(script_path))
        return str(script_path)

    def get_script_output(self, script_name: str) -> Optional[str]:
        """Get output from a script execution."""
        self.rate_limiter.acquire()

        try:
            return self.zap.script.script_var(scriptname=script_name, varkey='output')
        except Exception:
            return None

    def get_loaded_scripts(self) -> Dict[str, Dict]:
        """Get all loaded scripts."""
        return self.loaded_scripts.copy()
