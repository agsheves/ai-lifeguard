import json
from pathlib import Path

_DEFAULTS_DIR = Path(__file__).parent / "defaults"

_cache = {}


def _load_default(name):
    if name not in _cache:
        _cache[name] = json.loads((_DEFAULTS_DIR / name).read_text())
    return _cache[name]


def blocked_commands():
    return _load_default("blocked_commands.json")


def sensitive_paths():
    return _load_default("sensitive_paths.json")


def injection_patterns():
    return _load_default("injection_patterns.json")


def load_config(path):
    path = Path(path)

    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError:
            raise ImportError("Install pyyaml to use YAML configs: pip install pyyaml")
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
    elif path.suffix == ".json":
        with open(path) as f:
            raw = json.load(f)
    else:
        raise ValueError(f"Unsupported config format: {path.suffix}")

    return raw.get("ai_lifeguard", raw)


def load_orchestrator_config(raw_config):
    orch = raw_config.get("orchestrator", {})
    if not orch:
        return {}

    result = {}

    if "max_workers" in orch:
        result["max_workers"] = int(orch["max_workers"])

    if "routing" in orch:
        from .stream_models import InputType, ExecutionPath, DEFAULT_ROUTING
        routing = dict(DEFAULT_ROUTING)
        for key, value in orch["routing"].items():
            try:
                routing[InputType(key)] = ExecutionPath(value)
            except ValueError:
                pass
        result["routing"] = routing

    if "severity_map" in orch:
        from .stream_models import SeverityResponse, DEFAULT_SEVERITY_MAP
        smap = dict(DEFAULT_SEVERITY_MAP)
        for level, response in orch["severity_map"].items():
            try:
                smap[level] = SeverityResponse(response)
            except ValueError:
                pass
        result["severity_map"] = smap

    return result
