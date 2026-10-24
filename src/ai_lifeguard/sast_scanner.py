import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from .models import ThreatResult, ScanReport

log = logging.getLogger("ai_lifeguard.sast_scanner")

LOCAL_RULES = Path(__file__).parent / "defaults" / "semgrep_rules.yaml"
REGISTRY_CONFIGS = ("p/python", "p/default")
SEVERITY_LEVELS = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
OK_EXIT_CODES = (0, 1)
REGISTRY_ENV = "SEMGREP_REGISTRY"


def semgrep_available(semgrep_bin="semgrep"):
    return shutil.which(semgrep_bin) is not None


def registry_enabled(config=None):
    """Semgrep registry packs are opt-in: config key wins, then SEMGREP_REGISTRY env, else off."""
    if config and "registry" in config:
        return bool(config["registry"])
    return os.environ.get(REGISTRY_ENV, "").lower() in ("1", "true", "yes")


def default_configs(registry=False):
    configs = [str(LOCAL_RULES)]
    if registry:
        configs.extend(REGISTRY_CONFIGS)
    return configs


def _run_semgrep(directory, configs, timeout, semgrep_bin):
    cmd = [semgrep_bin, "scan", "--json", "--metrics=off", "--quiet", "--disable-version-check"]
    for cfg in configs:
        cmd.extend(["--config", cfg])
    cmd.append(str(directory))
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr


def _to_threat(finding):
    extra = finding.get("extra", {})
    line = finding.get("start", {}).get("line", 0)
    return ThreatResult(
        safe=False,
        level=SEVERITY_LEVELS.get(extra.get("severity", "").upper(), "medium"),
        module="sast_scanner",
        description=f"{finding.get('path', '?')}:{line}: {extra.get('message', '').strip()}",
        matched_rule=finding.get("check_id", ""),
    )


def scan_sast(directory, configs=None, registry=False, timeout=600, semgrep_bin="semgrep"):
    report = ScanReport(module="sast_scanner")
    if not semgrep_available(semgrep_bin):
        log.warning("semgrep not installed; run: pip install ai-lifeguard[sast]")
        report.threats.append(ThreatResult(
            safe=False, level="low", module="sast_scanner",
            description="semgrep not installed — SAST scan skipped", matched_rule="tool_missing",
        ))
        return report
    configs = list(configs) if configs else default_configs(registry)
    try:
        code, out, err = _run_semgrep(directory, configs, timeout, semgrep_bin)
        if code not in OK_EXIT_CODES and len(configs) > 1:
            log.warning("semgrep exited %s with registry configs; retrying with local rules only", code)
            configs = [str(LOCAL_RULES)]
            code, out, err = _run_semgrep(directory, configs, timeout, semgrep_bin)
        data = json.loads(out) if out.strip() else {}
    except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as e:
        report.threats.append(ThreatResult(
            safe=False, level="low", module="sast_scanner",
            description=f"semgrep failed: {e}", matched_rule="tool_error",
        ))
        return report
    if code not in OK_EXIT_CODES:
        report.threats.append(ThreatResult(
            safe=False, level="low", module="sast_scanner",
            description=f"semgrep exited {code}: {err.strip()[:300]}", matched_rule="tool_error",
        ))
    report.files_scanned = len(data.get("paths", {}).get("scanned", []))
    for finding in data.get("results", []):
        threat = _to_threat(finding)
        report.threats.append(threat)
        log.warning(threat.description)
    for error in data.get("errors", []):
        log.warning("semgrep: %s", error.get("message", error))
    return report
