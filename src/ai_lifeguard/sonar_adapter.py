import json
import logging
import urllib.parse
import urllib.request
from .models import ThreatResult, ScanReport

log = logging.getLogger("ai_lifeguard.sonar_adapter")

DEFAULT_SEVERITIES = ("BLOCKER", "CRITICAL", "MAJOR")
SEVERITY_LEVELS = {"BLOCKER": "high", "CRITICAL": "high", "MAJOR": "medium", "MINOR": "low", "INFO": "low"}
PAGE_SIZE = 500


def _get(url, token, timeout):
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/json", "User-Agent": "ai-lifeguard",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_issues(host_url, project_key, token, severities=DEFAULT_SEVERITIES, timeout=30):
    host = host_url.rstrip("/")
    issues, page = [], 1
    while True:
        params = urllib.parse.urlencode({
            "componentKeys": project_key, "resolved": "false", "severities": ",".join(severities),
            "ps": PAGE_SIZE, "p": page,
        })
        data = _get(f"{host}/api/issues/search?{params}", token, timeout)
        batch = data.get("issues", [])
        issues.extend(batch)
        total = data.get("paging", {}).get("total", len(issues))
        if not batch or len(issues) >= total:
            return issues
        page += 1


def quality_gate(host_url, project_key, token, timeout=30):
    params = urllib.parse.urlencode({"projectKey": project_key})
    data = _get(f"{host_url.rstrip('/')}/api/qualitygates/project_status?{params}", token, timeout)
    return data.get("projectStatus", {}).get("status")


def _to_threat(issue):
    level = SEVERITY_LEVELS.get(issue.get("severity", "").upper(), "medium")
    if issue.get("type") == "VULNERABILITY" and level == "medium":
        level = "high"
    component = issue.get("component", "").split(":", 1)[-1]
    line = issue.get("line", "")
    return ThreatResult(
        safe=False, level=level, module="sonar_adapter",
        description=f"{component}:{line}: {issue.get('message', '').strip()}",
        matched_rule=issue.get("rule", ""),
    )


def scan_sonar(host_url, project_key, token, severities=DEFAULT_SEVERITIES, timeout=30):
    report = ScanReport(module="sonar_adapter")
    if not (host_url and project_key):
        log.warning("Sonar host_url/project_key not configured; skipping")
        return report
    if not token:
        log.warning("Sonar token missing (set SONAR_TOKEN); skipping")
        return report
    try:
        issues = fetch_issues(host_url, project_key, token, severities, timeout)
        gate = quality_gate(host_url, project_key, token, timeout)
    except Exception as e:
        report.threats.append(ThreatResult(
            safe=False, level="low", module="sonar_adapter",
            description=f"Sonar unavailable: {e}", matched_rule="sonar_unavailable",
        ))
        return report
    report.files_scanned = len({issue.get("component") for issue in issues})
    for issue in issues:
        threat = _to_threat(issue)
        report.threats.append(threat)
        log.warning(threat.description)
    if gate == "ERROR":
        report.threats.append(ThreatResult(
            safe=False, level="high", module="sonar_adapter",
            description=f"Sonar quality gate failed for {project_key}", matched_rule="quality_gate_failed",
        ))
    return report
