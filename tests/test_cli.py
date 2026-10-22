import json
import pytest
from ai_lifeguard import cli, sast_scanner, dependency_auditor, sonar_adapter
from ai_lifeguard.models import ThreatResult, ScanReport

HIGH = ThreatResult(safe=False, level="high", module="sast_scanner", description="a.py:1: eval", matched_rule="r")
LOW = ThreatResult(safe=False, level="low", module="dependency_auditor", description="feed down", matched_rule="feed_unavailable")


@pytest.fixture
def fakes(monkeypatch, tmp_path):
    monkeypatch.setattr(sast_scanner, "semgrep_available", lambda *_: False)
    monkeypatch.setattr(sast_scanner, "scan_sast", lambda *a, **k: ScanReport("sast_scanner", 3, [HIGH]))
    monkeypatch.setattr(dependency_auditor, "scan_dependencies", lambda *a, **k: ScanReport("dependency_auditor", 2, [LOW]))
    monkeypatch.setattr(sonar_adapter, "scan_sonar", lambda *a, **k: ScanReport("sonar_adapter"))
    (tmp_path / "ok.py").write_text("print('hi')\n")
    return tmp_path


def test_scan_default_runs_behaviour_scanners(fakes, capsys):
    assert cli.main(["scan", "--dir", str(fakes)]) == 0
    out = capsys.readouterr().out
    assert "command_validator" in out and "sast_scanner" not in out


def test_scan_fail_on(fakes):
    assert cli.main(["scan", "--dir", str(fakes), "--sast"]) == 1
    assert cli.main(["scan", "--dir", str(fakes), "--sast", "--fail-on", "critical"]) == 0
    assert cli.main(["scan", "--dir", str(fakes), "--deps"]) == 0
    assert cli.main(["scan", "--dir", str(fakes), "--deps", "--fail-on", "low"]) == 1


def test_scan_json(fakes, capsys):
    cli.main(["scan", "--dir", str(fakes), "--sast", "--deps", "--sonar", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert [r["module"] for r in data["reports"]] == ["sast_scanner", "dependency_auditor", "sonar_adapter"]
    assert data["threats"][0]["level"] == "high"


def test_watch_once(monkeypatch, tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("pyyaml==6.0\n")
    feed = [{"id": "CVE-2026-9", "url": "u", "title": "CVE-2026-9: RCE in PyYAML", "content_text": "PyYAML for Python"}]
    monkeypatch.setattr(dependency_auditor, "fetch_feed", lambda *a, **k: feed)
    assert cli.main(["watch", "--dir", str(tmp_path), "--once"]) == 1
    out = capsys.readouterr().out
    assert "Watching 1 dependencies" in out and "CVE-2026-9" in out


def test_watch_requires_token(monkeypatch, tmp_path):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert cli.main(["watch", "--dir", str(tmp_path), "--once", "--github-repo", "o/r"]) == 2


def test_lifeguard_watch_with_orchestrator(monkeypatch):
    from ai_lifeguard import Lifeguard
    feed = [{"id": "CVE-2026-9", "url": "u", "title": "CVE-2026-9: RCE in PyYAML", "content_text": "PyYAML for Python"}]
    monkeypatch.setattr(dependency_auditor, "fetch_feed", lambda *a, **k: feed)
    alerts = []
    guard = Lifeguard(mode="production", on_threat=alerts.append)
    orch = guard.create_orchestrator()
    w = guard.watch_dependencies(dependencies={"pyyaml": "6.0"}, orchestrator=orch, start=False)
    assert len(w.poll()) == 1
    assert len(orch.kill_switch.event_log) == 1 and len(alerts) == 1
    orch.shutdown()
