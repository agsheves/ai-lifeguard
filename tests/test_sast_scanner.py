import json
import subprocess
from pathlib import Path
import pytest
from ai_lifeguard import sast_scanner as ss

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE = {
    "results": [
        {"check_id": "rules.ai-lifeguard-eval-exec-dynamic", "path": "app.py", "start": {"line": 7},
         "extra": {"severity": "ERROR", "message": "eval on non-literal", "metadata": {"cwe": ["CWE-95"]}}},
        {"check_id": "rules.ai-lifeguard-tempfile-mktemp", "path": "util.py", "start": {"line": 2},
         "extra": {"severity": "WARNING", "message": "racy"}},
        {"check_id": "x", "path": "y.py", "start": {"line": 1}, "extra": {"severity": "INFO", "message": "fyi"}},
    ],
    "errors": [],
    "paths": {"scanned": ["app.py", "util.py", "y.py"]},
}


def _fake_run(returncode=1, stdout=json.dumps(SAMPLE), stderr=""):
    calls = []
    def run(cmd, capture_output, text, timeout):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)
    return run, calls


def test_maps_findings(monkeypatch):
    monkeypatch.setattr(ss, "semgrep_available", lambda *_: True)
    run, calls = _fake_run()
    monkeypatch.setattr(subprocess, "run", run)
    report = ss.scan_sast("src", registry=False)
    assert report.files_scanned == 3
    assert [t.level for t in report.threats] == ["high", "medium", "low"]
    assert report.threats[0].description == "app.py:7: eval on non-literal"
    assert report.threats[0].matched_rule.endswith("eval-exec-dynamic")
    cmd = calls[0]
    assert cmd[:3] == ["semgrep", "scan", "--json"] and "--metrics=off" in cmd and "shell" not in cmd
    assert cmd[cmd.index("--config") + 1] == str(ss.LOCAL_RULES) and cmd[-1] == "src"


def test_registry_configs_included_then_dropped_on_failure(monkeypatch):
    monkeypatch.setattr(ss, "semgrep_available", lambda *_: True)
    calls = []
    def run(cmd, capture_output, text, timeout):
        calls.append(cmd)
        if "p/python" in cmd:
            return subprocess.CompletedProcess(cmd, 7, "", "registry unreachable")
        return subprocess.CompletedProcess(cmd, 0, json.dumps({"results": [], "paths": {"scanned": ["a.py"]}}), "")
    monkeypatch.setattr(subprocess, "run", run)
    report = ss.scan_sast("src", registry=True)
    assert len(calls) == 2 and "p/default" in calls[0] and "p/python" not in calls[1]
    assert report.clean and report.files_scanned == 1


def test_registry_off_by_default(monkeypatch):
    monkeypatch.delenv(ss.REGISTRY_ENV, raising=False)
    assert ss.default_configs() == [str(ss.LOCAL_RULES)]
    assert ss.registry_enabled() is False and ss.registry_enabled({}) is False
    monkeypatch.setenv(ss.REGISTRY_ENV, "true")
    assert ss.registry_enabled() is True
    assert ss.registry_enabled({"registry": False}) is False
    monkeypatch.setattr(ss, "semgrep_available", lambda *_: True)
    run, calls = _fake_run()
    monkeypatch.setattr(subprocess, "run", run)
    ss.scan_sast("src")
    assert "p/python" not in calls[0]


def test_tool_missing(monkeypatch):
    monkeypatch.setattr(ss, "semgrep_available", lambda *_: False)
    report = ss.scan_sast("src")
    assert report.threats[0].matched_rule == "tool_missing" and report.threats[0].level == "low"


def test_tool_error_is_reported(monkeypatch):
    monkeypatch.setattr(ss, "semgrep_available", lambda *_: True)
    run, _ = _fake_run(returncode=2, stdout="", stderr="boom")
    monkeypatch.setattr(subprocess, "run", run)
    report = ss.scan_sast("src", registry=False)
    assert report.threats[0].matched_rule == "tool_error" and "boom" in report.threats[0].description


def test_timeout(monkeypatch):
    monkeypatch.setattr(ss, "semgrep_available", lambda *_: True)
    def run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 1)
    monkeypatch.setattr(subprocess, "run", run)
    assert ss.scan_sast("src", registry=False).threats[0].matched_rule == "tool_error"


needs_semgrep = pytest.mark.skipif(not ss.semgrep_available(), reason="semgrep not installed")


@needs_semgrep
def test_rule_pack_fires_each_rule_once(tmp_path):
    (tmp_path / "bad.py").write_text((FIXTURES / "semgrep_bad.py.txt").read_text())
    report = ss.scan_sast(tmp_path, registry=False)
    expected = {
        "subprocess-shell-true-dynamic", "os-system-dynamic", "eval-exec-dynamic", "yaml-unsafe-load",
        "pickle-load-dynamic", "requests-verify-false", "urlopen-dynamic-url", "tempfile-mktemp",
        "hardcoded-secret", "llm-output-to-path",
    }
    fired = [t.matched_rule.rsplit("ai-lifeguard-", 1)[-1] for t in report.threats]
    assert sorted(fired) == sorted(expected)
    assert report.files_scanned == 1


@needs_semgrep
def test_rule_pack_clean_file(tmp_path):
    (tmp_path / "ok.py").write_text((FIXTURES / "semgrep_clean.py.txt").read_text())
    assert ss.scan_sast(tmp_path, registry=False).clean
