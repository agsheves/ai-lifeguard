import json
import urllib.request
import pytest
from ai_lifeguard import sonar_adapter as sa

ISSUES_P1 = {"paging": {"total": 3}, "issues": [
    {"component": "proj:src/a.py", "line": 10, "severity": "BLOCKER", "type": "BUG", "rule": "python:S1", "message": "blocker"},
    {"component": "proj:src/a.py", "line": 20, "severity": "MAJOR", "type": "VULNERABILITY", "rule": "python:S2", "message": "vuln"},
]}
ISSUES_P2 = {"paging": {"total": 3}, "issues": [
    {"component": "proj:src/b.py", "line": 1, "severity": "MAJOR", "type": "CODE_SMELL", "rule": "python:S3", "message": "smell"},
]}


def _router(gate="OK"):
    calls = []
    def get(url, token, timeout):
        calls.append((url, token))
        if "qualitygates" in url:
            return {"projectStatus": {"status": gate}}
        return ISSUES_P2 if "p=2" in url else ISSUES_P1
    return get, calls


def test_scan_sonar_maps_and_paginates(monkeypatch):
    get, calls = _router()
    monkeypatch.setattr(sa, "_get", get)
    report = sa.scan_sonar("https://sonar.example/", "proj", "tok")
    assert report.files_scanned == 2
    assert [t.level for t in report.threats] == ["high", "high", "medium"]
    assert report.threats[0].description == "src/a.py:10: blocker"
    assert report.threats[1].matched_rule == "python:S2"
    assert all(tok == "tok" for _, tok in calls) and len(calls) == 3
    assert "componentKeys=proj" in calls[0][0] and "resolved=false" in calls[0][0]


def test_failed_gate_adds_high(monkeypatch):
    get, _ = _router(gate="ERROR")
    monkeypatch.setattr(sa, "_get", get)
    report = sa.scan_sonar("https://sonar.example", "proj", "tok")
    assert report.threats[-1].matched_rule == "quality_gate_failed" and report.threats[-1].level == "high"


def test_missing_token_or_config_skips(monkeypatch):
    monkeypatch.setattr(sa, "_get", lambda *a: pytest.fail("should not call"))
    assert sa.scan_sonar("https://sonar.example", "proj", "").clean
    assert sa.scan_sonar("", "proj", "tok").clean


def test_unavailable(monkeypatch):
    def get(*a):
        raise OSError("connection refused")
    monkeypatch.setattr(sa, "_get", get)
    report = sa.scan_sonar("https://sonar.example", "proj", "tok")
    assert report.threats[0].matched_rule == "sonar_unavailable"


def test_get_sends_bearer(monkeypatch):
    seen = {}
    class Resp:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def read(self): return json.dumps({"ok": 1}).encode()
    def fake_open(req, timeout):
        seen["auth"] = req.get_header("Authorization")
        return Resp()
    monkeypatch.setattr(urllib.request, "urlopen", fake_open)
    assert sa._get("https://sonar.example/api/x", "tok", 5) == {"ok": 1}
    assert seen["auth"] == "Bearer tok"
