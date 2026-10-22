import json
import urllib.request
import pytest
from ai_lifeguard import dependency_auditor as da
from ai_lifeguard.kill_switch import KillSwitch

FEED = [
    {"id": "CVE-2026-1001#2026-10-22T10:00:00Z", "url": "https://cve.now/CVE-2026-1001",
     "title": "CVE-2026-1001: Remote code execution in python-dotenv parser",
     "content_text": "python-dotenv for Python before 1.0.2 allows code execution."},
    {"id": "CVE-2026-1002", "url": "https://cve.now/CVE-2026-1002",
     "title": "CVE-2026-1002: Prototype pollution in a web framework",
     "content_text": "The npm package lodash before 4.17.22 is affected."},
    {"id": "CVE-2026-1003", "url": "https://cve.now/CVE-2026-1003",
     "title": "CVE-2026-1003: Unauthenticated requests reach admin panel in AcmeRouter firmware",
     "content_text": "AcmeRouter devices accept unauthenticated HTTP."},
    {"id": "CVE-2026-1004", "url": "https://cve.now/CVE-2026-1004",
     "title": "CVE-2026-1004: SSRF in PyYAML loader",
     "content_text": "PyYAML for Python is actively exploited in the wild."},
]


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    da.clear_feed_cache()
    def boom(*a, **k):
        raise AssertionError("network call attempted")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    yield
    da.clear_feed_cache()


def test_title_match_is_medium():
    results = da.match_feed({"python-dotenv": "1.0.0"}, FEED)
    assert len(results) == 1
    assert results[0].level == "medium"
    assert results[0].matched_rule == "CVE-2026-1001"
    assert "python-dotenv==1.0.0" in results[0].description
    assert "https://cve.now/CVE-2026-1001" in results[0].description


def test_underscore_and_case_variants_match():
    assert da.match_feed({"Python_Dotenv": None}, FEED)


def test_content_only_match_with_hint_is_low():
    results = da.match_feed({"lodash": "4.17.0"}, FEED)
    assert len(results) == 1 and results[0].level == "low"


def test_common_word_in_title_without_hint_does_not_match():
    assert da.match_feed({"requests": "2.31.0"}, FEED) == []


def test_exploited_bumps_to_high():
    results = da.match_feed({"pyyaml": "6.0"}, FEED)
    assert results[0].level == "high"


def test_seen_dedupes_across_calls():
    seen = set()
    assert len(da.match_feed({"pyyaml": None}, FEED, seen)) == 1
    assert da.match_feed({"pyyaml": None}, FEED, seen) == []
    assert ("pyyaml", "CVE-2026-1004") in seen


def test_check_dependency_uses_feed(monkeypatch):
    monkeypatch.setattr(da, "fetch_feed", lambda *a, **k: FEED)
    assert not da.check_dependency("pyyaml>=6.0").safe
    assert da.check_dependency("numpy==1.26").safe


def test_check_dependency_feed_unavailable():
    r = da.check_dependency("pyyaml")
    assert r.safe and r.matched_rule == "feed_unavailable"


def test_check_dependency_guards():
    assert da.check_dependency("x" * 600).matched_rule == "input_too_long"
    assert da.check_dependency("==1.0").matched_rule == "bad_spec"


def test_fetch_feed_parses_and_caches(monkeypatch):
    calls = []
    class Resp:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def read(self): return json.dumps({"items": FEED}).encode()
    def fake_open(req, timeout):
        calls.append(req.full_url)
        return Resp()
    monkeypatch.setattr(urllib.request, "urlopen", fake_open)
    assert len(da.fetch_feed("https://example.test/feed")) == 4
    assert len(da.fetch_feed("https://example.test/feed")) == 4
    assert len(calls) == 1


def test_parse_requirements():
    deps = da.parse_requirements("""
# comment
requests==2.31.0  # pinned
pyyaml>=6.0; python_version > '3.8'
uvicorn[standard]~=0.30
-r other.txt
-e .
git+https://example.com/x.git
Flask_Login
""")
    assert deps == {"requests": "2.31.0", "pyyaml": "6.0", "uvicorn": "0.30", "flask-login": None}


def test_parse_pyproject():
    deps = da.parse_pyproject("""
[project]
dependencies = ["httpx>=0.27", "pydantic"]
[project.optional-dependencies]
yaml = ["pyyaml>=6.0"]
[tool.poetry.dependencies]
python = "^3.10"
rich = "^13.0"
""")
    assert deps == {"httpx": "0.27", "pydantic": None, "pyyaml": "6.0", "rich": "13.0"}


def test_parse_package_json():
    deps = da.parse_package_json(json.dumps({"dependencies": {"lodash": "^4.17.21"}, "devDependencies": {"vite": "~5.0.0"}}))
    assert deps == {"lodash": "4.17.21", "vite": "5.0.0"}


def test_parse_manifests_walks_tree(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / "requirements-dev.txt").write_text("pytest\n")
    sub = tmp_path / "web"; sub.mkdir()
    (sub / "package.json").write_text('{"dependencies": {"lodash": "4.17.0"}}')
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package.json").write_text('{"dependencies": {"evil": "1"}}')
    deps = da.parse_manifests(tmp_path)
    assert deps == {"requests": "2.31.0", "pytest": None, "lodash": "4.17.0"}


def test_scan_dependencies(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("pyyaml==6.0\nnumpy\n")
    monkeypatch.setattr(da, "fetch_feed", lambda *a, **k: FEED)
    report = da.scan_dependencies(tmp_path)
    assert report.files_scanned == 2
    assert [t.matched_rule for t in report.threats] == ["CVE-2026-1004"]


def test_scan_dependencies_feed_down(tmp_path):
    (tmp_path / "requirements.txt").write_text("pyyaml==6.0\n")
    report = da.scan_dependencies(tmp_path)
    assert not report.clean and report.threats[0].matched_rule == "feed_unavailable"


def test_watcher_poll_dispatches_once():
    alerts, notified = [], []
    ks = KillSwitch()
    w = da.CveWatcher({"pyyaml": "6.0", "lodash": None}, fetch=lambda: FEED,
                      on_threat=alerts.append, kill_switch=ks, notifier=notified.append)
    new = w.poll()
    assert sorted(r.matched_rule for r in new) == ["CVE-2026-1002", "CVE-2026-1004"]
    assert len(alerts) == 2 and len(notified) == 2
    assert len(ks.event_log) == 2
    assert ks.event_log[0].source_input.source_id == "cve_watcher"
    assert w.poll() == []
    assert len(alerts) == 2


def test_watcher_thread_runs_and_stops():
    alerts = []
    w = da.CveWatcher({"pyyaml": None}, interval=0.05, fetch=lambda: FEED, on_threat=alerts.append)
    w.start()
    import time
    deadline = time.time() + 2
    while not alerts and time.time() < deadline:
        time.sleep(0.01)
    w.stop(timeout=1)
    assert not w.is_alive() and len(alerts) == 1


def test_watcher_survives_callback_errors():
    def bad(_): raise RuntimeError("boom")
    w = da.CveWatcher({"pyyaml": None}, fetch=lambda: FEED, on_threat=bad)
    assert len(w.poll()) == 1
