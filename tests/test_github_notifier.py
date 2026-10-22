import pytest
from ai_lifeguard.github_notifier import GitHubIssueNotifier
from ai_lifeguard.models import ThreatResult

RESULT = ThreatResult(safe=False, level="medium", module="dependency_auditor",
                      description="pyyaml==6.0 matches CVE-2026-1004: SSRF (https://cve.now/CVE-2026-1004)",
                      matched_rule="CVE-2026-1004")


def _notifier(existing_titles):
    n = GitHubIssueNotifier("owner/repo", "ghp_x")
    calls = []
    def request(method, path, data=None):
        calls.append((method, path, data))
        if method == "GET":
            return [{"title": t} for t in existing_titles]
        return {"html_url": "https://github.com/owner/repo/issues/1"}
    n._request = request
    return n, calls


def test_opens_issue_when_absent():
    n, calls = _notifier([])
    assert n(RESULT) == "https://github.com/owner/repo/issues/1"
    method, path, data = calls[-1]
    assert method == "POST" and path == "/repos/owner/repo/issues"
    assert data["title"] == "[ai-lifeguard] CVE-2026-1004: dependency match (medium)"
    assert data["labels"] == ["security", "cve"] and "cve.now/CVE-2026-1004" in data["body"]


def test_dedupes_existing():
    n, calls = _notifier(["[ai-lifeguard] CVE-2026-1004: dependency match (medium)"])
    assert n(RESULT) is None
    assert [m for m, _, _ in calls] == ["GET"]


def test_errors_are_swallowed():
    n = GitHubIssueNotifier("owner/repo", "ghp_x")
    def boom(*a, **k):
        raise OSError("down")
    n._request = boom
    assert n(RESULT) is None


def test_validation():
    with pytest.raises(ValueError):
        GitHubIssueNotifier("badrepo", "tok")
    with pytest.raises(ValueError):
        GitHubIssueNotifier("o/r", "")
