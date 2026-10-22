import logging
import time
import urllib.parse
from ._http import fetch_json

log = logging.getLogger("ai_lifeguard.github_notifier")

API_URL = "https://api.github.com"


class GitHubIssueNotifier:

    def __init__(self, repo, token, labels=("security", "cve"), api_url=API_URL, timeout=15):
        if not repo or "/" not in repo:
            raise ValueError("repo must be 'owner/name'")
        if not token:
            raise ValueError("GitHub token required (set GITHUB_TOKEN)")
        self.repo = repo
        self._token = token
        self.labels = list(labels)
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout

    def __call__(self, result):
        cve = result.matched_rule or "unknown"
        try:
            if self.exists(cve):
                log.info("Issue for %s already open in %s", cve, self.repo)
                return None
            url = self.open_issue(result)
            log.warning("Opened GitHub issue for %s: %s", cve, url)
            return url
        except Exception as e:
            log.error("GitHub notification failed for %s: %s", cve, e)
            return None

    def exists(self, cve):
        params = urllib.parse.urlencode({"state": "open", "labels": ",".join(self.labels), "per_page": 100})
        issues = self._request("GET", f"/repos/{self.repo}/issues?{params}")
        return any(cve in issue.get("title", "") for issue in issues)

    def open_issue(self, result):
        cve = result.matched_rule
        body = (
            f"**AI Lifeguard CVE watch** flagged a dependency match.\n\n"
            f"- Severity: `{result.level}`\n- Rule: `{cve}`\n- Detail: {result.description}\n"
            f"- Detected: {time.strftime('%Y-%m-%dT%H:%MZ', time.gmtime())}\n\n"
            f"Review the advisory, upgrade or pin the dependency, then close this issue."
        )
        issue = self._request("POST", f"/repos/{self.repo}/issues", {
            "title": f"[ai-lifeguard] {cve}: dependency match ({result.level})",
            "body": body, "labels": self.labels,
        })
        return issue.get("html_url")

    def _request(self, method, path, data=None):
        return fetch_json(
            self.api_url + path, token=self._token, timeout=self.timeout, data=data, method=method,
            headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
        )
