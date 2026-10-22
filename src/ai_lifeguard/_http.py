import json
import urllib.request
from urllib.parse import urlparse

ALLOWED_SCHEMES = ("http", "https")


def fetch_json(url, token=None, timeout=10, data=None, method=None, headers=None):
    if urlparse(url).scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Refusing non-HTTP URL: {url!r}")
    hdrs = {"User-Agent": "ai-lifeguard", "Accept": "application/json"}
    hdrs.update(headers or {})
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    payload = None
    if data is not None:
        payload = json.dumps(data).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=payload, method=method, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        body = resp.read().decode("utf-8")
    return json.loads(body) if body else None
