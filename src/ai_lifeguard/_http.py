import json
import urllib.request
from urllib.parse import urlparse

ALLOWED_SCHEMES = ("http", "https")

_opener = urllib.request.OpenerDirector()
for _handler in (urllib.request.HTTPHandler, urllib.request.HTTPSHandler,
                 urllib.request.HTTPDefaultErrorHandler, urllib.request.HTTPErrorProcessor):
    _opener.add_handler(_handler())


def _open(req, timeout):
    return _opener.open(req, timeout=timeout)


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
    with _open(req, timeout) as resp:
        body = resp.read().decode("utf-8")
    return json.loads(body) if body else None
