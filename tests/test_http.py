import json
import pytest
from ai_lifeguard import _http
from ai_lifeguard._http import fetch_json


class Resp:
    def __init__(self, body): self.body = body
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def read(self): return self.body


def test_refuses_non_http(monkeypatch):
    monkeypatch.setattr(_http, "_open", lambda *a, **k: pytest.fail("must not open"))
    for url in ("file:///etc/passwd", "ftp://x/y", "/relative", "javascript:alert(1)"):
        with pytest.raises(ValueError):
            fetch_json(url)


def test_headers_payload_and_empty_body(monkeypatch):
    seen = {}
    def fake(req, timeout):
        seen["url"] = req.full_url; seen["method"] = req.get_method(); seen["data"] = req.data
        seen["auth"] = req.get_header("Authorization"); seen["ct"] = req.get_header("Content-type")
        seen["accept"] = req.get_header("Accept")
        return Resp(b"")
    monkeypatch.setattr(_http, "_open", fake)
    out = fetch_json("https://api.example/x", token="t", data={"a": 1}, method="POST", headers={"Accept": "custom"})
    assert out is None
    assert seen["method"] == "POST" and json.loads(seen["data"]) == {"a": 1}
    assert seen["auth"] == "Bearer t" and seen["ct"] == "application/json" and seen["accept"] == "custom"


def test_parses_json(monkeypatch):
    monkeypatch.setattr(_http, "_open", lambda *a, **k: Resp(b'{"ok": true}'))
    assert fetch_json("http://h/p") == {"ok": True}


def test_opener_only_handles_http_schemes():
    import urllib.request
    kinds = {type(h) for h in _http._opener.handlers}
    assert urllib.request.HTTPHandler in kinds and urllib.request.HTTPSHandler in kinds
    assert urllib.request.FileHandler not in kinds and urllib.request.FTPHandler not in kinds
