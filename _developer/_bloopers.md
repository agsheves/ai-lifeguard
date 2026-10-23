# Bloopers
Mistakes and corrections, newest first.

- 2026-10-22: Semgrep `# nosemgrep: <id>` needs the full check_id (`python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected`), not the registry short id; the short form silently does nothing. Get the id from `--json` output first.
- 2026-10-22: Registry rule p/python flagged every `urlopen(req)` with a dynamic URL. Fixed by one shared `_http.fetch_json` with an http/https scheme allowlist instead of three suppressions.
- 2026-10-22: Module loggers and `Lifeguard._handle` both log each threat, so CLI output was doubled. CLI now silences the `ai_lifeguard` logger for `scan` and prints its own table.
- 2026-10-22: Container logs showed nothing from the watcher because Python buffers stdout when not on a TTY. Always set PYTHONUNBUFFERED=1 in service Dockerfiles.
- 2026-10-23: CI failed on Python 3.10 only: no tomllib, so parse_pyproject returned {} and its test failed. Local venv is 3.14, so the matrix caught it. Added a regex fallback and a test that forces tomllib absent.
