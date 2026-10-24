# Bloopers
Mistakes and corrections, newest first.

- 2026-10-22: Semgrep `# nosemgrep: <id>` needs the full check_id (`python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected`), not the registry short id; the short form silently does nothing. Get the id from `--json` output first.
- 2026-10-22: Registry rule p/python flagged every `urlopen(req)` with a dynamic URL. Fixed by one shared `_http.fetch_json` with an http/https scheme allowlist instead of three suppressions.
- 2026-10-22: Module loggers and `Lifeguard._handle` both log each threat, so CLI output was doubled. CLI now silences the `ai_lifeguard` logger for `scan` and prints its own table.
- 2026-10-22: Container logs showed nothing from the watcher because Python buffers stdout when not on a TTY. Always set PYTHONUNBUFFERED=1 in service Dockerfiles.
- 2026-10-23: CI failed on Python 3.10 only: no tomllib, so parse_pyproject returned {} and its test failed. Local venv is 3.14, so the matrix caught it. Added a regex fallback and a test that forces tomllib absent.
- 2026-10-23: `# nosemgrep` hides a finding from CLI output but Semgrep still writes it into SARIF, and GitHub code scanning shows it as an open alert. Fix the code (HTTP-only OpenerDirector) instead of suppressing. Also: fixtures of deliberately bad code must not end in `.py` or CodeQL default setup scans them; use `.py.txt`.
- 2026-10-24: Appending a note to LICENSE makes it non-verbatim MIT, which can break licence detection on GitHub and PyPI. Keep LICENSE pristine; third-party terms go in THIRD_PARTY_NOTICES.md.
- 2026-10-24: Shipped Semgrep registry packs on by default without checking the Semgrep Rules License (internal use only, not for competing products). A security scanner enabling them by default is a grey area; defaults for third-party content must follow its licence, not convenience.
