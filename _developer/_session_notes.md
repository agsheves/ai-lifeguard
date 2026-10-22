# Session notes
Newest entry first. 150 words max per entry.

## 2026-10-22T21:16Z Deep-Thought
- Activity: v0.2.0 repo security workflow. New modules dependency_auditor (cve.now feed, CveWatcher), sast_scanner (Semgrep + bundled 10-rule pack), sonar_adapter, github_notifier, _http, cli. InputType.DEPENDENCY. CI `.github/workflows/security.yml`, dependabot, sonar-project.properties, deploy/. README + help updated. 141 tests green; dogfood scan of src clean (local pack + p/python + p/default).
- Decisions: core stays offline/zero-dep; network and semgrep are opt-in, scan_all(network=True) to include. Dependency CVE levels capped at high (exploited) / medium / low, never critical. Secrets only via env (SONAR_TOKEN, GITHUB_TOKEN).
- Issues: Docker daemon not running, Dockerfile.watcher unbuilt (see bloopers for semgrep notes).
- Next: push to trigger CI; Andrew does AL-001..003 (Basecamp 10434381676/719/796). Buildfile: _developer/_buildfile_security_workflow.md.

