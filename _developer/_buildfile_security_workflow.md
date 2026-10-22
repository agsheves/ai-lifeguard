# Buildfile: repo security workflow (v0.2.0)

Plan: ~/.claude/plans/there-have-been-an-woolly-pixel.md (copied below in brief).

## Goal
Extend AI Lifeguard from guarding agent behaviour to guarding the code and its dependencies:
Semgrep SAST (own rule pack + registry), SonarQube adapter (host-agnostic), cve.now dependency
watch (dev scan + background watcher), hosted watcher that opens GitHub issues, CI workflow.
Core stays zero-dependency and offline; network/shell-out pieces are explicit opt-ins.

## Steps
1. [x] `_developer/` scaffold, tasks, Basecamp mirror
2. [x] `InputType.DEPENDENCY` + routing + dispatch + test
3. [x] `dependency_auditor` + `_scanner.walk_named_files` + tests
4. [x] `CveWatcher` + `Lifeguard.watch_dependencies` + tests
5. [x] `sast_scanner` + `defaults/semgrep_rules.yaml` + pyproject extras + tests
6. [x] `sonar_adapter` + tests
7. [x] `github_notifier` + `cli` + entry point + tests
8. [x] `Lifeguard` wiring, help, README, config.yaml
9. [x] `.github/workflows/security.yml`, dependabot, sonar-project.properties
10. [x] `deploy/` Dockerfile.watcher, docker-compose.sonar.yml, README
11. [x] session notes, bloopers, version bump 0.2.0

## Log
- 2026-10-22 steps 1-4: scaffold c145321; AL-001..003 mirrored to Basecamp (10434381676/719/796); dependency_auditor + CveWatcher + InputType.DEPENDENCY, 116 tests green. Watcher levels capped at high (exploited) / medium / low — a dependency CVE is an alert, not an attack.
- 2026-10-22 steps 5-6: sast_scanner + 10-rule MIT pack (semgrep 1.182.1 confirmed JSON shape; local rule ids are prefixed with the config path, so match on suffix); sonar_adapter (bearer auth, paginated issues, quality gate); github_notifier with dedupe. pyproject 0.2.0 + extras + script entry.
- 2026-10-22 steps 7-10: cli (scan/watch), Lifeguard wiring (scan_sast/scan_dependencies/scan_sonar/check_dependency/watch_dependencies, scan_all(network=)), README, config.yaml, .github workflow (tests/semgrep/lifeguard/sonar jobs), dependabot, sonar-project.properties, deploy/. Dogfood: registry rule flagged dynamic urlopen in 3 modules -> shared _http.fetch_json with http/https allowlist + nosemgrep on the one call. 141 tests.
- 2026-10-22 step 11: notes + bloopers written. Docker build of deploy/Dockerfile.watcher verified later same day (OrbStack started): build ok, --once poll ok, default CMD ok after PYTHONUNBUFFERED=1. Live `ai-lifeguard scan --dir . --deps` parsed 4 deps from pyproject, 0 matches.
