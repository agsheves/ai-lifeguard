# Buildfile: repo security workflow (v0.2.0)

Plan: ~/.claude/plans/there-have-been-an-woolly-pixel.md (copied below in brief).

## Goal
Extend AI Lifeguard from guarding agent behaviour to guarding the code and its dependencies:
Semgrep SAST (own rule pack + registry), SonarQube adapter (host-agnostic), cve.now dependency
watch (dev scan + background watcher), hosted watcher that opens GitHub issues, CI workflow.
Core stays zero-dependency and offline; network/shell-out pieces are explicit opt-ins.

## Steps
1. [ ] `_developer/` scaffold, tasks, Basecamp mirror
2. [ ] `InputType.DEPENDENCY` + routing + dispatch + test
3. [ ] `dependency_auditor` + `_scanner.walk_named_files` + tests
4. [ ] `CveWatcher` + `Lifeguard.watch_dependencies` + tests
5. [ ] `sast_scanner` + `defaults/semgrep_rules.yaml` + pyproject extras + tests
6. [ ] `sonar_adapter` + tests
7. [ ] `github_notifier` + `cli` + entry point + tests
8. [ ] `Lifeguard` wiring, help, README, config.yaml
9. [ ] `.github/workflows/security.yml`, dependabot, sonar-project.properties
10. [ ] `deploy/` Dockerfile.watcher, docker-compose.sonar.yml, README
11. [ ] session notes, bloopers, version bump 0.2.0

## Log
