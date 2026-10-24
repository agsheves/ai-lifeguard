# Tasks for Andrew — prefix AL (ai-lifeguard). Mirrored to Basecamp Administration (48872565).
- [ ] AL-001: stand up a Sonar host (SonarQube Community Build on a server, or a SonarQube Cloud org) and add SONAR_TOKEN and SONAR_HOST_URL as GitHub repo secrets
- [ ] AL-002: provision the watcher server, set GITHUB_TOKEN (fine-grained, issues:write on agsheves/ai-lifeguard) and deploy deploy/Dockerfile.watcher
- [ ] AL-003: confirm GitHub code scanning and Dependabot alerts are enabled on agsheves/ai-lifeguard
- [ ] AL-004: decide whether this repo opts in to Semgrep registry packs (repo variable SEMGREP_REGISTRY=true, optional SEMGREP_APP_TOKEN secret); default is off for licence reasons
