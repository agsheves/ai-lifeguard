# Deploy: the server side of the security workflow

Everything in AI Lifeguard runs on device or in CI. Two pieces benefit from a long-lived host.

```
 dev machine / CI ──semgrep, pytest, ai-lifeguard scan──▶ GitHub checks + SARIF (code scanning)
        │
        └─sonar-scanner──▶ SonarQube server ◀──scan_sonar() / quality gate──┐
                                                                            ▼
 watcher server ──ai-lifeguard watch──▶ cve.now feed ──match──▶ GitHub issue on the repo
```

## 1. SonarQube server (AL-001)

Two options, same adapter either way: `sonar.host_url` + `project_key` in config, token in `SONAR_TOKEN`.

- **SonarQube Cloud**: free for public OSI-licensed repos. Create the org and project at sonarcloud.io, uncomment `sonar.organization` in `sonar-project.properties`, add `SONAR_TOKEN` as a repo secret (no `SONAR_HOST_URL` needed).
- **Self-hosted Community Build**: `SONAR_DB_PASSWORD=... docker compose -f docker-compose.sonar.yml up -d` on a box with 2 GB+ RAM and `vm.max_map_count=524288`. Create the project and a token in the UI, then add `SONAR_TOKEN` and `SONAR_HOST_URL` (public URL, port 9000 behind TLS) as repo secrets. Community Build analyses the main branch only; PR decoration is a paid feature, so CI blocks on `sonar.qualitygate.wait=true` instead.

Fly.io caveat: Sonar's embedded Elasticsearch needs the `vm.max_map_count` sysctl and ~2 GB RAM. A small VPS or a Docker host is the simpler home for it; Fly suits the watcher.

## 2. CVE watcher (AL-002)

`Dockerfile.watcher` installs the package and runs `ai-lifeguard watch` against the manifests copied into `/app`. Every `WATCH_INTERVAL` seconds it fetches the cve.now JSON feed, matches dependency names, and opens one GitHub issue per new CVE (deduped by title, labels `security`, `cve`).

Needs one secret: `GITHUB_TOKEN`, a fine-grained PAT with Issues: read/write on the target repo.

```
fly launch --no-deploy --copy-config --config deploy/fly.watcher.toml --dockerfile deploy/Dockerfile.watcher
fly secrets set GITHUB_TOKEN=github_pat_...
fly deploy --config deploy/fly.watcher.toml --dockerfile deploy/Dockerfile.watcher
```

Build from the repo root so `src/` and `pyproject.toml` are in the context. To watch another project, mount its manifests at `/app` and set `GITHUB_REPO`.

## 3. GitHub repo settings (AL-003)

Code scanning (receives the Semgrep SARIF) and Dependabot alerts are on by default for public repos; confirm under Settings → Security.
