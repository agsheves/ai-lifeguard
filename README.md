# AI Lifeguard

A lightweight Python library that monitors AI agent activity for security threats. Scan your codebase in development, guard inputs at runtime in production.

---
## ⚠️ This is a work in progress and published _as is_. Test before use in production code.


## The Problem

AI agents can read files, run commands, make network connections, and interact with MCP servers. That's powerful — and risky. A prompt injection can trick an agent into exfiltrating `.env` files. A typosquatted URL can go unnoticed. An MCP server can request permissions it doesn't need.

AI Lifeguard catches these threats with fast, local, regex-based checks. No external API calls. No LLM in the loop. Sub-millisecond per check.

## What It Monitors

| Module | Threats Detected |
|--------|-----------------|
| **command_validator** | Destructive commands (`rm -rf`), command chaining, subshell injection, encoded payloads |
| **file_access_monitor** | Credential access (`.env`, `.ssh`), path traversal, bulk exfiltration, null byte injection |
| **prompt_checker** | Instruction overrides, role hijacking, delimiter injection, privilege escalation |
| **connection_validator** | Homograph attacks, typosquatting, punycode spoofing, IP obfuscation, subdomain spoofing |
| **mcp_guardian** | Name spoofing, permission overreach, untrusted servers, tool shadowing |
| **dependency_auditor** | Dependencies named in new CVEs (cve.now feed), background watch, GitHub issue notifier |
| **sast_scanner** | Semgrep static analysis: bundled MIT rule pack for agent code, registry packs opt-in |
| **sonar_adapter** | Open SonarQube issues and quality-gate status pulled into the same report format |

## Install

```bash
pip install ai-lifeguard
```

Zero dependencies. Optional extras:

```bash
pip install ai-lifeguard[yaml]      # YAML config files
pip install ai-lifeguard[sast]      # Semgrep for scan_sast()
pip install ai-lifeguard[security]  # both
```

## Quick Start

```python
from ai_lifeguard import Lifeguard

guard = Lifeguard()

# Check a command
result = guard.check_command("rm -rf /")
print(result.safe)        # False
print(result.level)       # "critical"
print(result.description) # "Blocked destructive pattern in command"

# Check a prompt
result = guard.check_prompt("Ignore all previous instructions")
print(result.safe)        # False

# Check a URL
result = guard.check_endpoint("https://gooogle.com")
print(result.safe)        # False — typosquat detected
```

## Two Modes

### Dev: scan your codebase before deploy

Walks your source tree, extracts commands/URLs/file paths/prompts, and checks each one. Run this in CI or as a pre-commit hook.

```python
guard = Lifeguard(mode="dev")

# Scan everything
reports = guard.scan_all("./src")

# Or scan individually
report = guard.scan_connections("./src")  # find all URLs, validate each
report = guard.scan_commands("./src")     # find shell commands, check for danger
report = guard.scan_files("./src")        # find file access, flag sensitive paths
report = guard.scan_prompts("./src")      # find prompts, check for injection risk
report = guard.scan_mcps("./src")         # find MCP configs, validate trust

for report in reports:
    if not report.clean:
        print(f"{report.module}: {len(report.threats)} threats found")
```

### Production: guard inputs at runtime

Your code is deployed. Now protect it from untrusted inputs — user prompts, new connections, MCP servers coming online.

```python
def alert_admin(result):
    send_slack(f"THREAT: {result.level} — {result.description}")

guard = Lifeguard(mode="production", on_threat=alert_admin)

# Gate user input before sending to an LLM
result = guard.check_prompt(user_input)
if not result.safe:
    return "Sorry, I can't process that request."

# Gate a URL before connecting
result = guard.check_endpoint(url)
if not result.safe:
    return block_request(result)

# Gate an MCP server before allowing it
result = guard.check_mcp("unknown-server", permissions=["file_write", "exec"])
if not result.safe:
    deny_connection(result)
```

## Code & Dependency Security

The five behaviour guards above are offline and regex-only. Since AI made bug-hunting cheap, the code itself and its dependencies need the same attention, so v0.2 adds three opt-in scanners. They shell out or use the network, so they never run unless you ask.

```python
guard = Lifeguard.from_config("config.yaml")

report = guard.scan_sast("./src")          # Semgrep: bundled rule pack (+ registry packs if opted in)
report = guard.scan_dependencies(".")      # requirements/pyproject/package.json vs cve.now feed
report = guard.scan_sonar()                # open SonarQube issues + quality gate (needs SONAR_TOKEN)
reports = guard.scan_all("./src", network=True)   # everything

result = guard.check_dependency("requests==2.31.0")   # one package, production mode
```

**Watch for new CVEs at runtime.** A daemon thread polls the feed and alerts once per new match. With an orchestrator it goes through the kill switch like any other threat; a dependency CVE is an alert, never `critical`.

```python
orch = guard.create_orchestrator()
watcher = guard.watch_dependencies(".", interval=900, orchestrator=orch)
...
watcher.stop()
```

**CLI for CI and servers.**

```bash
ai-lifeguard scan --dir src --sast --deps --fail-on high      # exit 1 on high/critical
ai-lifeguard watch --dir . --github-repo owner/name           # opens a GitHub issue per new CVE match
```

The bundled Semgrep rules live in `src/ai_lifeguard/defaults/semgrep_rules.yaml` (MIT) and run by default. Semgrep's registry packs (`p/python`, `p/default`) are off by default because they carry the Semgrep Rules License (internal use, not for competing products). Opt in with `SEMGREP_REGISTRY=true`, `semgrep.registry: true` or `scan --registry`; your own Semgrep install fetches them with metrics off. This repo runs all of this on itself in `.github/workflows/security.yml`; see `deploy/` for the hosted watcher and SonarQube server.

## Setting Up Your Fork

Everything optional is keyed off environment variables, so a fork needs no code changes.

```bash
pip install -e .[sast]
ai-lifeguard setup --write-env   # writes .env from .env_template if none exists, then shows what is on/off
```

| Key | Used by | Where to get it |
|---|---|---|
| `SEMGREP_REGISTRY` | `scan --sast`, CI | Set `true` only if your use fits the Semgrep Rules License (see `THIRD_PARTY_NOTICES.md`). In GitHub, a repository **variable**. |
| `SEMGREP_APP_TOKEN` | Semgrep | Optional. semgrep.dev → Settings → Tokens. Repository secret. |
| `SONAR_TOKEN`, `SONAR_HOST_URL` | `scan_sonar()`, CI | Your SonarQube server or SonarQube Cloud. Repository secrets. Set `sonar.project_key` in `config.yaml` and `sonar-project.properties`. |
| `GITHUB_TOKEN` | `ai-lifeguard watch --github-repo` | Fine-grained PAT, Issues: read/write on the target repo. Set on the watcher host, not in CI. |

`.env` is gitignored. Load it with your shell or process manager; the library only reads `os.environ`.

## Configuration

Works out of the box with sensible defaults. Override only what you need:

```yaml
# config.yaml
ai_lifeguard:
  mode: dev

  allowed_domains:
    - "api.openai.com"
    - "api.anthropic.com"

  trusted_mcps:
    - name: "filesystem"
      publisher: "anthropic"

  semgrep:
    registry: false         # true = also fetch Semgrep registry packs (needs network; see THIRD_PARTY_NOTICES.md)

  sonar:
    host_url: "https://sonarcloud.io"   # or your SonarQube Community Build server
    project_key: "org_project"
    token_env: SONAR_TOKEN              # token is read from the environment, never from this file
```

```python
guard = Lifeguard.from_config("config.yaml")
```

## Return Types

Every `check_*` method returns a `ThreatResult`:

```python
result.safe          # bool — True if no threat
result.level         # "none" | "low" | "medium" | "high" | "critical"
result.module        # which checker flagged it
result.description   # human-readable explanation
result.matched_rule  # which pattern triggered
```

Every `scan_*` method returns a `ScanReport`:

```python
report.module         # which scanner ran
report.files_scanned  # how many files were checked
report.threats        # list of ThreatResults
report.clean          # True if no threats found
```

## Help

```python
guard = Lifeguard()
guard.help()  # prints full method reference
```

## License

MIT. The tools and feeds the optional scanners call keep their own licences; see `THIRD_PARTY_NOTICES.md`.

---

Stay safe out there

<img width="352" height="348" alt="buchannon" src="https://github.com/user-attachments/assets/b1c81327-d468-4ef0-9080-1f41b68e2569" />


(credit: baywatch.fandom.com)
