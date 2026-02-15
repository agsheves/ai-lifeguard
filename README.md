# AI Lifeguard

---
## ⚠️ This is a work in progress and published _as is_. Test before use in production code.


A lightweight Python library that monitors AI agent activity for security threats. Scan your codebase in development, guard inputs at runtime in production.

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

## Install

```bash
pip install ai-lifeguard
```

Zero dependencies. Optional YAML config support:

```bash
pip install ai-lifeguard[yaml]
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

MIT

---

Stay safe out there

<img width="352" height="348" alt="buchannon" src="https://github.com/user-attachments/assets/b1c81327-d468-4ef0-9080-1f41b68e2569" />


(credit: baywatch.fandom.com)
