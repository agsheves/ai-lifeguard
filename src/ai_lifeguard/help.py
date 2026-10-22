HELP_TEXT = """
AI Lifeguard v0.2.0
====================

Two modes, one class:

  guard = Lifeguard(mode="dev")           # scan code before deploy
  guard = Lifeguard(mode="production")    # guard inputs at runtime

Dev — scan your codebase:

  guard.scan_all("./src")          Run all scanners
  guard.scan_commands("./src")     Find dangerous shell commands
  guard.scan_files("./src")        Find sensitive file access
  guard.scan_prompts("./src")      Find prompt injection risks
  guard.scan_connections("./src")  Find suspicious URLs/endpoints
  guard.scan_mcps("./src")         Find untrusted MCP configs
  guard.scan_all("./src", network=True)   Also run SAST, CVE and Sonar scans

Code & dependency security (opt-in; shells out or uses the network):

  guard.scan_sast("./src")         Semgrep: bundled rule pack + p/python + p/default
  guard.scan_dependencies(".")     Match requirements/pyproject/package.json against cve.now
  guard.scan_sonar()               Pull open issues + quality gate from SonarQube (config: sonar:)
  guard.check_dependency("pkg==1.0")      Check one dependency against the CVE feed
  guard.watch_dependencies(".", interval=900, orchestrator=orch, notifier=None)
                                   Background CveWatcher; alerts once per new CVE match

  pip install ai-lifeguard[sast]   installs semgrep
  ai-lifeguard scan --dir . --sast --deps --fail-on high     CLI for CI
  ai-lifeguard watch --dir . --github-repo owner/name        Hosted watcher -> GitHub issues

Production — check individual inputs:

  guard.check_command(cmd)              Validate a shell command
  guard.check_file_access(path)         Validate a file path
  guard.check_prompt(text)              Check for prompt injection
  guard.check_endpoint(url)             Validate a URL/endpoint
  guard.check_mcp(name, permissions)    Validate an MCP connection
  guard.check_dependency(spec)          Check a dependency against the CVE feed

Every method returns a ThreatResult:

  result.safe          bool — True if no threat detected
  result.level         "none" | "low" | "medium" | "high" | "critical"
  result.module        Which checker flagged it
  result.description   What was found
  result.matched_rule  Which pattern triggered

Production callbacks:

  def alert(result):
      send_slack(result.description)

  guard = Lifeguard(mode="production", on_threat=alert)

Stream Orchestrator — hybrid serial/parallel checking:

  orch = guard.create_orchestrator(
      isolation_callbacks=[disable_chat],
      kill_callbacks=[kill_process],
  )

  handle = orch.submit(InputType.COMMAND, cmd, source_id="user-42")
  handle = orch.submit(InputType.PROMPT, text, source_id="session-7")

  handles = orch.submit_batch([
      (InputType.COMMAND, cmd, "src-1"),
      (InputType.PROMPT, text, "src-2"),
  ])

  results = orch.wait_all(handles)

  Serial checks (COMMAND, FILE_ACCESS) block until complete.
  Parallel checks (PROMPT, ENDPOINT, MCP, DEPENDENCY) run in background threads.

Kill Switch — automatic escalation on threat detection:

  Severity     Response
  low          Log only
  medium       Log + on_threat callback
  high         Log + on_threat + isolation callbacks
  critical     Log + on_threat + isolation + kill callbacks

  orch.kill_switch.engaged     True if any threat triggered isolation
  orch.kill_switch.event_log   Audit trail of all engagements
  orch.kill_switch.reset()     Clear engaged state after review

Config:

  guard = Lifeguard.from_config("config.yaml")   # or .json

Docs: https://github.com/agsheves/ai-lifeguard/blob/main/README.md
""".strip()


def show_help():
    print(HELP_TEXT)
