import logging
import os
from .models import ThreatResult, ScanReport
from .stream_models import InputType, ExecutionPath, OrchestratorConfig
from .orchestrator import StreamOrchestrator
from .kill_switch import KillSwitch
from . import config as _config
from . import command_validator
from . import file_access_monitor
from . import prompt_checker
from . import connection_validator
from . import mcp_guardian
from . import dependency_auditor
from . import sast_scanner
from . import sonar_adapter
from .dependency_auditor import CveWatcher
from .github_notifier import GitHubIssueNotifier
from .help import show_help

__all__ = [
    "Lifeguard", "ThreatResult", "ScanReport",
    "StreamOrchestrator", "InputType", "ExecutionPath", "OrchestratorConfig",
    "KillSwitch", "CveWatcher", "GitHubIssueNotifier",
]

log = logging.getLogger("ai_lifeguard")


class Lifeguard:

    def __init__(self, mode="dev", on_threat=None, config=None):
        self.mode = mode
        self.on_threat = on_threat
        self.config = config or {}

        self._allowed_domains = self.config.get("allowed_domains", [])
        self._allowed_commands = self.config.get("allowed_commands", [])
        self._trusted_mcps = self.config.get("trusted_mcps", [])
        self._feed_url = self.config.get("cve_feed_url", dependency_auditor.FEED_URL)

        if mode == "dev":
            logging.basicConfig(level=logging.WARNING, format="%(name)s: %(message)s")

    @classmethod
    def from_config(cls, path, on_threat=None):
        cfg = _config.load_config(path)
        mode = cfg.get("mode", "dev")
        return cls(mode=mode, on_threat=on_threat, config=cfg)

    def help(self):
        show_help()

    # --- Production: single-input checks ---

    def check_command(self, cmd):
        result = command_validator.check_command(cmd, self._allowed_commands or None)
        self._handle(result)
        return result

    def check_file_access(self, path):
        result = file_access_monitor.check_file_access(path)
        self._handle(result)
        return result

    def check_prompt(self, text):
        result = prompt_checker.check_prompt(text)
        self._handle(result)
        return result

    def check_endpoint(self, url):
        result = connection_validator.check_endpoint(url, self._allowed_domains or None)
        self._handle(result)
        return result

    def check_mcp(self, server_name, permissions=None):
        result = mcp_guardian.check_mcp(server_name, permissions, self._trusted_mcps or None)
        self._handle(result)
        return result

    def check_dependency(self, spec):
        result = dependency_auditor.check_dependency(spec, feed_url=self._feed_url)
        self._handle(result)
        return result

    # --- Dev: bulk static analysis ---

    def scan_all(self, directory=".", network=False):
        reports = [
            self.scan_commands(directory),
            self.scan_files(directory),
            self.scan_prompts(directory),
            self.scan_connections(directory),
            self.scan_mcps(directory),
        ]
        if sast_scanner.semgrep_available():
            reports.append(self.scan_sast(directory, registry=None if network else False))
        if network:
            reports.append(self.scan_dependencies(directory))
            if self.config.get("sonar"):
                reports.append(self.scan_sonar())
        return reports

    def scan_commands(self, directory="."):
        report = command_validator.scan_commands(directory)
        self._handle_report(report)
        return report

    def scan_files(self, directory="."):
        report = file_access_monitor.scan_files(directory)
        self._handle_report(report)
        return report

    def scan_prompts(self, directory="."):
        report = prompt_checker.scan_prompts(directory)
        self._handle_report(report)
        return report

    def scan_connections(self, directory="."):
        report = connection_validator.scan_connections(directory, self._allowed_domains or None)
        self._handle_report(report)
        return report

    def scan_mcps(self, directory="."):
        report = mcp_guardian.scan_mcps(directory, self._trusted_mcps or None)
        self._handle_report(report)
        return report

    # --- Code & dependency security (opt-in: shells out or uses the network) ---

    def scan_sast(self, directory=".", registry=None):
        cfg = self.config.get("semgrep", {})
        if registry is None:
            registry = sast_scanner.registry_enabled(cfg)
        report = sast_scanner.scan_sast(
            directory, configs=cfg.get("configs") or None, registry=registry,
            timeout=cfg.get("timeout", 600),
        )
        self._handle_report(report)
        return report

    def scan_dependencies(self, directory="."):
        report = dependency_auditor.scan_dependencies(directory, self._feed_url)
        self._handle_report(report)
        return report

    def scan_sonar(self):
        cfg = self.config.get("sonar", {})
        token = os.environ.get(cfg.get("token_env", "SONAR_TOKEN"), "")
        report = sonar_adapter.scan_sonar(
            cfg.get("host_url", ""), cfg.get("project_key", ""), token,
            severities=tuple(cfg.get("severities", sonar_adapter.DEFAULT_SEVERITIES)),
        )
        self._handle_report(report)
        return report

    def watch_dependencies(self, directory=".", interval=900, orchestrator=None,
                           notifier=None, dependencies=None, start=True):
        deps = dependencies or dependency_auditor.parse_manifests(directory)
        watcher = CveWatcher(
            deps, interval=interval, feed_url=self._feed_url,
            on_threat=None if orchestrator else self._handle,
            kill_switch=orchestrator.kill_switch if orchestrator else None,
            notifier=notifier,
        )
        if start:
            watcher.start()
        return watcher

    # --- Internal ---

    def _handle(self, result):
        if result.safe:
            return
        log.warning("[%s] %s", result.level.upper(), result.description)
        if self.mode == "production" and self.on_threat:
            self.on_threat(result)

    def _handle_report(self, report):
        for threat in report.threats:
            self._handle(threat)

    # --- Stream Orchestrator ---

    def create_orchestrator(self, config=None, **kwargs):
        if config is None:
            config = OrchestratorConfig(on_threat=self.on_threat, **kwargs)
        return StreamOrchestrator(config=config, lifeguard_instance=self)
