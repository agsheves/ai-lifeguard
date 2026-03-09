import logging
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
from .help import show_help

__all__ = [
    "Lifeguard", "ThreatResult", "ScanReport",
    "StreamOrchestrator", "InputType", "ExecutionPath", "OrchestratorConfig",
    "KillSwitch",
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

    # --- Dev: bulk static analysis ---

    def scan_all(self, directory="."):
        return [
            self.scan_commands(directory),
            self.scan_files(directory),
            self.scan_prompts(directory),
            self.scan_connections(directory),
            self.scan_mcps(directory),
        ]

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
