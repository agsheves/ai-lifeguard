import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from .models import ThreatResult
from .stream_models import (
    InputType, ExecutionPath, CheckInput, CheckHandle, OrchestratorConfig,
)
from .kill_switch import KillSwitch
from . import command_validator
from . import file_access_monitor
from . import prompt_checker
from . import connection_validator
from . import mcp_guardian
from . import dependency_auditor

log = logging.getLogger("ai_lifeguard.orchestrator")


class StreamOrchestrator:

    def __init__(self, config=None, lifeguard_instance=None):
        self._config = config or OrchestratorConfig()
        self._lifeguard = lifeguard_instance

        self._kill_switch = KillSwitch(
            severity_map=self._config.severity_map,
            on_threat=self._config.on_threat,
            isolation_callbacks=list(self._config.isolation_callbacks),
            kill_callbacks=list(self._config.kill_callbacks),
        )

        self._pool = ThreadPoolExecutor(
            max_workers=self._config.max_workers,
            thread_name_prefix="lifeguard-check",
        )

        self._active_handles = []
        self._lock = threading.Lock()
        self._shutdown = False

    @property
    def kill_switch(self):
        return self._kill_switch

    def submit(self, input_type, payload, source_id="", metadata=None,
               force_serial=False):
        if self._shutdown:
            raise RuntimeError("Orchestrator has been shut down")

        check_input = CheckInput(
            input_type=input_type,
            payload=payload,
            source_id=source_id,
            metadata=metadata or {},
        )

        handle = CheckHandle(input=check_input)

        path = (ExecutionPath.SERIAL if force_serial
                else self._config.routing.get(input_type, ExecutionPath.SERIAL))

        if path == ExecutionPath.SERIAL:
            result = self._run_check(check_input)
            handle._set_result(result)
            if not result.safe:
                self._kill_switch.engage(result, check_input)
            return handle

        with self._lock:
            self._active_handles.append(handle)
        self._pool.submit(self._parallel_worker, check_input, handle)
        return handle

    def submit_batch(self, items):
        handles = []
        for item in items:
            if len(item) == 2:
                input_type, payload = item
                source_id = ""
            else:
                input_type, payload, source_id = item[0], item[1], item[2]
            handles.append(self.submit(input_type, payload, source_id=source_id))
        return handles

    def wait_all(self, handles, timeout=None):
        results = []
        for handle in handles:
            handle.wait(timeout=timeout)
            results.append(handle.result)
        return results

    def shutdown(self, wait=True):
        self._shutdown = True
        self._pool.shutdown(wait=wait)

    def _parallel_worker(self, check_input, handle):
        try:
            result = self._run_check(check_input)
            handle._set_result(result)
            if not result.safe:
                self._kill_switch.engage(result, check_input)
        except Exception as e:
            log.error("Check failed for %s: %s", check_input.input_type, e)
            handle._set_result(ThreatResult(
                safe=False,
                level="high",
                module="orchestrator",
                description=f"Check failed with error: {e}",
                matched_rule="check_error",
            ))
        finally:
            with self._lock:
                if handle in self._active_handles:
                    self._active_handles.remove(handle)

    def _run_check(self, check_input):
        payload = check_input.payload
        meta = check_input.metadata

        allowed_commands = None
        allowed_domains = None
        trusted_mcps = None
        if self._lifeguard:
            allowed_commands = self._lifeguard._allowed_commands or None
            allowed_domains = self._lifeguard._allowed_domains or None
            trusted_mcps = self._lifeguard._trusted_mcps or None

        dispatch = {
            InputType.COMMAND: lambda: command_validator.check_command(
                payload, allowed_commands),
            InputType.FILE_ACCESS: lambda: file_access_monitor.check_file_access(
                payload),
            InputType.PROMPT: lambda: prompt_checker.check_prompt(
                payload),
            InputType.ENDPOINT: lambda: connection_validator.check_endpoint(
                payload, allowed_domains),
            InputType.MCP: lambda: mcp_guardian.check_mcp(
                payload, meta.get("permissions"), trusted_mcps),
            InputType.DEPENDENCY: lambda: dependency_auditor.check_dependency(
                payload),
        }

        handler = dispatch.get(check_input.input_type)
        if handler:
            return handler()

        return ThreatResult(
            safe=False,
            level="medium",
            module="orchestrator",
            description=f"Unknown input type: {check_input.input_type}",
            matched_rule="unknown_type",
        )
