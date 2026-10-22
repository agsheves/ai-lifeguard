from dataclasses import dataclass, field
from enum import Enum
import threading
import time


class InputType(Enum):
    COMMAND = "command"
    FILE_ACCESS = "file_access"
    PROMPT = "prompt"
    ENDPOINT = "endpoint"
    MCP = "mcp"
    DEPENDENCY = "dependency"


class ExecutionPath(Enum):
    SERIAL = "serial"
    PARALLEL = "parallel"


class SeverityResponse(Enum):
    LOG = "log"
    ALERT = "alert"
    ISOLATE = "isolate"
    KILL = "kill"


DEFAULT_ROUTING = {
    InputType.COMMAND: ExecutionPath.SERIAL,
    InputType.FILE_ACCESS: ExecutionPath.SERIAL,
    InputType.PROMPT: ExecutionPath.PARALLEL,
    InputType.ENDPOINT: ExecutionPath.PARALLEL,
    InputType.MCP: ExecutionPath.PARALLEL,
    InputType.DEPENDENCY: ExecutionPath.PARALLEL,
}

DEFAULT_SEVERITY_MAP = {
    "low": SeverityResponse.LOG,
    "medium": SeverityResponse.ALERT,
    "high": SeverityResponse.ISOLATE,
    "critical": SeverityResponse.KILL,
}


@dataclass
class CheckInput:
    input_type: InputType
    payload: object
    source_id: str = ""
    submitted_at: float = field(default_factory=time.time)
    metadata: dict = field(default_factory=dict)


@dataclass
class CheckHandle:
    input: CheckInput
    _event: threading.Event = field(default_factory=threading.Event, repr=False)
    _result: object = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def done(self):
        return self._event.is_set()

    @property
    def result(self):
        if self._event.is_set():
            return self._result
        return None

    def wait(self, timeout=None):
        self._event.wait(timeout=timeout)
        return self._result

    def _set_result(self, result):
        with self._lock:
            self._result = result
            self._event.set()


@dataclass
class KillSwitchEvent:
    threat_result: object
    source_input: CheckInput
    response_taken: SeverityResponse
    timestamp: float = field(default_factory=time.time)
    callbacks_invoked: list = field(default_factory=list)
    errors: list = field(default_factory=list)


@dataclass
class OrchestratorConfig:
    routing: dict = field(default_factory=lambda: dict(DEFAULT_ROUTING))
    severity_map: dict = field(default_factory=lambda: dict(DEFAULT_SEVERITY_MAP))
    max_workers: int = 4
    on_threat: object = None
    isolation_callbacks: list = field(default_factory=list)
    kill_callbacks: list = field(default_factory=list)
