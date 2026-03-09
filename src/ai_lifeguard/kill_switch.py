import logging
import threading
from .stream_models import SeverityResponse, KillSwitchEvent, DEFAULT_SEVERITY_MAP

log = logging.getLogger("ai_lifeguard.kill_switch")


class KillSwitch:

    def __init__(self, severity_map=None, on_threat=None,
                 isolation_callbacks=None, kill_callbacks=None):
        self._severity_map = severity_map or dict(DEFAULT_SEVERITY_MAP)
        self._on_threat = on_threat
        self._isolation_callbacks = list(isolation_callbacks or [])
        self._kill_callbacks = list(kill_callbacks or [])
        self._lock = threading.Lock()
        self._engaged = False
        self._event_log = []

    @property
    def engaged(self):
        return self._engaged

    @property
    def event_log(self):
        with self._lock:
            return list(self._event_log)

    def engage(self, threat_result, source_input):
        response = self._severity_map.get(
            threat_result.level, SeverityResponse.ALERT
        )

        event = KillSwitchEvent(
            threat_result=threat_result,
            source_input=source_input,
            response_taken=response,
        )

        with self._lock:
            self._engaged = True

            if response == SeverityResponse.LOG:
                log.warning(
                    "[KILL_SWITCH:LOG] %s | source=%s",
                    threat_result.description, source_input.source_id,
                )

            elif response == SeverityResponse.ALERT:
                log.warning(
                    "[KILL_SWITCH:ALERT] %s | source=%s",
                    threat_result.description, source_input.source_id,
                )
                self._invoke_on_threat(threat_result, event)

            elif response == SeverityResponse.ISOLATE:
                log.critical(
                    "[KILL_SWITCH:ISOLATE] %s | source=%s",
                    threat_result.description, source_input.source_id,
                )
                self._invoke_on_threat(threat_result, event)
                self._invoke_isolation(event)

            elif response == SeverityResponse.KILL:
                log.critical(
                    "[KILL_SWITCH:KILL] %s | source=%s",
                    threat_result.description, source_input.source_id,
                )
                self._invoke_on_threat(threat_result, event)
                self._invoke_isolation(event)
                self._invoke_kill(event)

            self._event_log.append(event)

        return event

    def reset(self):
        with self._lock:
            self._engaged = False

    def add_isolation_callback(self, callback):
        with self._lock:
            self._isolation_callbacks.append(callback)

    def add_kill_callback(self, callback):
        with self._lock:
            self._kill_callbacks.append(callback)

    def _invoke_on_threat(self, threat_result, event):
        if not self._on_threat:
            return
        try:
            self._on_threat(threat_result)
            event.callbacks_invoked.append("on_threat")
        except Exception as e:
            event.errors.append(f"on_threat: {e}")
            log.error("on_threat callback failed: %s", e)

    def _invoke_isolation(self, event):
        for cb in self._isolation_callbacks:
            name = getattr(cb, "__name__", repr(cb))
            try:
                cb(event)
                event.callbacks_invoked.append(f"isolate:{name}")
            except Exception as e:
                event.errors.append(f"isolate:{name}: {e}")
                log.error("Isolation callback %s failed: %s", name, e)

    def _invoke_kill(self, event):
        for cb in self._kill_callbacks:
            name = getattr(cb, "__name__", repr(cb))
            try:
                cb(event)
                event.callbacks_invoked.append(f"kill:{name}")
            except Exception as e:
                event.errors.append(f"kill:{name}: {e}")
                log.error("Kill callback %s failed: %s", name, e)
