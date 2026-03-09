import threading
from ai_lifeguard.models import ThreatResult
from ai_lifeguard.stream_models import (
    CheckInput, InputType, SeverityResponse, DEFAULT_SEVERITY_MAP,
)
from ai_lifeguard.kill_switch import KillSwitch


def _make_threat(level="medium"):
    return ThreatResult(
        safe=False, level=level, module="test",
        description=f"Test threat ({level})", matched_rule="test_rule",
    )


def _make_input(source_id="test-source"):
    return CheckInput(
        input_type=InputType.COMMAND, payload="test", source_id=source_id,
    )


def test_log_level_no_callbacks():
    called = []
    ks = KillSwitch(on_threat=lambda r: called.append(r))
    event = ks.engage(_make_threat("low"), _make_input())
    assert event.response_taken == SeverityResponse.LOG
    assert called == []


def test_alert_level_calls_on_threat():
    called = []
    ks = KillSwitch(on_threat=lambda r: called.append(r))
    ks.engage(_make_threat("medium"), _make_input())
    assert len(called) == 1
    assert called[0].level == "medium"


def test_isolate_level_calls_isolation_callbacks():
    isolated = []
    ks = KillSwitch(
        on_threat=lambda r: None,
        isolation_callbacks=[lambda e: isolated.append(e.source_input.source_id)],
    )
    ks.engage(_make_threat("high"), _make_input("user-99"))
    assert isolated == ["user-99"]


def test_kill_level_calls_all_callbacks():
    on_threat_calls = []
    isolation_calls = []
    kill_calls = []

    ks = KillSwitch(
        on_threat=lambda r: on_threat_calls.append(r),
        isolation_callbacks=[lambda e: isolation_calls.append(True)],
        kill_callbacks=[lambda e: kill_calls.append(True)],
    )
    ks.engage(_make_threat("critical"), _make_input())

    assert len(on_threat_calls) == 1
    assert len(isolation_calls) == 1
    assert len(kill_calls) == 1


def test_engaged_flag():
    ks = KillSwitch()
    assert not ks.engaged
    ks.engage(_make_threat("low"), _make_input())
    assert ks.engaged


def test_reset_clears_engaged():
    ks = KillSwitch()
    ks.engage(_make_threat("low"), _make_input())
    ks.reset()
    assert not ks.engaged


def test_event_log_records():
    ks = KillSwitch()
    ks.engage(_make_threat("low"), _make_input("src-1"))
    ks.engage(_make_threat("high"), _make_input("src-2"))
    log = ks.event_log
    assert len(log) == 2
    assert log[0].source_input.source_id == "src-1"
    assert log[1].source_input.source_id == "src-2"


def test_callback_exception_recorded():
    def bad_callback(event):
        raise ValueError("boom")

    ks = KillSwitch(isolation_callbacks=[bad_callback])
    event = ks.engage(_make_threat("high"), _make_input())
    assert len(event.errors) == 1
    assert "boom" in event.errors[0]


def test_concurrent_engage():
    ks = KillSwitch()
    barrier = threading.Barrier(10)

    def engage_one():
        barrier.wait()
        ks.engage(_make_threat("medium"), _make_input())

    threads = [threading.Thread(target=engage_one) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(ks.event_log) == 10


def test_add_callbacks_after_init():
    isolation_calls = []
    kill_calls = []

    ks = KillSwitch()
    ks.add_isolation_callback(lambda e: isolation_calls.append(True))
    ks.add_kill_callback(lambda e: kill_calls.append(True))

    ks.engage(_make_threat("critical"), _make_input())
    assert len(isolation_calls) == 1
    assert len(kill_calls) == 1


def test_custom_severity_map():
    called = []
    custom_map = {"low": SeverityResponse.KILL}
    ks = KillSwitch(
        severity_map=custom_map,
        kill_callbacks=[lambda e: called.append(True)],
    )
    ks.engage(_make_threat("low"), _make_input())
    assert len(called) == 1
