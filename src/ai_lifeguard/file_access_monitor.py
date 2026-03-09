import re
import time
import logging
import threading
from . import config
from .models import ThreatResult, ScanReport
from ._scanner import walk_files, extract_matches

log = logging.getLogger("ai_lifeguard.file_access_monitor")

FILE_SOURCE_PATTERNS = re.compile(
    r'open\s*\(\s*["\']([^"\']+)["\']'
    r'|Path\s*\(\s*["\']([^"\']+)["\']'
    r'|read_text\s*\(\s*["\']([^"\']+)["\']'
    r'|read_file\s*\(\s*["\']([^"\']+)["\']',
)

_access_log = []
_access_lock = threading.Lock()
BULK_THRESHOLD = 20
BULK_WINDOW = 5


MAX_INPUT_LENGTH = 4_000


def check_file_access(path):
    if len(path) > MAX_INPUT_LENGTH:
        return ThreatResult(
            safe=False, level="high", module="file_access_monitor",
            description=f"Input exceeds max length ({len(path)} > {MAX_INPUT_LENGTH})",
            matched_rule="input_too_long",
        )

    defaults = config.sensitive_paths()

    if _check_bulk_access(path):
        return ThreatResult(
            safe=False,
            level="high",
            module="file_access_monitor",
            description=f"Bulk file access detected ({BULK_THRESHOLD}+ reads in {BULK_WINDOW}s)",
            matched_rule="bulk_exfiltration",
        )

    for category, patterns in defaults.items():
        for pattern in patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return ThreatResult(
                    safe=False,
                    level=_level_for(category),
                    module="file_access_monitor",
                    description=f"Access to {category} path: {path}",
                    matched_rule=pattern,
                )

    if "\x00" in path:
        return ThreatResult(
            safe=False,
            level="critical",
            module="file_access_monitor",
            description="Null byte in file path",
            matched_rule="null_byte",
        )

    return ThreatResult(safe=True, module="file_access_monitor")


def scan_files(directory):
    report = ScanReport(module="file_access_monitor")

    for filepath in walk_files(directory):
        report.files_scanned += 1
        matches = extract_matches(filepath, FILE_SOURCE_PATTERNS)

        for match_text, _ in matches:
            groups = FILE_SOURCE_PATTERNS.search(match_text)
            if not groups:
                continue
            target = next((g for g in groups.groups() if g), None)
            if not target:
                continue

            result = check_file_access(target)
            if not result.safe:
                result.description = f"{filepath}: {result.description}"
                report.threats.append(result)
                log.warning("%s: %s", filepath, result.description)

    return report


def reset_bulk_tracker():
    with _access_lock:
        _access_log.clear()


def _check_bulk_access(path):
    now = time.time()
    with _access_lock:
        _access_log.append(now)
        cutoff = now - BULK_WINDOW
        while _access_log and _access_log[0] < cutoff:
            _access_log.pop(0)
        return len(_access_log) >= BULK_THRESHOLD


def _level_for(category):
    return {
        "credentials": "critical",
        "system": "high",
        "hidden_config": "high",
        "traversal": "critical",
    }.get(category, "medium")
