import json
import logging
import re
import threading
import time
from ._http import fetch_json
from .models import ThreatResult, ScanReport
from .stream_models import InputType, CheckInput
from ._scanner import walk_named_files

log = logging.getLogger("ai_lifeguard.dependency_auditor")

FEED_URL = "https://cve.now/feed?format=json"
FEED_TTL = 900
FEED_TIMEOUT = 10
MAX_INPUT_LENGTH = 500
MANIFEST_PATTERNS = ("requirements*.txt", "pyproject.toml", "package.json")

SPEC_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:(?:==|>=|<=|~=|!=|>|<|@)\s*([^,;\s]+))?")
ECOSYSTEM_HINT = re.compile(r"\b(?:pypi|pip|python|npm|node(?:\.js)?|javascript|typescript)\b", re.I)
EXPLOITED = re.compile(r"(?:actively|known)\s+exploited|in the wild|\bKEV\b", re.I)

_feed_cache = {}
_cache_lock = threading.Lock()


def normalise(name):
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _name_pattern(name):
    parts = [re.escape(p) for p in normalise(name).split("-") if p]
    return re.compile(r"(?<![a-z0-9])" + r"[-_.]?".join(parts) + r"(?![a-z0-9])", re.I)


def _distinctive(name):
    return len(name) >= 10 or any(not c.isalpha() for c in name)


def parse_spec(spec):
    m = SPEC_RE.match(spec)
    if not m:
        return None, None
    return normalise(m.group(1)), m.group(2)


def fetch_feed(url=FEED_URL, timeout=FEED_TIMEOUT, ttl=FEED_TTL):
    with _cache_lock:
        cached = _feed_cache.get(url)
        if cached and time.time() - cached[0] < ttl:
            return cached[1]
    try:
        items = (fetch_json(url, timeout=timeout) or {}).get("items", [])
    except Exception as e:
        log.warning("CVE feed unavailable (%s): %s", url, e)
        return []
    with _cache_lock:
        _feed_cache[url] = (time.time(), items)
    return items


def clear_feed_cache():
    with _cache_lock:
        _feed_cache.clear()


def cve_id(item):
    return str(item.get("id", "")).split("#")[0]


def match_pairs(dependencies, items, seen=None):
    pairs = []
    for name, version in dependencies.items():
        pattern = _name_pattern(name)
        spec = f"{name}=={version}" if version else name
        for item in items:
            cid = cve_id(item)
            key = (normalise(name), cid)
            if seen is not None and key in seen:
                continue
            title = item.get("title", "")
            body = item.get("content_text", "")
            hint = bool(ECOSYSTEM_HINT.search(title + " " + body))
            if pattern.search(title) and (hint or _distinctive(name)):
                level = "medium"
            elif pattern.search(body) and hint:
                level = "low"
            else:
                continue
            if EXPLOITED.search(title + " " + body):
                level = "high"
            if seen is not None:
                seen.add(key)
            pairs.append((spec, ThreatResult(
                safe=False, level=level, module="dependency_auditor",
                description=f"{spec} matches {title} ({item.get('url', '')})",
                matched_rule=cid,
            )))
    return pairs


def match_feed(dependencies, items, seen=None):
    return [result for _, result in match_pairs(dependencies, items, seen)]


def check_dependency(spec, seen=None, feed_url=FEED_URL):
    if len(spec) > MAX_INPUT_LENGTH:
        return ThreatResult(
            safe=False, level="high", module="dependency_auditor",
            description=f"Input exceeds max length ({len(spec)} > {MAX_INPUT_LENGTH})",
            matched_rule="input_too_long",
        )
    name, version = parse_spec(spec)
    if not name:
        return ThreatResult(
            safe=False, level="low", module="dependency_auditor",
            description=f"Unparseable dependency spec: {spec!r}", matched_rule="bad_spec",
        )
    items = fetch_feed(feed_url)
    if not items:
        return ThreatResult(
            safe=True, level="low", module="dependency_auditor",
            description="CVE feed unavailable — dependency not checked", matched_rule="feed_unavailable",
        )
    threats = match_feed({name: version}, items, seen)
    return threats[0] if threats else ThreatResult(safe=True, module="dependency_auditor")


def parse_requirements(text):
    deps = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        name, version = parse_spec(line)
        if name:
            deps[name] = version
    return deps


def _parse_pyproject_fallback(text):
    deps = {}
    sections = re.finditer(r"^\[(project|project\.optional-dependencies|tool\.poetry\.dependencies)\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    for section in sections:
        name, body = section.group(1), section.group(2)
        if name == "tool.poetry.dependencies":
            for pkg, version in re.findall(r'^([A-Za-z0-9_.-]+)\s*=\s*"([^"]*)"', body, re.M):
                if pkg.lower() != "python":
                    deps[normalise(pkg)] = version.lstrip("^~=<>!") or None
            continue
        if name == "project":
            m = re.search(r"^dependencies\s*=\s*\[(.*?)\]", body, re.M | re.S)
            arrays = [m.group(1)] if m else []
        else:
            arrays = re.findall(r"=\s*\[(.*?)\]", body, re.S)
        for arr in arrays:
            for spec in re.findall(r"[\"']([^\"']+)[\"']", arr):
                pkg, version = parse_spec(spec)
                if pkg:
                    deps[pkg] = version
    return deps


def parse_pyproject(text):
    try:
        import tomllib
    except ImportError:
        log.info("tomllib unavailable (Python < 3.11); using regex fallback for pyproject.toml")
        return _parse_pyproject_fallback(text)
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        log.warning("Could not parse pyproject.toml: %s", e)
        return {}
    deps = {}
    project = data.get("project", {})
    specs = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        specs.extend(extra)
    for spec in specs:
        name, version = parse_spec(spec)
        if name:
            deps[name] = version
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, value in poetry.items():
        if name.lower() == "python":
            continue
        version = value if isinstance(value, str) else value.get("version") if isinstance(value, dict) else None
        deps[normalise(name)] = version.lstrip("^~=<>!") if version else None
    return deps


def parse_package_json(text):
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        log.warning("Could not parse package.json: %s", e)
        return {}
    deps = {}
    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            deps[normalise(name)] = version.lstrip("^~=<>") if isinstance(version, str) else None
    return deps


def parse_manifests(directory):
    deps = {}
    for path in walk_named_files(directory, MANIFEST_PATTERNS):
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        if path.name == "pyproject.toml":
            deps.update(parse_pyproject(text))
        elif path.name == "package.json":
            deps.update(parse_package_json(text))
        else:
            deps.update(parse_requirements(text))
    return deps


def scan_dependencies(directory, feed_url=FEED_URL):
    report = ScanReport(module="dependency_auditor")
    deps = parse_manifests(directory)
    report.files_scanned = len(deps)
    if not deps:
        return report
    items = fetch_feed(feed_url)
    if not items:
        report.threats.append(ThreatResult(
            safe=False, level="low", module="dependency_auditor",
            description="CVE feed unavailable — dependencies not checked", matched_rule="feed_unavailable",
        ))
        return report
    for result in match_feed(deps, items):
        report.threats.append(result)
        log.warning(result.description)
    return report


class CveWatcher(threading.Thread):

    def __init__(self, dependencies, interval=FEED_TTL, feed_url=FEED_URL,
                 on_threat=None, kill_switch=None, notifier=None, fetch=None):
        super().__init__(name="lifeguard-cve-watcher", daemon=True)
        self._dependencies = dict(dependencies)
        self._interval = interval
        self._feed_url = feed_url
        self._on_threat = on_threat
        self._kill_switch = kill_switch
        self._notifier = notifier
        self._fetch = fetch or (lambda: fetch_feed(self._feed_url, ttl=0))
        self._stop_event = threading.Event()
        self._seen = set()
        self.threats = []

    @property
    def dependencies(self):
        return dict(self._dependencies)

    def run(self):
        while not self._stop_event.is_set():
            try:
                self.poll()
            except Exception as e:
                log.error("CVE watcher poll failed: %s", e)
            self._stop_event.wait(self._interval)

    def poll(self):
        items = self._fetch()
        new = match_pairs(self._dependencies, items, seen=self._seen)
        for spec, result in new:
            self.threats.append(result)
            log.warning("[CVE_WATCH] %s", result.description)
            self._dispatch(spec, result)
        return [result for _, result in new]

    def stop(self, timeout=None):
        self._stop_event.set()
        if self.is_alive():
            self.join(timeout)

    def _dispatch(self, spec, result):
        for name, cb in (("on_threat", self._on_threat), ("notifier", self._notifier)):
            if not cb:
                continue
            try:
                cb(result)
            except Exception as e:
                log.error("CVE watcher %s callback failed: %s", name, e)
        if self._kill_switch:
            source = CheckInput(input_type=InputType.DEPENDENCY, payload=spec, source_id="cve_watcher")
            self._kill_switch.engage(result, source)
