import argparse
import json
import logging
import os
import sys
from pathlib import Path
from . import Lifeguard, sast_scanner
from .github_notifier import GitHubIssueNotifier

LEVEL_ORDER = ["none", "low", "medium", "high", "critical"]
ENV_TEMPLATE = """# AI Lifeguard integrations. Copy to .env (gitignored) and fill in what you use.
# Every integration is optional and off until its key is present. See THIRD_PARTY_NOTICES.md.

# Semgrep registry packs (p/python, p/default). Semgrep Rules License: internal use only,
# not for competing products. Set to true to opt in; the bundled MIT rule pack always runs.
SEMGREP_REGISTRY=false
# Optional: token from semgrep.dev so your Semgrep fetches rules as a logged-in user.
SEMGREP_APP_TOKEN=

# SonarQube: token from your server or SonarQube Cloud. Host URL only for self-hosted.
SONAR_TOKEN=
SONAR_HOST_URL=

# GitHub fine-grained PAT with Issues: read/write on the target repo (ai-lifeguard watch --github-repo).
GITHUB_TOKEN=
"""


def _rank(level):
    return LEVEL_ORDER.index(level) if level in LEVEL_ORDER else 2


def _guard(config_path):
    if config_path:
        return Lifeguard.from_config(config_path)
    return Lifeguard(mode="dev")


def _print_reports(reports, as_json):
    threats = [t for r in reports for t in r.threats]
    if as_json:
        print(json.dumps({
            "reports": [{"module": r.module, "files_scanned": r.files_scanned, "threats": len(r.threats)} for r in reports],
            "threats": [t.__dict__ for t in threats],
        }, indent=2))
        return threats
    print(f"{'module':<22}{'files':>6}{'threats':>9}  worst")
    for r in reports:
        worst = max((t.level for t in r.threats), key=_rank, default="none")
        print(f"{r.module:<22}{r.files_scanned:>6}{len(r.threats):>9}  {worst}")
    for t in sorted(threats, key=lambda t: -_rank(t.level)):
        print(f"[{t.level.upper()}] {t.module}: {t.description}")
    return threats


def cmd_scan(args):
    guard = _guard(args.config)
    reports = []
    if args.all or not (args.sast or args.deps or args.sonar):
        reports.extend(guard.scan_all(args.dir))
    if args.sast:
        reports.append(guard.scan_sast(args.dir, registry=True if args.registry else None))
    if args.deps:
        reports.append(guard.scan_dependencies(args.dir))
    if args.sonar:
        reports.append(guard.scan_sonar())
    threats = _print_reports(reports, args.json)
    failing = [t for t in threats if _rank(t.level) >= _rank(args.fail_on)]
    return 1 if failing else 0


def cmd_watch(args):
    guard = _guard(args.config)
    notifier = None
    if args.github_repo:
        token = os.environ.get("GITHUB_TOKEN", "")
        if not token:
            print("GITHUB_TOKEN not set; cannot open issues", file=sys.stderr)
            return 2
        notifier = GitHubIssueNotifier(args.github_repo, token)
    watcher = guard.watch_dependencies(args.dir, interval=args.interval, notifier=notifier, start=False)
    print(f"Watching {len(watcher.dependencies)} dependencies every {args.interval}s")
    if args.once:
        new = watcher.poll()
        for t in new:
            print(f"[{t.level.upper()}] {t.description}")
        return 1 if new else 0
    watcher.start()
    try:
        while watcher.is_alive():
            watcher.join(1)
    except KeyboardInterrupt:
        watcher.stop(timeout=5)
    return 0


def cmd_setup(args):
    guard = _guard(args.config)
    env = lambda name: bool(os.environ.get(name))
    rows = [
        ("semgrep binary", sast_scanner.semgrep_available(), "pip install ai-lifeguard[sast]"),
        ("semgrep registry packs", sast_scanner.registry_enabled(guard.config.get("semgrep")), "SEMGREP_REGISTRY=true or semgrep.registry: true (licence: THIRD_PARTY_NOTICES.md)"),
        ("SEMGREP_APP_TOKEN", env("SEMGREP_APP_TOKEN"), "optional; token from semgrep.dev"),
        ("SONAR_TOKEN", env("SONAR_TOKEN"), "token from your SonarQube server or SonarQube Cloud"),
        ("SONAR_HOST_URL", env("SONAR_HOST_URL"), "self-hosted Sonar only; Cloud uses sonar.host_url in config"),
        ("GITHUB_TOKEN", env("GITHUB_TOKEN"), "fine-grained PAT, Issues: read/write, for watch --github-repo"),
    ]
    if args.write_env:
        target = Path(args.dir) / ".env"
        if target.exists():
            print(f"{target} exists; left untouched")
        else:
            target.write_text(ENV_TEMPLATE)
            print(f"wrote {target}; fill in the keys you use")
    print(f"{'integration':<24}{'status':<10}how to enable")
    for name, on, how in rows:
        print(f"{name:<24}{'on' if on else 'off':<10}{'' if on else how}")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="ai-lifeguard", description="Scan code and dependencies, or watch for new CVEs")
    parser.add_argument("--config", help="config.yaml or .json")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="run scanners once and exit non-zero on findings")
    scan.add_argument("--dir", default=".")
    scan.add_argument("--all", action="store_true", help="behaviour scanners (default when no other flag given)")
    scan.add_argument("--sast", action="store_true", help="Semgrep scan (bundled rule pack)")
    scan.add_argument("--registry", action="store_true", help="also use Semgrep registry packs (opt-in, see THIRD_PARTY_NOTICES.md)")
    scan.add_argument("--deps", action="store_true", help="dependency CVE scan (network)")
    scan.add_argument("--sonar", action="store_true", help="pull SonarQube issues (network, needs SONAR_TOKEN)")
    scan.add_argument("--fail-on", default="high", choices=LEVEL_ORDER[1:])
    scan.add_argument("--json", action="store_true")
    scan.set_defaults(func=cmd_scan)
    watch = sub.add_parser("watch", help="poll the CVE feed for dependency matches")
    watch.add_argument("--dir", default=".")
    watch.add_argument("--interval", type=int, default=900)
    watch.add_argument("--github-repo", help="owner/name to open issues in (needs GITHUB_TOKEN)")
    watch.add_argument("--once", action="store_true", help="poll once and exit 1 if anything matched")
    watch.set_defaults(func=cmd_watch)
    setup = sub.add_parser("setup", help="show which optional tools and keys are configured")
    setup.add_argument("--dir", default=".")
    setup.add_argument("--write-env", action="store_true", help="write a .env template here if none exists")
    setup.set_defaults(func=cmd_setup)
    return parser


def main(argv=None):
    logging.basicConfig(level=logging.WARNING, format="%(name)s: %(message)s")
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        logging.getLogger("ai_lifeguard").setLevel(logging.ERROR)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
