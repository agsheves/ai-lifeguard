import argparse
import json
import logging
import os
import sys
from . import Lifeguard
from .github_notifier import GitHubIssueNotifier

LEVEL_ORDER = ["none", "low", "medium", "high", "critical"]


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
        reports.append(guard.scan_sast(args.dir))
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


def build_parser():
    parser = argparse.ArgumentParser(prog="ai-lifeguard", description="Scan code and dependencies, or watch for new CVEs")
    parser.add_argument("--config", help="config.yaml or .json")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="run scanners once and exit non-zero on findings")
    scan.add_argument("--dir", default=".")
    scan.add_argument("--all", action="store_true", help="behaviour scanners (default when no other flag given)")
    scan.add_argument("--sast", action="store_true", help="Semgrep scan")
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
    return parser


def main(argv=None):
    logging.basicConfig(level=logging.WARNING, format="%(name)s: %(message)s")
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        logging.getLogger("ai_lifeguard").setLevel(logging.ERROR)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
