# Third-party notices

AI Lifeguard is MIT licensed (see `LICENSE`). The package bundles no third-party code, rules or data. Its optional scanners call tools you install and services you sign up for, each under its own terms, and nothing in this repo changes those terms. This file lists them so you can check your own use before you fork, deploy or sell something built on it.

| Component | How AI Lifeguard uses it | Licence / terms | What that means for you |
|---|---|---|---|
| Semgrep CE engine | `scan_sast` runs the `semgrep` binary you installed (`pip install ai-lifeguard[sast]`) as a separate process | LGPL-2.1 | No obligations for running the CLI. |
| Semgrep Registry packs (`p/python`, `p/default`) | Fetched by your Semgrep at scan time, only after you opt in with `SEMGREP_REGISTRY=true`, `semgrep.registry: true` or `--registry`. Never bundled. | Semgrep Rules License 1.0 for Semgrep-authored rules; community rules keep their own licences, some GPL or AGPL | Internal use of the rules is permitted. Using them inside a competing product or service is not. Keep them off if you ship a scanner. |
| Bundled rule pack `src/ai_lifeguard/defaults/semgrep_rules.yaml` | Our own rules, run by default | MIT (this repo) | None. |
| cve.now feed | `scan_dependencies`, `check_dependency` and `CveWatcher` fetch `https://cve.now/feed?format=json` at runtime and quote advisory titles in results and GitHub issues | Summaries CC BY 4.0; built on NVD data; cve.now is not endorsed by NVD | Keep the attribution when you redisplay feed content. Results and issues already carry the link and credit. |
| SonarQube Community Build, SonarQube Cloud | `scan_sonar` reads the web API of a server you run or an account you hold; CI uses `SonarSource/sonarqube-scan-action` | LGPL-3.0 (server and action); SonarQube Cloud terms of service | None for API use. Cloud terms apply to your account. |
| GitHub REST API | `GitHubIssueNotifier` opens issues with your token | GitHub terms of service | Use a fine-grained token scoped to the target repo. |
| PyYAML (optional extra) | `Lifeguard.from_config` for YAML configs | MIT | None. |

Licence texts: [Semgrep](https://github.com/semgrep/semgrep/blob/develop/LICENSE), [Semgrep Rules License](https://semgrep.dev/legal/rules-license), [cve.now](https://cve.now), [SonarQube](https://github.com/SonarSource/sonarqube/blob/master/LICENSE.txt), [sonarqube-scan-action](https://github.com/SonarSource/sonarqube-scan-action/blob/master/LICENSE), [PyYAML](https://github.com/yaml/pyyaml/blob/main/LICENSE).

This is an engineer's summary, not legal advice. Check the linked texts for your situation.
