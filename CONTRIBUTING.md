# Contributing to OpenCDR

Thank you for your interest in contributing. OpenCDR is an open-source project and welcomes pull requests, bug reports, and detection rule contributions.

---

## Getting Started

```bash
git clone --recurse-submodules https://github.com/<your-org>/opencdr.git
cd opencdr
pip install -r requirements-dev.txt
```

`support_files/detection_rules` is a git submodule (rule content lives in its own repo, see
[Detection Rules](#detection-rules) below) — `--recurse-submodules` populates it on clone. If you
already cloned without that flag: `git submodule update --init`.

Run the test suite before making any changes:

```bash
pytest tests/ -v

# With coverage
pytest tests/ --cov=src --cov=scripts --cov-report=term-missing
```

---

## Types of Contributions

### Bug Reports
Open a GitHub issue with:
- What you expected to happen
- What actually happened
- Steps to reproduce (event JSON, rule JSON if applicable)
- Deployment stage and region (redact account IDs)

### Detection Rules
New rules are the highest-value contribution, and rule content lives in its own repo —
[dbnz-io/opencdr-detection-rules](https://github.com/dbnz-io/opencdr-detection-rules), MIT-licensed
— consumed here as a git submodule at `support_files/detection_rules`. Adding a rule is a two-repo
change:

1. Open a PR to [dbnz-io/opencdr-detection-rules](https://github.com/dbnz-io/opencdr-detection-rules)
   adding the rule JSON to `<source>/` (e.g. `cloudtrail/`, `guardduty/` — one folder per event
   source; add a new source folder the same way if the rule doesn't fit an existing one) following
   the naming convention `NNN_rule_name.json`. See that repo's README for the rule schema and
   contribution expectations.
2. Once merged there, open a companion PR here that bumps the submodule pin
   (`git submodule update --remote support_files/detection_rules`) and adds a matching test event to
   `support_files/test_events/NNN_event_name.json`.
3. Verify locally: `python3 scripts/test_rules_local.py --event NNN`
4. Describe the attack pattern the rule covers in the PR description.

For rule schema reference see [dbnz-io/opencdr-detection-rules](https://github.com/dbnz-io/opencdr-detection-rules), and [Detection Rules](docs/detection-rules.md) for how rules are stored and loaded here.

### Code Changes
- Keep PRs focused — one logical change per PR
- All domain logic changes require corresponding tests in `tests/domain/`
- Run `pytest tests/ --cov=src/domain --cov-report=term-missing` and ensure coverage does not regress
- `serverless.yml` changes should follow the least-privilege IAM principle already in place

---

## Code Style

- Python: follow PEP 8, no type annotation requirements for now
- Shell scripts: `set -euo pipefail`, quote all variables
- JSON rules: 2-space indent, no trailing commas

---

## Commit Messages

Use the imperative mood and a short subject line (under 72 characters):

```
Add rule 024: EC2 security group egress rule added
Fix correlation engine time window boundary condition
```

---

## Pull Request Checklist

- [ ] Tests pass locally (`pytest tests/ -v`)
- [ ] New detection rules include a matching test event
- [ ] No secrets, account IDs, or real ARNs in committed files
- [ ] PR description explains the *why*, not just the *what*
