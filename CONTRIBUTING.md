# Contributing to OpenCDR

Thank you for your interest in contributing. OpenCDR is an open-source project and welcomes pull requests, bug reports, and detection rule contributions.

---

## Getting Started

```bash
git clone https://github.com/<your-org>/opencdr.git
cd opencdr
pip install -r requirements-dev.txt
```

Run the test suite before making any changes:

```bash
pytest tests/ -v
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
New rules are the highest-value contribution. To add a rule:

1. Add the rule JSON to `support_files/detection_rules/` following the naming convention `NNN_rule_name.json`
2. Add a matching test event to `support_files/test_events/NNN_event_name.json`
3. Verify locally: `python3 scripts/test_rules_local.py --event NNN`
4. Open a PR with the rule, the test event, and a description of the attack pattern it covers

For rule schema reference see the [Writing Detection Rules](README.md#writing-detection-rules) section of the README.

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
