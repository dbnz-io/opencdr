---
name: New detection rule
about: Propose a new signal or correlation rule
labels: detection-rule
---

**Attack pattern**
Describe the AWS attack technique or misconfiguration this rule detects.

**MITRE ATT&CK mapping** (optional)
Tactic / Technique ID

**Proposed rule JSON**
```json
{
  "rule_id": "NNN_rule_name",
  "rule_kind": "signal",
  ...
}
```

**Sample event JSON** (optional)
Paste a sanitized EventBridge event payload that would trigger this rule.

**Why this is worth including in the default ruleset**
