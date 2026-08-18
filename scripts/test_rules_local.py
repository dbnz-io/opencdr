#!/usr/bin/env python3
"""
Local rule tester — no AWS required.

Loads all signal rules from support_files/detection_rules/ and all test events
from support_files/test_events/, runs them through the parser and detection
engine, and reports which rules fired.

Usage:
    python3 scripts/test_rules_local.py
    python3 scripts/test_rules_local.py --event support_files/test_events/001_console_login_no_mfa.json
    python3 scripts/test_rules_local.py --rule 009_admin_policy_attached
"""

import argparse
import json
import sys
from pathlib import Path

# Make project root importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.domain.detection_engine import run_detection
from src.domain.ocsf_min_parser import build_default_router

RULES_DIR  = Path(__file__).parent.parent / "support_files" / "detection_rules"
EVENTS_DIR = Path(__file__).parent.parent / "support_files" / "test_events"

RESET  = "\033[0m"
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BOLD   = "\033[1m"

SEVERITY_COLOR = {
    "CRITICAL": RED + BOLD,
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "LOW":      CYAN,
}


def load_json(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def load_signal_rules() -> list:
    # Recursive: rule files live in per-source subfolders (cloudtrail/,
    # guardduty/, and any future source folder added the same way).
    rules = []
    for path in sorted(RULES_DIR.rglob("*.json")):
        rule = load_json(path)
        if rule.get("rule_kind") == "signal":
            rules.append(rule)
    return rules


def load_test_events() -> list:
    events = []
    for path in sorted(EVENTS_DIR.glob("*.json")):
        events.append({"_filename": path.name, "_path": str(path), **load_json(path)})
    return events


def color_severity(severity: str) -> str:
    c = SEVERITY_COLOR.get(severity, "")
    return f"{c}{severity}{RESET}"


def run_all(filter_event: str = None, filter_rule: str = None):
    router = build_default_router()
    rules  = load_signal_rules()
    events = load_test_events()

    if filter_event:
        events = [e for e in events if filter_event in e["_filename"]]
    if filter_rule:
        rules = [r for r in rules if filter_rule in r.get("rule_id", "")]

    if not rules:
        print(f"{RED}No rules matched filter.{RESET}")
        sys.exit(1)
    if not events:
        print(f"{RED}No test events matched filter.{RESET}")
        sys.exit(1)

    print(f"\n{BOLD}OpenCDR — Local Rule Tester{RESET}")
    print(f"Rules loaded : {len(rules)}")
    print(f"Events loaded: {len(events)}\n")
    print("─" * 70)

    fired_rules   = set()
    total_matches = 0

    for event_data in events:
        filename = event_data.pop("_filename")
        event_data.pop("_path")

        normalized = router.parse(event_data)
        if not normalized:
            print(f"{YELLOW}[SKIP]{RESET}  {filename}  — no parser matched")
            continue

        detections = run_detection(normalized, rules)

        if not detections:
            print(f"{YELLOW}[MISS]{RESET}  {filename}")
            print(f"        ↳ parsed as {CYAN}{normalized.activity_name}{RESET} "
                  f"(actor: {normalized.actor.user_name or 'unknown'}) — no rules matched\n")
            continue

        print(f"{GREEN}[HIT] {RESET}  {filename}")
        print(f"        ↳ parsed as {CYAN}{normalized.activity_name}{RESET} "
              f"(actor: {normalized.actor.user_name or 'unknown'})")

        for d in detections:
            sev = d.get("severity", "UNKNOWN")
            rule_id = d.get("rule_id", "unknown")
            fired_rules.add(rule_id)
            total_matches += 1
            print(f"        ↳ {GREEN}FIRED{RESET}  [{color_severity(sev)}]  {rule_id}")

        print()

    print("─" * 70)
    print(f"\n{BOLD}Summary{RESET}")
    print(f"  Total matches : {GREEN}{total_matches}{RESET}")
    print(f"  Rules fired   : {GREEN}{len(fired_rules)}/{len(rules)}{RESET}")

    unfired = [r["rule_id"] for r in rules if r["rule_id"] not in fired_rules]
    if unfired:
        print(f"\n  {YELLOW}Rules with no matching test event:{RESET}")
        for rule_id in unfired:
            print(f"    - {rule_id}")

    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test OpenCDR detection rules locally.")
    parser.add_argument("--event", help="Filter by event filename substring")
    parser.add_argument("--rule",  help="Filter by rule_id substring")
    args = parser.parse_args()

    run_all(filter_event=args.event, filter_rule=args.rule)
