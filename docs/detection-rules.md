# Detection Rules

*How OpenCDR stores, loads, and manages detection rules. For the rule schema itself, the full
catalog of what ships, and how to author or contribute a new rule, see*
[dbnz-io/opencdr-detection-rules](https://github.com/dbnz-io/opencdr-detection-rules) *— rule
content lives there, MIT-licensed, and this repo consumes it as a git submodule at
`support_files/detection_rules` (see [Authoring, testing, and loading](#authoring-testing-and-loading)
below for how the two repos relate day to day).*

## Storage model

Every rule is one row in the `detection-rules-table`: partition key `rule_kind`, sort key `rule_id`, and the actual rule content stored as `rule_body` — a JSON-serialized string, parsed back into a real object by `src/infra/detection_rules_repository.py` when `processor`/`alerter` load rules. This indirection is what makes rules **data, not code**: editing a rule is a DynamoDB write (via the API or `scripts/load_rules.sh`), not a Lambda redeploy. `src/handlers/api.py`'s `/rules` endpoints reuse the same `unpack_rule_body` helper on every read, so `GET /rules`/`GET /rules/{id}` return the real fields either way — whether a rule was loaded via `load_rules.sh` (`rule_body`-wrapped) or created/edited through the API itself (which writes flat, no wrapper). Both shapes coexist in the table; a rule normalizes to flat the next time it's saved through the API.

Three values of `rule_kind` exist in practice, though not all are exposed the same way:

- **`signal`** — matched by `processor` against one normalized event at a time. Mutable via the API (`ALLOWED_RULE_KINDS` in `src/handlers/api.py`).
- **`correlation`** — matched by `alerter` against a window of recent signals. Also mutable via the API.
- **`list`** — reference lists (e.g. allow-lists) that rule conditions can check membership against via `in_list`/`not_in_list`, loaded via `load_detection_rules(rule_kind="list")` in `processor.py`. Mutable through the `/rules` API like the other two kinds — see [List rules](https://github.com/dbnz-io/opencdr-detection-rules#list-rules) in the rules repo for the schema.

## Authoring, testing, and loading

`support_files/detection_rules` is a git submodule pointing at
[dbnz-io/opencdr-detection-rules](https://github.com/dbnz-io/opencdr-detection-rules), pinned to a
specific commit — not an ordinary tracked directory. A fresh clone of this repo needs one extra
step to actually populate it:

```bash
git clone --recurse-submodules https://github.com/dbnz-io/opencdr-internal.git
# or, if already cloned without that flag:
git submodule update --init
```

Rule content, schema, and the full catalog of what ships live in that repo's own README, not here.
Every loader on this side (`scripts/load_rules.sh`, `scripts/test_rules_local.py`, `opencdr.py
rules load`) scans `support_files/detection_rules/` recursively regardless of which commit is
checked out, so authoring a new rule is entirely a change in the other repo — nothing here needs to
change to pick it up once the submodule pin is bumped.

```bash
# Test all rules against sample events, without touching AWS
python3 scripts/test_rules_local.py

# Filter by event or by rule
python3 scripts/test_rules_local.py --event 012
python3 scripts/test_rules_local.py --rule cloudtrail

# Preview what load_rules.sh would write, without writing it
./scripts/load_rules.sh --dry-run

# Load rules into a deployed stack -- response_module stripped by default,
# see the warning in docs/setup.md before passing --with-response-modules
./scripts/load_rules.sh --stage dev

# Pull in whatever's newest on the rules repo's main, then pin this repo
# to it -- the pin only moves when you commit the resulting change here.
git submodule update --remote support_files/detection_rules
git add support_files/detection_rules
git commit -m "chore: bump detection rules submodule"
```

Sample events for 23 of the 24 signal rules live in `support_files/test_events/` — one JSON fixture per rule, in the exact normalized-event shape `processor` expects (`028_guardduty_catchall` has no dedicated fixture by design — its whole purpose is to catch findings the curated fixtures don't cover). These fixtures stay in *this* repo (they exercise this repo's parser, not the rules repo), so contributing a new rule that needs one is a two-repo change: the rule itself as a PR to opencdr-detection-rules, plus a companion PR here adding the fixture and bumping the submodule pin — see that repo's [Contributing](https://github.com/dbnz-io/opencdr-detection-rules#contributing) section for the exact flow.

`./scripts/load_rules.sh` does a plain upsert of everything under `support_files/detection_rules/` (recursively, across every source folder) — no merge logic. Running it against a stage where a rule has since been edited live via the API will silently overwrite that edit back to the file's version. It's meant for initial seeding and intentional bulk updates, not something to wire into a deploy pipeline that runs on every push (this repo's own CI deliberately does not call it on deploy, for exactly that reason).

## Managing rules at runtime

The full CRUD surface is also available over the API — see [API Reference](api-reference.md#rules) — for editing a single rule without touching files, or building your own tooling on top.

## Related pages

- [dbnz-io/opencdr-detection-rules](https://github.com/dbnz-io/opencdr-detection-rules) — rule schema, full catalog, and contribution flow
- [Architecture](architecture.md) — where rules sit in the overall data flow
- [Incident Response](incident-response.md) — what happens when a rule's `response_module` fires
- [API Reference](api-reference.md) — the `/rules` endpoints
