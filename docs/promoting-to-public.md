# Promoting to the public repo

How a version of `opencdr-internal` becomes a release on the public
`dbnz-io/opencdr` repo, via `.github/workflows/promote-to-public.yml`.

## Model

- **Manual, on-demand.** Nothing about a private-repo push, deploy, or
  internal release (`ci.yml`'s own `release` job) triggers this — those
  happen far more often than you'd want a public release to. You decide
  when a version is ready and run this workflow deliberately.
- **Clean-slate, not history-preserving.** This repo's real git history —
  including a dead API key still sitting in it (confirmed not live, see
  `CHANGELOG.md`) — is never pushed to the public repo. Each promotion
  builds a filtered snapshot via `git archive` and pushes it as one new
  commit on the public side, not a merge or rebase of real history.
- **Independent versioning.** The public repo starts its own SemVer series
  at `v1.0.0`, unrelated to this repo's own internal version/CHANGELOG.

## What's excluded, and why

`.gitattributes` at the repo root marks internal-only paths with
`export-ignore`, which `git archive` respects natively — nothing bespoke
to maintain here beyond that file. Currently excluded:

| Path | Why |
|---|---|
| `.claude/` | Internal Claude Code tooling (hooks, skills) — not relevant to adopters |
| `node_modules/`, `.serverless/`, `.requirements.zip` | Gitignored but tracked (a pre-existing repo quirk — `.gitignore` doesn't retroactively untrack). `.serverless/` in particular can hold deployed CloudFormation template snapshots; not something to publish. |
| `*.pdf`, `*.pptx` | Stray internal documents (e.g. conference slides) that have ended up committed |
| `flag` | An empty, unexplained stray file — harmless, just clutter |

Adding a new internal-only path later is a one-line addition to
`.gitattributes`, not a workflow change. Preview exactly what would be
promoted at any time, without pushing anything, with:

```bash
git archive HEAD | tar -tf -
```

## One-time setup

The workflow needs a credential that can push to `dbnz-io/opencdr` —
the default `GITHUB_TOKEN` can't cross into another repo.

1. Create a **fine-grained personal access token**
   (github.com → Settings → Developer settings → Fine-grained tokens):
   - **Repository access:** only `dbnz-io/opencdr`
   - **Permissions:** Contents — Read and write (also covers creating
     releases/tags)
   - Set an expiration and calendar a reminder to rotate it — this repo's
     CI doesn't auto-rotate it the way the AWS OIDC deploy role avoids
     needing rotation at all.
2. Add it as a secret in **this** repo (`opencdr-internal`), not the
   public one:

   ```bash
   gh secret set OPENCDR_PUBLIC_REPO_TOKEN --repo dbnz-io/opencdr-internal
   ```

## Running it

Always do a dry run first — it runs the full test suite, a gitleaks scan
of the working tree, builds the exact promotion tree, and lists what
would be pushed, without touching the public repo at all:

```bash
gh workflow run promote-to-public.yml \
  --repo dbnz-io/opencdr-internal \
  -f version=v1.0.0 \
  -f release_notes="First public release." \
  -f dry_run=true
```

Once that looks right, re-run with `dry_run=false` to actually push,
tag, and create the GitHub Release. The workflow refuses to run if the
target tag already exists on the public repo — versions are never
overwritten, only added.

## What isn't handled here

- **Rewriting `README.md`/docs for a public audience.** The copied tree
  is exactly what's in this repo today; if anything reads as
  internal-only in prose (not just in file placement), that's a manual
  edit before running this, not something the workflow does for you.
- **Syncing future changes.** This promotes a snapshot at a point in
  time. There's no ongoing sync between the two repos — the next
  promotion is the next deliberate `workflow_dispatch` run, the same as
  this one.
