# Contributing to WebhookGuard

Short rules so ten people can commit without stepping on each other.

## Branches
| Branch | Purpose | Rules |
|--------|---------|-------|
| `main` | Stable, demo-ready code | Only the Lead merges `dev` into `main` (Day 10 and Day 12) |
| `dev` | Integration branch | All PRs target `dev`; needs 1 approval |
| `feature/<task-name>` | One branch per task | Created from `dev`, deleted after merge |

Branch names come from the task plan, e.g. `feature/hmac-utils`, `feature/timestamp-check`, `feature/replay-check`.

## Daily workflow
```bash
git checkout dev && git pull origin dev
git checkout -b feature/<task-name>

# ... work, then commit in small steps ...
git add <files>
git commit -m "feat(timestamp): reject far-future timestamps"

git fetch origin && git rebase origin/dev   # stay up to date
git push -u origin feature/<task-name>
# open a Pull Request into dev on GitHub
```

## Commit messages
Format: `type(scope): short description`

| Type | Use for |
|------|---------|
| `feat` | New functionality |
| `fix` | Bug fix |
| `test` | Adding or changing tests |
| `docs` | Documentation |
| `refactor` | Code change with no behaviour change |
| `chore` | Config, requirements, tooling |

Examples: `feat(replay): add atomic check-and-set in event store`, `test(hmac): add determinism test`.

## Pull requests
- Fill in the PR template completely.
- One task per PR; keep PRs small enough to review in 15 minutes.
- Merge only after 1 approval and passing tests. Use "Squash and merge".
- Reviewers: respond within 24 hours (Lead prioritises Days 3-6 and 9-10).

## Ownership
- Each member owns the files listed for their task (see the table in `README.md`).
- Need a change in someone else's module? Open an issue or a PR to that owner. Do not edit it directly.
- Interfaces live in `docs/api-contract.md`. Changing one needs the Lead's approval and a heads-up to dependent owners.

## Dependencies and stubs
If an upstream module is not merged yet, code against a stub that follows the contract (for example, read the key from an environment variable). Replace the stub when the real module lands.

## Security rules (this is a security project)
- Never commit secrets, keys, `.env` files or databases. Use `.env.example` for variable names only.
- Compare signatures with a constant-time function (`hmac.compare_digest`).
- Do not log secrets or full signatures.

## Tests
```bash
pip install -r requirements.txt
pytest tests/ -v
```
Put each module's unit tests next to its task in `/tests` (e.g. `tests/test_hmac_utils.py`).
