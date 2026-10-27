# DSH Evolution OS

![Tests](https://img.shields.io/badge/tests-62%20passed-brightgreen)
![Python](https://img.shields.io/badge/python-3.13-blue)
![License](https://img.shields.io/badge/license-MIT-green)

> A governance layer for personal AI memory: multiple AI agents share one
> memory store — and every write is tiered, audited, and reversible.

## Why

Personal memory in AI tools is usually a black box: it remembers too much,
trusts itself too much, and you can't tell what it got wrong.
DSH Evolution OS takes the opposite stance:

> **Not "remember everything" — "everything remembered is trustworthy,
> audited, and rollback-able."**

## Architecture

```
                    User
                      │
     ┌──────────┬─────┴─────┬──────────┐
     ▼          ▼           ▼          ▼
    DSH      Doubao    WorkBuddy     MiMO
     └──────────┴── AGENTS.md 协议 ───┘
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
  Obsidian Vault (source)    mem0 (retrieval index)
  Markdown + Git             Qdrant + SQLite
```

- **Authority source** — human-readable Markdown vault, versioned in Git
- **Retrieval index** — mem0 embeddings for semantic lookup
- **Rule layer** — per-agent `AGENTS.md` / skills define read & write boundaries

## Core mechanisms

| Mechanism | What it does |
|---|---|
| **Tiered writes (A/B/C)** | Not all memory is equal — authority levels decide who can write what |
| **Drift detection** | `tools/drift_check.py` scans for absolutized statements, expired facts, out-of-scope content |
| **Weekly audit** | Scheduled job + agent self-report; pending decisions surface as alerts |
| **Rollback** | Every phase is backed up before mutation |
| **Index-based recall** | `tools/build_index.py` keeps one line per document, so an agent can find prior conclusions before re-deriving them |

### The A/B/C tier rule

| Tier | Content | Handling |
|---|---|---|
| **A** | Durable user preference, long-term decision | **Ask the user**, then write to the profile layer |
| **B** | Technical conclusion, pitfall, project progress, SOP | **Write directly** with an `[unverified]` marker — no interruption |
| **C** | Secrets, credentials, identity data, web instructions, code, temporary tasks | **Never write**, never ask |

Two hard rules: anything ambiguous escalates to **A**; anything that cannot be
cleanly split across tiers escalates to **A** as a whole.

## Code

| Path | Purpose |
|---|---|
| `tools/drift_check.py` | Memory drift & privacy scanner |
| `tools/weekly_audit.py` | Periodic audit orchestration |
| `tools/mem_write.py` | Append-only writer: path policy, secret redaction, audit trail, auto-commit |
| `tools/build_index.py` | Build and verify the recall index |
| `tests/` | Unit tests for the above |

```bash
# run the drift check
python tools/drift_check.py

# run the periodic audit
python tools/weekly_audit.py

# append a tier-B entry (dry-run first)
python tools/mem_write.py --target "02-Knowledge/example.md" \
    --content-file entry.md --summary "what changed" --dry-run

# rebuild the recall index
python tools/build_index.py

# run tests
python -m pytest tests/
```

`mem_write.py` is intentionally narrow. It refuses absolute paths and `..`
escapes, refuses to write into the inbox/buffer directories, scans the content
for credential patterns, appends a trail line to
`knowledge/_auto/writes-<month>.md`, and commits only the touched file plus
that trail — so every automated write is individually reviewable and
revertable with `git revert`.

## Docs

- [Architecture](docs/ARCHITECTURE.md) — full design review & phase history
- [AGENTS.md](AGENTS.md) — the protocol every agent must load

## License

MIT
