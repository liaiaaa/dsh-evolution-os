# DSH Evolution OS

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

## Code

| Path | Purpose |
|---|---|
| `tools/drift_check.py` | Memory drift & privacy scanner |
| `tools/weekly_audit.py` | Periodic audit orchestration |
| `tests/` | Unit tests for both tools |

```bash
# run drift check
python tools/drift_check.py

# run tests
python -m pytest tests/
```

## Docs

- [Architecture](docs/ARCHITECTURE.md) — full design review & phase history
- [AGENTS.md](AGENTS.md) — the protocol every agent must load

## License

MIT
