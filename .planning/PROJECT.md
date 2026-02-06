# TaskHound Modularization

## What This Is

Refactoring TaskHound's monolithic CLI into a stage-based pipeline with user-facing subcommands. Users can run individual stages (`warmup`, `collect`, `resolve`, `classify`, `report`) independently with session persistence between them, or run the full pipeline as today. This enables re-running stages without rescanning (e.g., re-report with different flags, re-classify after adding BloodHound data) and makes the codebase navigable as it continues to grow.

## Core Value

Users can run any pipeline stage independently and re-run downstream stages without repeating upstream work.

## Requirements

### Validated

<!-- Existing capabilities that work today -->

- ✓ Online SMB/RPC target enumeration with parallel processing — existing
- ✓ SID→name resolution with multi-tier fallback chain (BH → LDAP → LSARPC → GC) — existing
- ✓ Task classification (TIER-0/PRIV/TASK) with BloodHound and LDAP data — existing
- ✓ DPAPI credential extraction and decryption — existing
- ✓ LAPS password retrieval with caching — existing
- ✓ Multiple output formats (JSON, CSV, plain, HTML report) — existing
- ✓ BloodHound OpenGraph generation and upload — existing
- ✓ Offline mode (exported XMLs) and offline-disk mode (mounted filesystem) — existing
- ✓ TOML config file support — existing
- ✓ Credential Guard detection — existing
- ✓ Credential validation via Task Scheduler RPC — existing
- ✓ --opsec mode (SMB-only, no DC traffic) — existing
- ✓ Resolver modularized into `resolver/` with pluggable backends — existing

### Active

<!-- Modularization work — what we're building -->

**Pipeline stages (subcommands):**
- [ ] `warmup` stage — auth setup, LAPS retrieval, BH connection, cache warming
- [ ] `collect` stage — scan live targets via SMB/RPC, grab DPAPI blobs/masterkeys by default
- [ ] `resolve` stage — SID→name resolution (network calls to DC/LDAP/LSARPC)
- [ ] `classify` stage — BloodHound classification, severity scoring (mostly local)
- [ ] `report` stage — generate outputs (pure transform, no network)

**Standalone commands:**
- [ ] `upload` command — BloodHound upload (separated from report)
- [ ] `decrypt` command — DPAPI decryption of collected blobs (--dpapi-key + host)
- [ ] `ingest` command — import offline data (--xml-dir for exported XMLs, --disk for mounted filesystem)
- [ ] `full` command — chains warmup→collect→resolve→classify→report

**Infrastructure:**
- [ ] Session cache (SQLite) for inter-stage data persistence
- [ ] Explicit `--session <name>` for multi-domain support
- [ ] Merge-by-default session behavior (append new results to existing session)
- [ ] Staleness warnings when downstream data is outdated after upstream re-run
- [ ] Auth context persistence in SQLite (plaintext, pentesting context)
- [ ] `--opsec` as global modifier restricting all stages to SMB-only
- [ ] Backward compatibility: no subcommand = `full` (current behavior)
- [ ] Minor flag moves with deprecation warnings where needed

**Cleanup:**
- [ ] Retire legacy `utils/sid_resolver.py` (2841 lines) — replaced by `resolver/` package

### Out of Scope

- Convenience aliases (scan, attack, audit, opsec shortcuts) — defer until core pipeline is validated
- Config file stage filtering (per-stage TOML section loading) — not enough usage data to invest
- Interactive mode / TUI — not requested
- Plugin system for custom stages — over-engineering for current needs
- Encrypted credential storage / OS keyring — pentesting context, plaintext is acceptable

## Context

**Codebase state:** ~15,000 lines of Python across 50+ modules. The resolver subsystem is already modularized into `resolver/backends/` with pluggable backends. The SID resolver migration is in progress (legacy `utils/sid_resolver.py` at 2841 lines coexists with new `resolver/` package on `refactor/sid-resolver` branch).

**Pain points driving this work:**
- `cli.py` (955 lines) orchestrates everything — auth, scanning, resolution, classification, output
- `config.py` (1037 lines) handles all argument parsing for every mode
- Users can't re-run downstream stages without rescanning all targets
- Adding features means touching cli.py, which is getting unwieldy
- The tool's line count has grown beyond what the original modularization doc estimated

**Existing modularization doc:** `planning/MODULARIZATION.md` was written Dec 2025 and is stale:
- Line counts are all understated (e.g., online.py was ~600, now 773; bloodhound.py was ~200, now 610)
- Doesn't acknowledge the resolver modularization work that's already done
- Proposed "enrich" stage has been split into "resolve" + "classify" per this project
- "loot" stage eliminated — collect grabs blobs by default, decrypt is a separate utility
- BH upload separated from report into its own command
- Ingest replaces the offline/offline-disk mode flags

**Tech stack:** Python 3.11+, impacket, rich, pycryptodome, SQLite for caching. No framework — pure CLI with argparse.

## Constraints

- **Backward compatibility**: `taskhound` with no subcommand must behave identically to today. Minor flag relocations acceptable with deprecation warnings.
- **Test coverage**: Maintain above 50% threshold. New stages need unit tests.
- **No new dependencies**: Session cache uses existing SQLite infrastructure (cache_manager.py). No new libraries.
- **Incremental delivery**: Each stage should be extractable and testable independently. Don't require all stages to exist before any can be used.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| User-facing subcommands, not internal-only refactor | Users need to re-run stages independently (re-report, re-classify) | — Pending |
| Split "enrich" into "resolve" + "classify" | Resolution is expensive (network), classification is cheap (local). Users want to re-classify without re-resolving. | — Pending |
| Eliminate "loot" stage, collect grabs blobs by default | Each host has unique DPAPI_SYSTEM key, no convenient batch decrypt. Collect blobs always, decrypt explicitly. | — Pending |
| Separate BH upload from report | Report is pure transform (no network), upload is network. Different failure modes. | — Pending |
| "ingest" for offline modes | Single command with --xml-dir / --disk flags replaces two separate code paths | — Pending |
| Explicit --session naming | Multi-domain support. Users scanning corp.local and partner.com need separate sessions. | — Pending |
| Merge-by-default sessions | Pentester runs collect on 10 hosts, then 5 more. Results should accumulate. | — Pending |
| Auth stored plaintext in SQLite | Pentesting context — operator's box already has plaintext creds from other tools | — Pending |
| --opsec as global modifier | More powerful than per-stage flags. One flag restricts entire pipeline to SMB-only. | — Pending |
| Skip convenience aliases for v1 | Focus on core pipeline. Aliases are sugar that can be added after validation. | — Pending |

---
*Last updated: 2026-02-06 after initialization*
