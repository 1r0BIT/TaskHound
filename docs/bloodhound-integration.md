# BloodHound Integration

## Why bother

Without BloodHound, TaskHound can tell you that `SHINRA\svc_mako` runs a scheduled task
with stored credentials on REACTOR01. With BloodHound, it can tell you that `svc_mako`
has a path to Domain Admin through three group memberships and an unconstrained delegation.
That's the difference between "mildly interesting" and "hair on fire."

There is no single integration point. Just a ton of duct tape holding multiple query
backends together.

## Live connection setup

TaskHound supports three BloodHound backends. Pick one.

### BloodHound Community Edition (BHCE) with API key (recommended)

```bash
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local -t reactor01.shinra.local \
  --bh-live --bhce \
  --bh-connector http://127.0.0.1:8080 \
  --bh-api-key-id YOUR_KEY_ID \
  --bh-api-key YOUR_API_KEY
```

### BHCE with username/password

```bash
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local -t reactor01.shinra.local \
  --bh-live --bhce \
  --bh-connector http://127.0.0.1:8080 \
  --bh-user admin@bh.local --bh-password 'BHpassword'
```

### Legacy BloodHound (Neo4j)

```bash
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local -t reactor01.shinra.local \
  --bh-live --legacy \
  --bh-connector bolt://neo4j.local:7687 \
  --bh-user neo4j --bh-password 'neo4jpass'
```

Or put all of this in `taskhound.toml` and never type it again:

```toml
[bloodhound]
type = "bhce"
url = "http://127.0.0.1:8080"
api_key_id = "YOUR_KEY_ID"
api_key = "YOUR_API_KEY"
```

## Tier-0 detection methods

TaskHound uses whichever data source is available, in order of preference:

| Method | Source | What it checks | Requires |
|--------|--------|---------------|----------|
| BHCE API | BloodHound CE | `is_tier_zero` property, admin tier assignments | `--bh-live --bhce` |
| Legacy Neo4j | BloodHound Legacy | Cypher query for HVT-tagged nodes | `--bh-live --legacy` |
| LDAP | Domain Controller | Group membership (Domain Admins, Enterprise Admins, etc.) | LDAP access (default) |
| Built-in | Hardcoded SIDs | Well-known admin group RIDs (-500, -512, -519, etc.) | Nothing |

If you have BloodHound data, use it. The LDAP fallback checks a fixed list of groups.
The built-in SID check is the last resort and only catches the obvious stuff.

## Offline data ingestion

Don't have a live BloodHound instance? You can export high-value targets and feed them in:

```bash
# From BHCE or Legacy, export HVT list to CSV/JSON, then:
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local -t reactor01.shinra.local \
  --bh-data ./hvt_export.csv
```

### Cypher export queries

**BHCE (API v2):**
```cypher
MATCH (n) WHERE n.system_tags CONTAINS "admin_tier_0"
RETURN n.name AS name, n.objectid AS objectid, labels(n) AS type
```

**Legacy (Neo4j):**
```cypher
MATCH (n {highvalue: true})
RETURN n.name AS name, n.objectid AS objectid, labels(n) AS type
```

Export to CSV, point `--bh-data` at it. Good enough.

## OpenGraph attack path visualization

This is the fun part. TaskHound generates custom BloodHound nodes and edges that show
scheduled task and service attack paths directly in the BloodHound graph.

All custom node and edge kinds are namespace-prefixed with `TH_` (required by
BloodHound CE v9). Native BloodHound kinds (`Computer`, `User`, `Base`) are never
prefixed, and `TaskHound` stays unprefixed because it is upload-grouping metadata,
not a graph kind.

### Task nodes

- **Node type**: `TH_ScheduledTask` (kinds: TH_ScheduledTask, Base, TaskHound)
- **Edge**: `TH_HasTaskWithStoredCreds` -- Computer to TH_ScheduledTask (if credentials are stored, traversable)
- **Edge**: `TH_HasTask` -- Computer to TH_ScheduledTask (no stored credentials, non-traversable)
- **Edge**: `TH_RunsAs` -- TH_ScheduledTask to User (the service account, traversable)

### Service nodes (new)

- **Node type**: `TH_WindowsService` (kinds: TH_WindowsService, Base, TaskHound)
- **Edge**: `TH_HasServiceWithStoredCreds` -- Computer to TH_WindowsService (traversable)
- **Edge**: `TH_RunsAs` -- TH_WindowsService to User (traversable)

### Output files

Tasks and services get separate OpenGraph files:
- `taskhound_opengraph.json` -- scheduled task nodes and edges
- `taskhound_services_opengraph.json` -- service nodes and edges

This keeps the graph clean and lets you ingest them independently.

### Generate and upload

```bash
# Generate OpenGraph files (auto-uploads to BHCE if connected)
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local -t reactor01.shinra.local \
  --bh-live --bhce --bh-opengraph \
  --bh-connector http://127.0.0.1:8080 \
  --bh-api-key-id KEYID --bh-api-key SECRET

# Generate without auto-upload
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local -t reactor01.shinra.local \
  --bh-live --bhce --bh-opengraph --bh-no-upload

# Upload a previously generated file manually
# (use the BHCE API or the BH UI file upload)
```

### Customization

```bash
--bh-allow-orphans       # Include nodes even if the Computer isn't in BH
```

Node icons and colors are no longer set via CLI flags. They are declared in the
v9 extension schema and applied automatically on upload (see "Traversability and
icons" below).

### Node and edge documentation

For detailed documentation on every custom node kind and edge kind -- including
abuse info, remediation guidance, OPSEC considerations, and MITRE ATT&CK references
-- see [opengraph-nodes-and-edges.md](opengraph-nodes-and-edges.md).

### Starter queries

TaskHound ships pre-built Cypher queries for exploring OpenGraph data in BloodHound
CE. Import `docs/opengraph/queries/starter_queries.json` into the Cypher tab via
drag and drop. Queries include full attack path visualization, credential extraction
results, TIER-0 findings, shortest-path analysis, and more.

See [opengraph/queries/README.md](opengraph/queries/README.md) for the full list.

### Traversability and icons

TaskHound ships a BloodHound CE v9 extension schema that makes the credential-bearing
edges traversable. On upload, TaskHound auto-installs the schema via
`PUT /api/v2/extensions`; it is also written to the output directory as
`taskhound_extension_schema.json` so you can install it manually in the BloodHound UI
if you prefer.

The schema declares which edges participate in pathfinding:

- `TH_HasTaskWithStoredCreds`, `TH_HasServiceWithStoredCreds`, `TH_RunsAs` are
  **traversable** -- they form the real `Computer -> Task/Service -> RunAs-principal`
  attack path and now show up in BloodHound's **Pathfinding / Attack Paths** views,
  not just raw Cypher.
- `TH_HasTask` is **non-traversable** -- there are no stored credentials behind it, so
  it is intentionally excluded from pathfinding to avoid false attack paths.

The schema also declares node icons and colors, applied automatically once installed:

- **TH_ScheduledTask**: `clock` (purple `#8B5CF6`)
- **TH_WindowsService**: `gears` (cyan `#06B6D4`)

> **Note:** Traversability and icons require BloodHound CE **v9+**. On pre-v9
> BloodHound the schema install no-ops -- the edges remain generic and are
> reachable via the Cypher tab only, not Search or Pathfinding.

### Attack path diagram

<img width="1437" height="519" alt="TaskHound OpenGraph Attack Path Diagram" src="https://github.com/user-attachments/assets/fe4077c6-1b3a-43a0-90df-d565f63763f4" />

An editable [arrows.app](https://arrows.app) version is available at
`docs/opengraph-diagram.json` -- import it to customize the diagram.

## Limitations

- OpenGraph is BHCE-only. Legacy BloodHound (Neo4j) does not support custom node types.
  If you're still on Legacy, you get tier-0 detection and HVT enrichment, but no graph
  visualization. Time to upgrade, probably.
- OpenGraph upload requires API key or password auth to BHCE. The upload happens
  automatically unless you pass `--bh-no-upload`.
- The `--bh-timeout` flag exists because some BloodHound instances are... slow. Default
  is usually fine.
