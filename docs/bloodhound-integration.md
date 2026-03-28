# BloodHound Integration

## Why bother

Without BloodHound, TaskHound can tell you that `CORP\svc_sql` runs a scheduled task
with stored credentials on DBSERVER01. With BloodHound, it can tell you that `svc_sql`
has a path to Domain Admin through three group memberships and an unconstrained delegation.
That's the difference between "mildly interesting" and "hair on fire."

There is no single integration point. Just a ton of duct tape holding multiple query
backends together.

## Live connection setup

TaskHound supports three BloodHound backends. Pick one.

### BloodHound Community Edition (BHCE) with API key (recommended)

```bash
taskhound -u admin -p 'P@ss' -d corp.local -t 10.0.0.5 \
  --bh-live --bhce \
  --bh-connector https://bh.corp.local:8080 \
  --bh-api-key-id YOUR_KEY_ID \
  --bh-api-key YOUR_API_KEY
```

### BHCE with username/password

```bash
taskhound -u admin -p 'P@ss' -d corp.local -t 10.0.0.5 \
  --bh-live --bhce \
  --bh-connector https://bh.corp.local:8080 \
  --bh-user admin@bh.local --bh-password 'BHpassword'
```

### Legacy BloodHound (Neo4j)

```bash
taskhound -u admin -p 'P@ss' -d corp.local -t 10.0.0.5 \
  --bh-live --legacy \
  --bh-connector bolt://neo4j.local:7687 \
  --bh-user neo4j --bh-password 'neo4jpass'
```

Or put all of this in `taskhound.toml` and never type it again:

```toml
[bloodhound]
type = "bhce"
url = "https://bh.corp.local:8080"
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
taskhound -u admin -p 'P@ss' -d corp.local -t 10.0.0.5 \
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

### Task nodes

- **Node type**: `ScheduledTask` (kinds: ScheduledTask, Base, TaskHound)
- **Edge**: `HasTaskWithStoredCreds` -- Computer to ScheduledTask (if credentials are stored)
- **Edge**: `HasTask` -- Computer to ScheduledTask (no stored credentials)
- **Edge**: `RunsAs` -- ScheduledTask to User (the service account)

### Service nodes (new)

- **Node type**: `WindowsService` (kinds: WindowsService, Base, TaskHound)
- **Edge**: `HasServiceWithStoredCreds` -- Computer to WindowsService
- **Edge**: `RunsAs` -- WindowsService to User

### Output files

Tasks and services get separate OpenGraph files:
- `taskhound_opengraph.json` -- scheduled task nodes and edges
- `taskhound_services_opengraph.json` -- service nodes and edges

This keeps the graph clean and lets you ingest them independently.

### Generate and upload

```bash
# Generate OpenGraph files (auto-uploads to BHCE if connected)
taskhound -u admin -p 'P@ss' -d corp.local -t 10.0.0.5 \
  --bh-live --bhce --bh-opengraph \
  --bh-connector https://bh.corp.local:8080 \
  --bh-api-key-id KEYID --bh-api-key SECRET

# Generate without auto-upload
taskhound -u admin -p 'P@ss' -d corp.local -t 10.0.0.5 \
  --bh-live --bhce --bh-opengraph --bh-no-upload

# Upload a previously generated file manually
# (use the BHCE API or the BH UI file upload)
```

### Customization

```bash
--bh-icon clock          # Font Awesome icon for task nodes (default: clock)
--bh-color #FF0000       # Node color
--bh-force-icon          # Override icon even if already set
--bh-allow-orphans       # Include nodes even if the Computer isn't in BH
```

## Limitations

- OpenGraph is BHCE-only. Legacy BloodHound (Neo4j) does not support custom node types.
  If you're still on Legacy, you get tier-0 detection and HVT enrichment, but no graph
  visualization. Time to upgrade, probably.
- OpenGraph upload requires API key or password auth to BHCE. The upload happens
  automatically unless you pass `--bh-no-upload`.
- The `--bh-timeout` flag exists because some BloodHound instances are... slow. Default
  is usually fine.
