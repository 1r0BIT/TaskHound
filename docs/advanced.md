# Advanced Usage

Things you probably won't need on day one but will eventually reach for.

## Multi-Threaded Scanning

By default, TaskHound uses 10 threads. That's fine for most networks. Adjust as needed:

```bash
# 20 threads for a large environment
taskhound -u user -p pass -d corp.local --targets-file hosts.txt --threads 20

# Sequential mode (one host at a time, for when you're being careful)
taskhound -u user -p pass -d corp.local -t host1 --threads 1
```

Note: Windows limits around 10 concurrent SMB connections per source host. If you're scanning few targets repeatedly, `--rate-limit` helps avoid getting your connections dropped:

```bash
# Cap at 5 targets per second
--rate-limit 5
```

For extra stealth (or if your SOC is jumpy), add jitter. This only applies in sequential mode (`--threads 1`), because adding random delays to a thread pool would be... architecturally questionable.

```bash
# 0-5 second random delay between hosts
--threads 1 --jitter 5
```

Or just use `--opsec` which bundles all the quiet options together: `--no-ldap --no-rpc --no-loot --no-credguard --no-validate-creds --threads 1`. Combine with `--jitter` if you're feeling particularly paranoid.

## Auto-Target Discovery

Instead of maintaining a host list, let TaskHound find targets for you:

```bash
taskhound -u user -p pass -d corp.local --dc-ip 10.0.0.1 --auto-targets
```

### Data Source Priority

TaskHound tries BloodHound first (if configured via `--bloodhound-*` options), then falls back to LDAP. BloodHound is faster and doesn't generate LDAP traffic, but requires a running BloodHound CE instance with recent data.

### Smart Filtering

By default, `--auto-targets` filters out noise:

| Filter | Default | Override |
|--------|---------|----------|
| Disabled computer accounts | Excluded | `--include-disabled` |
| Stale accounts | Excluded | `--stale-threshold 180` (days) |
| Domain Controllers | Excluded | `--include-dcs` |

DCs are excluded because scanning them is noisy and usually not what you want during an engagement. If you genuinely need DC task enumeration, `--include-dcs` is there. No judgment.

### LDAP Filter Presets

The `--ldap-filter` flag supports presets or raw LDAP syntax:

```bash
# Preset filters
--ldap-filter servers        # Server OS only
--ldap-filter workstations   # Workstation OS only

# Raw LDAP (when presets aren't enough)
--ldap-filter "(operatingSystem=*2019*)"
```

When using BloodHound as the data source, presets work but raw LDAP filters require the LDAP fallback path. I know this is far from ideal.

## SID Resolution Chain

When TaskHound encounters a SID, it walks a multi-tier resolution chain. Each tier is tried in order until one returns a name:

| Tier | Source | Speed | Network? |
|------|--------|-------|----------|
| 0 | Well-known SIDs + special patterns | Instant | No |
| 1 | SQLite cache | Fast | No |
| 2 | BloodHound API | Fast | Yes (HTTP) |
| 3 | LSARPC (target host, then DC) | Medium | Yes (SMB) |
| 4 | LDAP | Medium | Yes (LDAP) |
| 5 | Global Catalog | Medium | Yes (LDAP/GC) |

Most SIDs resolve at tier 0 or 1 after the first run. The cache makes repeat scans significantly faster.

### Separate LDAP Credentials

Sometimes your scanning account doesn't have LDAP access, or you want to use a different account for SID resolution:

```bash
--ldap-user lookupaccount --ldap-password 'LessPrivileged123'
```

This only affects LDAP-based SID resolution (tiers 4 and 5). SMB auth still uses the main credentials.

### Global Catalog (Cross-Domain)

Tier 5 kicks in for SIDs from trusted domains. TaskHound auto-discovers the GC server, but this only works if there's a forest trust and the GC is reachable. For multi-forest environments, this is what resolves those mysterious foreign SIDs that LDAP can't find.

## Caching

SID resolution results are cached in a local SQLite database. This is more important than it sounds -- a 500-host scan can generate thousands of SID lookups, and hitting LDAP/LSARPC for each one is slow and noisy.

```bash
# Default: 24-hour TTL
--cache-ttl 86400

# Disable caching entirely (for when you suspect stale data)
--no-cache

# Nuke the cache and start fresh
--clear-cache
```

The cache lives alongside your TaskHound config. It's just SQLite, so you can inspect it with any SQLite tool if you're curious what's in there.

## DNS over TCP

If you're routing through a SOCKS proxy (common in tunneled engagements), UDP DNS won't work. Force TCP:

```bash
--dns-tcp
```

That's it. Small flag, surprisingly important when you're pivoting through three hosts and wondering why DNS resolution is failing silently.

## AdaptixC2 BOF Integration

There's a BOF (Beacon Object File) implementation of TaskHound's core enumeration logic in the Extension-Kit repository. It runs inside AdaptixC2 agents, which means you can enumerate scheduled tasks without dropping a Python runtime on target. The BOF handles the SMB and XML parsing natively. If you're using AdaptixC2, check the Extension-Kit repo for the taskhound module -- I would have loved to integrate some sort of association between the two tools, but for now they're separate. Left as an exercise for the reader.
