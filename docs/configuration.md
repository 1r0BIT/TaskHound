# Configuration

Typing the same 15 flags every time gets old fast. TaskHound supports TOML config files so you can set defaults once and forget about them (until they break something).

## Config File Locations

TaskHound looks for config files in this order:

1. `taskhound.toml` in the current working directory
2. `~/.config/taskhound/taskhound.toml`

CLI arguments override config file values. Always. Environment variables sit in between. The full precedence:

**CLI args > Environment variables > Local config > User config > Defaults**

## Example Config

```toml
[authentication]
username = "homer.simpson"
domain = "THESIMPSONS.LOCAL"
# password = "Doh!123"  # Works but consider env vars for secrets

[target]
dc_ip = "10.0.0.1"
threads = 10
timeout = 30

[bloodhound]
live = true
connector = "http://127.0.0.1:8080"
api_key = "${BH_API_KEY}"          # Env var expansion
api_key_id = "${BH_API_KEY_ID}"    # Env var expansion
type = "bhce"

[bloodhound.opengraph]
enabled = true

[laps]
enabled = true

[cache]
enabled = true
ttl = 86400  # 24 hours
```

See `config/taskhound.toml.example` in the repo for every available option with comments. There are more knobs than you'll probably ever need.

## Environment Variables for Secrets

Putting passwords in config files is a bad look. Config values that start with `${` and end with `}` are expanded from environment variables:

```toml
[authentication]
password = "${TH_PASSWORD}"

[bloodhound]
api_key = "${BH_API_KEY}"
api_key_id = "${BH_API_KEY_ID}"
```

```bash
export TH_PASSWORD='Doh!123'
export BH_API_KEY='your-api-key'
export BH_API_KEY_ID='your-key-id'
taskhound -t moe.thesimpsons.local   # Everything else from config
```

This is marginally better than plaintext in a file. Not great, but better. For proper secret management you're on your own.

## Sections Reference

| Section | What it covers |
|---------|---------------|
| `[authentication]` | Username, domain, password, hashes, kerberos, AES key |
| `[target]` | DC IP, nameserver, threads, timeout, rate limiting, jitter |
| `[scanning]` | Offline mode, include/exclude filters, credential guard detection |
| `[opsec]` | Protocol restrictions (no_ldap, no_rpc), full OPSEC toggle |
| `[cache]` | SQLite cache settings, TTL |
| `[laps]` | LAPS toggle, custom admin username, force flag |
| `[bloodhound]` | Connection details, type (bhce/legacy), OpenGraph settings |
| `[ldap]` | Separate LDAP creds, tier-0 detection, Global Catalog server |
| `[dpapi]` | DPAPI loot toggle, DPAPI_SYSTEM key |
| `[output]` | Formats, directory, backup toggle, verbosity |
