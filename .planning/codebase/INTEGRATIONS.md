# External Integrations

**Analysis Date:** 2026-02-06

## APIs & External Services

**BloodHound Community Edition (BHCE):**
- REST API over HTTP/HTTPS for Cypher query execution and authentication
- SDK/Client: `requests` HTTP library
- Auth: Bearer token (username/password) or API Key (HMAC-signed requests)
  - Implementation: `taskhound/utils/bh_auth.py` (BloodHoundAuthenticator class)
  - Implementation: `taskhound/utils/bh_api.py` (HMAC signing, token retrieval)
- Endpoints:
  - `POST /api/v2/graphs/cypher` - Execute Cypher queries
  - `GET /api/version` - Version check / connection validation
- Connection: Default `http://localhost:8080`, configurable via `--bh-connector` or TOML `[bloodhound]`
- Environment vars supported: `BH_API_KEY`, `BH_API_KEY_ID` (via TOML references)

**Legacy BloodHound (Neo4j):**
- Neo4j Bolt protocol (binary, not HTTP)
- SDK/Client: `neo4j` Python driver (conditional import, optional)
- Auth: Username/password for Neo4j Bolt
- Port: `bolt://host:7687` (standard Neo4j Bolt port)
- Connection: `--bhce` flag selects BHCE; absence defaults to Legacy mode
- Cypher queries: High-value user detection, domain SID caching, user property lookups
- Note: Not compatible with OpenGraph output (`taskhound/config.py` enforces this)

**Windows Domain Services (Active Directory):**

- SMB (Server Message Block):
  - Protocol: SMB3 over port 445
  - Purpose: Enumerate scheduled tasks via RPC, access DPAPI secrets, LAPS retrieval
  - SDK/Client: `impacket.smbconnection.SMBConnection`
  - Auth: NTLM (cleartext password, NTLM hash LM:NT or NT-only, Kerberos, AES key)
  - Implementation: `taskhound/smb/connection.py` (smb_connect function)

- RPC / DCE-RPC:
  - Protocol: DCE-RPC over SMB (TSCH - Task Scheduler Service)
  - Purpose: Query scheduled task definitions (XML parsing, triggers, credentials)
  - SDK/Client: `impacket.dcerpc.v5.tsch` (Task Scheduler RPC interface)
  - Implementation: `taskhound/smb/task_rpc.py` (TaskRPCScanner class)
  - Port: Implicit over SMB (445)

- LDAP / LDAPS:
  - Protocol: LDAP (389) or LDAPS (636) over TCP
  - Purpose: User/group enumeration, SID resolution, Tier-0 group membership
  - SDK/Client: `impacket.ldap.ldap` (LDAPConnection)
  - Auth: Simple bind (username/password) or Kerberos
  - Nameserver: Configurable via `--nameserver` (defaults to system DNS)
  - Implementation: `taskhound/utils/ldap.py` (get_ldap_connection function)

- DNS:
  - Protocol: DNS SRV/A/PTR records
  - Purpose: DC discovery (`_ldap._tcp.dc._msdcs.{domain}`), GC discovery (`_gc._tcp.{forest_root}`), reverse lookups
  - SDK/Client: `dnspython` library (optional, falls back to `socket` module)
  - Implementation: `taskhound/utils/dns.py` (discover_domain_controllers, discover_global_catalog_servers)

## Data Storage

**Databases:**
- SQLite (persistent cache)
  - Purpose: Cache SID resolution results, LAPS passwords, user properties
  - Connection: Auto-created, default location: working directory or configurable
  - ORM: Direct `sqlite3` module (no ORM)
  - Implementation: `taskhound/utils/cache_manager.py`
  - Enabled via: `--cache` flag or TOML `[cache] enabled = true`
  - TTL: Configurable, default 86400 seconds (24 hours)

**File Storage:**
- Local filesystem only:
  - Task XML exports: `--output-dir` (default: `./output`)
  - Report formats: Plain text, JSON, CSV, HTML
  - BloodHound OpenGraph JSON: `--opengraph-output` (default: `./opengraph`)
  - Config: TOML file from working directory or `~/.config/taskhound/`

**Caching:**
- SQLite-based persistent cache (documented above)
- In-memory caching of DNS lookups, LDAP queries, BloodHound data
- Cache manager: `taskhound/utils/cache_manager.py`

## Authentication & Identity

**Auth Provider:**
- Custom (none external)
- Mechanisms supported:
  - Cleartext password
  - NTLM hash (LM:NT or NT-only format)
  - Kerberos (with KDC host specification, AES key support, TGT/TGS from ccache)
  - LDAP simple bind
  - BloodHound API Key (HMAC-signed) or Bearer token (username/password)
  - SMB NTLMv2 authentication

- Implementation:
  - LDAP: `taskhound/utils/ldap.py` (Kerberos/NTLM support via impacket)
  - SMB: `taskhound/smb/connection.py` (all auth methods)
  - BloodHound: `taskhound/utils/bh_auth.py` (API key + bearer token)

**Credential Input:**
- CLI flags: `-u`, `-p`, `-d`, `--hashes`, `--aes-key`, `--kerberos`
- TOML config: `[authentication]` section
- Environment variables: Referenced in TOML via `${VAR}` syntax (not directly read)

## Monitoring & Observability

**Error Tracking:**
- None detected - Errors logged to console and optional log files

**Logs:**
- Console output via `taskhound/utils/logging.py`
- Log levels: debug, info, status, good, warn, error
- Output streams: stderr (warnings/errors), stdout (info/success)
- File logging: No persistent log file storage detected

## CI/CD & Deployment

**Hosting:**
- GitHub (repository: https://github.com/1r0BIT/TaskHound)
- No cloud deployment detected

**CI Pipeline:**
- Not detected (no `.github/workflows/` or similar found in initial scan)

**Distribution:**
- PyPI-compatible: `pip install .` from source
- Published releases via GitHub Releases

**AdaptixC2 Integration:**
- BOF (Beacon Object File) included: `taskhound/` directory contains Python implementation
- Note: Extension-Kit integration under `SAR-BOF/taskhound/`

## Environment Configuration

**Required env vars (optional, via TOML references):**
- `BH_API_KEY` - BloodHound API key for authentication
- `BH_API_KEY_ID` - BloodHound API key ID for authentication

**Optional env vars:**
- None detected (all config via CLI, TOML, or direct credentials)

**Secrets location:**
- CLI arguments: Plaintext risk (no masking)
- TOML config: Supports `${VAR}` references to environment variables
- .env files: Not detected (no dotenv dependency)

**Configuration Loading Order:**
- CLI arguments (highest priority)
- Environment variables (via TOML `${VAR}`)
- Local config file: `taskhound.toml` (working directory)
- User config file: `~/.config/taskhound/taskhound.toml`
- Defaults (lowest priority)

## Webhooks & Callbacks

**Incoming:**
- None detected

**Outgoing:**
- BloodHound OpenGraph auto-upload (optional)
  - Method: POST requests to BloodHound CE API
  - Endpoint: BloodHound ingest API (built-in to BHCE)
  - Trigger: When `--opengraph-auto-upload` flag enabled
  - Implementation: `taskhound/opengraph/writer.py` (generate_opengraph_files function)

## Cross-Domain Trust Resolution

**BloodHound Integration (SID → Name):**
- Query: `query_domain_by_netbios(netbios_name)` - NETBIOS to FQDN resolution
- Query: `query_user_by_upn(upn)` - User validation in trusted domains
- Query: `query_all_domain_sids()` - Cache all domain SID prefixes and trust relationships
- Purpose: Cross-domain user/group resolution without additional LDAP queries
- Implementation: `taskhound/connectors/bloodhound.py` (BloodHoundConnector class)

**SID Resolution Hierarchy:**
1. BloodHound (if connected)
2. Local cache (SQLite)
3. LSA RPC (impacket)
4. LDAP (Domain Controller)
5. Global Catalog (intra-forest trusts)
6. Failure: Cached as unknown

---

*Integration audit: 2026-02-06*
