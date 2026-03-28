<p align="center">
  <img width="350" height="350" alt="TaskHound Logo" src="https://github.com/user-attachments/assets/325b57e9-b96a-4de7-9974-736fd58fa70c" />
</p>

<p align="center">
  <strong>Windows Privileged Scheduled Task & Service Discovery Tool</strong> for fun and profit.
</p>

<p align="center">
  <a href="https://github.com/1r0BIT/TaskHound/releases">
    <img src="https://img.shields.io/github/v/release/1r0BIT/TaskHound?style=flat-square&logo=github&color=blue" alt="Latest Release">
  </a>
  <a href="https://bloodhound.specterops.io/">
    <img src="https://img.shields.io/badge/BloodHound-OpenGraph-red.svg?style=flat-square&logo=neo4j" alt="BloodHound OpenGraph">
  </a>
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/python-3.11+-blue.svg?style=flat-square&logo=python&logoColor=white" alt="Python 3.11+">
  </a>
  <br>
  <a href="https://deepwiki.com/1r0BIT/TaskHound">
    <img src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki">
  </a>
  <a href="https://twitter.com/0xr0BIT">
    <img src="https://img.shields.io/badge/Twitter-@0xr0BIT-1DA1F2?style=flat-square&logo=twitter&logoColor=white" alt="Twitter">
  </a>
  <a href="https://r0bit.io">
    <img src="https://img.shields.io/badge/Blog-r0bit.io-orange?style=flat-square&logo=rss&logoColor=white" alt="Blog">
  </a>
</p>
<hr />

TaskHound hunts for Windows scheduled tasks and services running with privileged accounts and stored credentials. It enumerates tasks over SMB, discovers domain-account services via SVCCTL RPC, and identifies high-value attack opportunities through BloodHound integration.

For the full backstory (and the questionable life choices that led here): [Part 1](https://r0bit.io/posts/taskhound/part1/index.html) and [Part 2](https://r0bit.io/posts/taskhound/part2/index.html).

## Quick Start

```bash
# Install
git clone https://github.com/1r0BIT/TaskHound.git
cd TaskHound
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt && pip install .

# Basic scan — tasks only
taskhound -u homer.simpson -p 'Doh!123' -d thesimpsons.local -t moe.thesimpsons.local

# Tasks + services (discovers domain-account services too)
taskhound -u homer.simpson -p 'Doh!123' -d thesimpsons.local -t moe.thesimpsons.local --services

# Services only (skip task enumeration)
taskhound -u homer.simpson -p 'Doh!123' -d thesimpsons.local -t moe.thesimpsons.local --services-only

# Auto-discover all domain computers, 20 threads
taskhound -u homer.simpson -p 'Doh!123' -d thesimpsons.local --dc-ip 10.0.0.1 --auto-targets --threads 20

# Full stealth mode
taskhound -u homer.simpson -p 'Doh!123' -d thesimpsons.local -t moe.thesimpsons.local --opsec --jitter 5
```

## Key Features

| Feature | Description |
|---------|-------------|
| **Scheduled Task Discovery** | Enumerates tasks over SMB, parses XMLs, identifies stored credentials |
| **Service Enumeration** | Discovers Windows services running as domain accounts via SVCCTL RPC |
| **Tier-0 & PRIV Detection** | Identifies tasks/services running as Domain Admins, Enterprise Admins, high-value targets |
| **BloodHound OpenGraph** | Visualize tasks and services as attack path nodes in BloodHound CE |
| **LSA Secret Extraction** | Registry-only credential extraction (no disk writes) for service passwords + DPAPI keys |
| **DPAPI Auto-Decryption** | Automatically extracts DPAPI system key and decrypts stored task credentials |
| **LAPS Integration** | Auto-retrieve LAPS passwords (Windows LAPS + Legacy) for per-host authentication |
| **Credential Validation** | Checks if stored task passwords are still valid via RPC heuristics |
| **Multi-threaded Scanning** | Parallel target processing with rate limiting and jitter for OPSEC |
| **Offline Analysis** | Process mounted disk images, collected XMLs, or exported registry hives |
| **Multiple Output Formats** | Plain text, JSON, CSV, and HTML security reports |
| **SID Resolution** | Multi-tier chain: BloodHound → Cache → LSARPC → LDAP → Global Catalog |

## Documentation

The README used to be 750 lines. It was getting out of hand. Here's where everything lives now:

| Guide | What's in it |
|-------|-------------|
| [Getting Started](docs/getting-started.md) | Installation, first scan, what to expect |
| [Authentication](docs/authentication.md) | Password, NTLM hash, Kerberos, AES keys, LAPS |
| [Service Enumeration](docs/service-enumeration.md) | `--services` flag, SVCCTL, gMSA detection, classification |
| [BloodHound Integration](docs/bloodhound-integration.md) | BHCE setup, OpenGraph nodes/edges, Cypher queries |
| [Loot & Credentials](docs/loot-and-credentials.md) | LSA extraction, DPAPI, `--loot`, `--no-lsa`, credential validation |
| [Output Formats](docs/output-formats.md) | Plain/JSON/CSV/HTML, directory structure |
| [OPSEC](docs/opsec.md) | Detection surface, `--opsec`, per-protocol disable flags |
| [Configuration](docs/configuration.md) | TOML config files, precedence, environment variables |
| [Offline Analysis](docs/offline-analysis.md) | `--offline`, `--offline-disk`, registry hive parsing |
| [Advanced Usage](docs/advanced.md) | Threading, auto-targets, SID resolution, caching, BOF |

## AdaptixC2 Integration

TaskHound's BOF is included in the [Adaptix Extension-Kit](https://github.com/Adaptix-Framework/Extension-Kit) under `SAR-BOF/taskhound/`.

## Roadmap

When caffeine intake and free time align:

- **Modularization of Stages**: This turned into a behemoth with way too many switches. I'll fix that.
- **Abuse Info Integration**: MITRE ATT&CK techniques in BloodHound nodes
- **Custom Tier-0 Mappings**: Support for user-defined privilege zones in BHCE

## Acknowledgements

- [Fortra/Impacket](https://github.com/fortra/impacket) - SMB/RPC/Kerberos, DPAPI-NG, MS-GKDI, regsecrets
- [SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound) - Attack path analysis
- [Podalirius/bh-opengraph](https://github.com/Podalirius/bh-opengraph) - OpenGraph inspiration
- [Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec) - LAPS implementation reference
- [jborean93/dpapi-ng](https://github.com/jborean93/dpapi-ng) - DPAPI-NG research
- [tijldeneut/DPAPIck3](https://github.com/tijldeneut/DPAPIck3) - DPAPI decryption reference
- [gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz) - DPAPI research
- [Synacktiv](https://www.synacktiv.com/publications/lsa-secrets-revisiting-secretsdump) - Registry-only LSA extraction research

And everyone who contributed to making offensive security tooling accessible.

---

## Disclaimer

TaskHound is strictly an **audit and educational tool**. Use only in environments you own or have explicit authorization to test. Seriously. Don't be a jerk.

## Contributing

PRs welcome. Half of this was caffeine-induced vibe-coding, so don't expect miracles.

## License

Use responsibly. No warranty provided. See `LICENSE` for details.
