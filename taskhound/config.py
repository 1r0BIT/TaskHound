import argparse
import os
import subprocess
import sys
import traceback
from typing import Any, Dict

from rich.console import Console
from rich.table import Table
from rich_argparse import RichHelpFormatter

try:
    import tomllib
except ImportError:
    # Fallback for older Python versions if needed
    try:
        import tomli as tomllib  # type: ignore[no-redef]  # conditional import fallback
    except ImportError:
        tomllib = None  # type: ignore[assignment]  # conditional import fallback

from .utils.helpers import is_ipv4


class TableRichHelpFormatter(RichHelpFormatter):
    """
    Custom help formatter that displays argument groups with Rich styling.
    Uses uppercase group names and custom color scheme.
    """

    # Customize styles for better appearance
    styles = {
        **RichHelpFormatter.styles,
        "argparse.groups": "bold cyan",
        "argparse.args": "green",
        "argparse.metavar": "yellow",
        "argparse.help": "white",
    }

    # Format group names in uppercase
    group_name_formatter = str.upper


class TableHelpAction(argparse.Action):
    """
    Custom help action that displays arguments in Rich tables.
    """

    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
        super().__init__(
            option_strings=option_strings,
            dest=dest,
            default=default,
            nargs=0,
            help=help,
        )

    def __call__(self, parser, namespace, values, option_string=None):
        console = Console()

        # Print description
        if parser.description:
            console.print(f"\n[bold white]{parser.description}[/]\n")

        # Print usage
        console.print(f"[dim]Usage:[/] [bold]{parser.prog}[/] [OPTIONS] [TARGETS]\n")

        # Group arguments by their group
        for group in parser._action_groups:
            # Skip empty groups
            actions = [a for a in group._group_actions if not isinstance(a, argparse._HelpAction) and not isinstance(a, TableHelpAction)]
            if not actions:
                continue

            # Print title
            console.print(f"[bold cyan]{group.title.upper()}[/]")

            # Print description if present
            if group.description:
                console.print(f"[dim]{group.description}[/]")

            # Create table for this group
            table = Table(
                border_style="dim",
                show_header=True,
                header_style="bold white",
                padding=(0, 1),
                expand=False,
            )

            table.add_column("Option", style="green", no_wrap=True)
            table.add_column("Description", style="white")

            for action in actions:
                # Build option string
                opts = ", ".join(action.option_strings) if action.option_strings else action.dest

                # Add metavar if present
                if action.metavar:
                    opts += f" [yellow]{action.metavar}[/]"
                elif action.type and action.type is not bool:
                    opts += f" [yellow]{action.dest.upper()}[/]"

                # Get help text - don't add default if already mentioned in help
                help_text = action.help or ""
                if (
                    action.default
                    and action.default != argparse.SUPPRESS
                    and action.default is not None
                    and action.default is not True
                    and action.default is not False
                    and "default:" not in help_text.lower()
                ):
                    help_text += f" [dim](default: {action.default})[/]"

                table.add_row(opts, help_text)

            console.print(table)
            console.print()

        parser.exit()


class OnceOnly(argparse.Action):
    """
    Custom argparse Action to prevent arguments from being specified multiple times.
    This is critical for preventing CLI parsing bugs where a flag (e.g. -d)
    is accidentally reused as part of another flag's value (e.g. -debug).
    """

    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is not None:
            raise argparse.ArgumentError(self, f"Argument {option_string} can only be specified once.")
        setattr(namespace, self.dest, values)


def load_config() -> Dict[str, Any]:
    """
    Load configuration from TOML files.

    Priority:
    1. ./taskhound.toml
    2. ./config/taskhound.toml
    3. ~/.config/taskhound/taskhound.toml
    """
    if not tomllib:
        return {}

    paths = ["taskhound.toml", "config/taskhound.toml", os.path.expanduser("~/.config/taskhound/taskhound.toml")]

    config_data = {}
    loaded_path = None

    for path in paths:
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    config_data = tomllib.load(f)
                loaded_path = path
                break
            except Exception as e:
                print(f"[!] Error loading config file {path}: {e}")

    if not config_data:
        return {}

    if loaded_path and loaded_path == "taskhound.toml":
        # Warn if using current working directory (security concern)
        print("[!] WARNING: Using taskhound.toml from current directory")
        print("[!] This can be a security risk - consider moving to config/taskhound.toml")

    # Flatten and map config to argparse destinations
    defaults = {}

    # Authentication
    auth = config_data.get("authentication", {})
    if "username" in auth:
        defaults["username"] = auth["username"]
    if "password" in auth:
        defaults["password"] = auth["password"]
    if "domain" in auth:
        defaults["domain"] = auth["domain"]
    if "hashes" in auth:
        defaults["hashes"] = auth["hashes"]
    if "kerberos" in auth:
        defaults["kerberos"] = auth["kerberos"]
    if "aes_key" in auth:
        defaults["aes_key"] = auth["aes_key"]

    # Target
    target = config_data.get("target", {})
    if "dc_ip" in target:
        defaults["dc_ip"] = target["dc_ip"]
    if "nameserver" in target:
        defaults["nameserver"] = target["nameserver"]
    if "timeout" in target:
        defaults["timeout"] = target["timeout"]
    if "target" in target:
        defaults["target"] = target["target"]
    if "targets_file" in target:
        defaults["targets_file"] = target["targets_file"]
    if "threads" in target:
        defaults["threads"] = target["threads"]
    if "rate_limit" in target:
        defaults["rate_limit"] = target["rate_limit"]
    if "jitter" in target:
        defaults["jitter"] = target["jitter"]
    if "dns_tcp" in target:
        defaults["dns_tcp"] = target["dns_tcp"]

    # Scanning
    scan = config_data.get("scanning", {})
    if "offline" in scan:
        defaults["offline"] = scan["offline"]
    if "include_local" in scan:
        defaults["include_local"] = scan["include_local"]
    if "opsec" in scan:
        defaults["opsec"] = scan["opsec"]
    if "unsaved_creds" in scan:
        defaults["unsaved_creds"] = scan["unsaved_creds"]
    if "include_ms" in scan:
        defaults["include_ms"] = scan["include_ms"]
    if "include_all" in scan:
        defaults["include_all"] = scan["include_all"]
    if "credguard_detect" in scan:
        defaults["credguard_detect"] = scan["credguard_detect"]
    if "bh_data" in scan:
        defaults["bh_data"] = scan["bh_data"]

    # OPSEC settings - granular control over noisy operations
    opsec_section = config_data.get("opsec", {})
    if "enabled" in opsec_section:
        defaults["opsec"] = opsec_section["enabled"]
    if "no_ldap" in opsec_section:
        defaults["no_ldap"] = opsec_section["no_ldap"]
    if "no_rpc" in opsec_section:
        defaults["no_rpc"] = opsec_section["no_rpc"]

    # Cache
    cache = config_data.get("cache", {})
    if "ttl" in cache:
        defaults["cache_ttl"] = cache["ttl"]
    if "enabled" in cache:
        defaults["no_cache"] = not cache["enabled"]
    if "file" in cache:
        defaults["cache_file"] = cache["file"]

    # LAPS
    laps = config_data.get("laps", {})
    if "enabled" in laps:
        defaults["laps"] = laps["enabled"]
    if "user" in laps:
        defaults["laps_user"] = laps["user"]
    if "force" in laps:
        defaults["force_laps"] = laps["force"]

    # Credential Validation
    cred_validation = config_data.get("credential_validation", {})
    if "enabled" in cred_validation:
        defaults["validate_creds"] = cred_validation["enabled"]

    # DPAPI
    dpapi = config_data.get("dpapi", {})
    if "loot" in dpapi:
        defaults["loot"] = dpapi["loot"]
    if "key" in dpapi:
        defaults["dpapi_key"] = dpapi["key"]

    # BloodHound
    bh = config_data.get("bloodhound", {})
    if "live" in bh:
        defaults["bh_live"] = bh["live"]
    if "connector" in bh:
        defaults["bh_connector"] = bh["connector"]
    if "username" in bh:
        defaults["bh_user"] = bh["username"]
    if "password" in bh:
        defaults["bh_password"] = bh["password"]
    if "api_key" in bh:
        defaults["bh_api_key"] = bh["api_key"]
    if "api_key_id" in bh:
        defaults["bh_api_key_id"] = bh["api_key_id"]
    if "timeout" in bh:
        defaults["bh_timeout"] = bh["timeout"]
    if "save_file" in bh:
        defaults["bh_save"] = bh["save_file"]

    if "type" in bh:
        if bh["type"].lower() == "bhce":
            defaults["bhce"] = True
        elif bh["type"].lower() == "legacy":
            defaults["legacy"] = True

    # BloodHound OpenGraph
    bhog = bh.get("opengraph", {})
    if "enabled" in bhog:
        defaults["bh_opengraph"] = bhog["enabled"]
    # Note: output_dir is deprecated - OpenGraph now uses {output_dir}/opengraph/
    if "no_upload" in bhog:
        defaults["bh_no_upload"] = bhog["no_upload"]
    # Note: set_icon removed - icon is now always set on upload
    if "force_icon" in bhog:
        defaults["bh_force_icon"] = bhog["force_icon"]
    if "icon" in bhog:
        defaults["bh_icon"] = bhog["icon"]
    if "color" in bhog:
        defaults["bh_color"] = bhog["color"]
    if "allow_orphans" in bhog:
        defaults["bh_allow_orphans"] = bhog["allow_orphans"]

    # LDAP
    ldap = config_data.get("ldap", {})
    if "no_ldap" in ldap:
        defaults["no_ldap"] = ldap["no_ldap"]
    if "user" in ldap:
        defaults["ldap_user"] = ldap["user"]
    if "password" in ldap:
        defaults["ldap_password"] = ldap["password"]
    if "hashes" in ldap:
        defaults["ldap_hashes"] = ldap["hashes"]
    if "domain" in ldap:
        defaults["ldap_domain"] = ldap["domain"]
    if "tier0" in ldap:
        defaults["ldap_tier0"] = ldap["tier0"]
    if "gc_server" in ldap:
        defaults["gc_server"] = ldap["gc_server"]

    # Output
    output = config_data.get("output", {})
    if "formats" in output:
        # New-style: output.formats = ["plain", "json"]
        defaults["output"] = ",".join(output["formats"])
    if "dir" in output:
        defaults["output_dir"] = output["dir"]
    if "no_backup" in output:
        defaults["no_backup"] = output["no_backup"]
    if "no_summary" in output:
        defaults["no_summary"] = output["no_summary"]
    if "debug" in output:
        defaults["debug"] = output["debug"]
    if "verbose" in output:
        defaults["verbose"] = output["verbose"]
    if "no_confirm" in output:
        defaults["no_confirm"] = output["no_confirm"]

    return defaults


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="taskhound",
        description="Windows Privileged Scheduled Task Discovery Tool for fun and profit.",
        formatter_class=TableRichHelpFormatter,
        add_help=False,  # Disable default help
    )
    # Add custom table-based help
    ap.add_argument("-h", "--help", action=TableHelpAction, help="Show this help message")

    # Authentication options
    auth = ap.add_argument_group("Authentication options")
    auth.add_argument("-u", "--username", action=OnceOnly, help="Username (required for online mode)")
    auth.add_argument(
        "-p", "--password", action=OnceOnly, help="Password (omit with -k if using Kerberos/ccache)"
    )
    auth.add_argument("-d", "--domain", action=OnceOnly, help="Domain (required for online mode)")
    auth.add_argument(
        "--hashes", help="NTLM hashes in LM:NT format (or NT-only 32-hex) to use instead of password"
    )
    auth.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication (supports ccache)")
    auth.add_argument(
        "--aes-key",
        dest="aes_key",
        help="AES key for Kerberos authentication (AES-128: 32 hex chars, AES-256: 64 hex chars). Implies -k."
    )

    # Target selection
    target = ap.add_argument_group("Target options")
    target.add_argument("-t", "--target", action=OnceOnly, help="Target(s) - single host or comma-separated list (e.g., 192.168.1.1,192.168.1.2)")
    target.add_argument("-T", "--targets-file", help="File with targets, one per line")
    target.add_argument("--dc-ip", help="Domain controller IP (required when using Kerberos without DNS)")
    target.add_argument(
        "--ns", "--nameserver",
        dest="nameserver",
        help="DNS nameserver for lookups. If not specified, uses --dc-ip or system DNS. "
        "Useful when DNS server differs from DC (lab environments, split DNS).",
    )
    target.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Connection timeout in seconds (default: 5). Lower values speed up scans with unreachable hosts.",
    )
    target.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of parallel worker threads for scanning multiple targets (default: 10). "
        "Recommended: 10-20 for large networks with unique hosts. Use --threads 1 for sequential mode. "
        "NOTE: Windows limits ~10 concurrent SMB connections per host - use --rate-limit if scanning few hosts repeatedly.",
    )
    target.add_argument(
        "--rate-limit",
        type=float,
        default=None,
        help="Maximum targets per second (default: unlimited). Use to avoid triggering security alerts "
        "or hitting Windows SMB connection limits. Example: --rate-limit 5 limits to 5 targets/second.",
    )
    target.add_argument(
        "--jitter",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Random delay (0 to N seconds) between scanning each host. Useful for OPSEC to avoid "
        "predictable timing patterns. Only applies to sequential scanning (--threads 1). "
        "Example: --jitter 5 adds 0-5 second random delay between hosts.",
    )
    target.add_argument(
        "--dns-tcp",
        action="store_true",
        help="Force DNS queries over TCP instead of UDP. Required when using SOCKS proxies or proxychains "
        "(UDP doesn't traverse SOCKS). Combine with --dc-ip for reliable DNS resolution through tunnels.",
    )
    target.add_argument(
        "--auto-targets",
        action="store_true",
        help="Auto-discover targets by querying for domain computer objects. "
        "Uses BloodHound data if available (via --bloodhound-* options), otherwise falls back to LDAP. "
        "By default, filters out disabled accounts and stale computers (>60 days). "
        "Can be combined with -t/--target or -T/--targets-file to add additional targets.",
    )
    target.add_argument(
        "--ldap-filter",
        help="Filter for --auto-targets. Supports presets or raw LDAP syntax. "
        "Presets: 'servers' (Windows Server OS), 'workstations' (non-server OS). "
        "Raw LDAP: '(operatingSystem=*2019*)' for specific OS. "
        "Only one filter allowed. When using BloodHound, presets work but raw LDAP requires LDAP fallback.",
    )
    target.add_argument(
        "--include-dcs",
        action="store_true",
        help="Include Domain Controllers when using --auto-targets. By default, DCs are excluded "
        "to reduce noise and avoid security concerns from scanning the DC directly.",
    )
    target.add_argument(
        "--include-disabled",
        action="store_true",
        help="Include disabled computer accounts in --auto-targets. By default, disabled accounts "
        "are filtered out since they represent decommissioned or offline systems.",
    )
    target.add_argument(
        "--stale-threshold",
        type=int,
        default=60,
        metavar="DAYS",
        help="Exclude computers with password age older than DAYS (default: 60). "
        "Stale accounts typically indicate offline/decommissioned systems. "
        "Set to 0 to disable stale filtering. Based on pwdLastSet attribute.",
    )

    # High value / scanning options
    scan = ap.add_argument_group("Scanning options")
    scan.add_argument(
        "--offline",
        help="Offline mode: parse previously collected XML files from directory (no authentication required)",
    )
    scan.add_argument(
        "--offline-disk",
        help="Offline disk mode: collect and analyze from mounted Windows filesystem (VHDX, forensic image). "
        "Point to the mount root (e.g., /mnt/vhdx). Creates TaskHound-compatible backup by default (use --no-backup to disable).",
    )
    scan.add_argument(
        "--disk-hostname",
        help="Override hostname detection for --offline-disk mode (default: auto-detect from SYSTEM registry)",
    )
    scan.add_argument("--bh-data", help="Path to High Value Target export (csv/json from Neo4j)")

    # BloodHound live connection options
    bh_group = ap.add_argument_group("BloodHound Live Connection")
    bh_group.add_argument(
        "--bh-live",
        action="store_true",
        help="Use live BloodHound connection (parameters can be provided via CLI or taskhound.toml file)",
    )
    bh_group.add_argument("--bh-user", help="BloodHound username (or set in config file)")
    bh_group.add_argument("--bh-password", help="BloodHound password (or set in config file)")
    bh_group.add_argument(
        "--bh-api-key",
        help="BloodHound API key for HMAC authentication (requires --bh-api-key-id, or set api_key in config file)",
    )
    bh_group.add_argument(
        "--bh-api-key-id",
        help="BloodHound API key ID for HMAC authentication (requires --bh-api-key, or set api_key_id in config file)",
    )
    bh_group.add_argument(
        "--bh-connector",
        default="http://127.0.0.1:8080",
        help="BloodHound connector URI (default: http://127.0.0.1:8080, or set in config file). "
        "Examples: localhost, http://localhost:8080, https://bh.domain.com, bolt://neo4j.local:7687. "
        "Supports both BHCE (http/https) and Legacy (bolt) protocols. "
        "If no protocol specified: defaults to http:// for BHCE, bolt:// for Legacy.",
    )
    bh_group.add_argument(
        "--bh-timeout",
        type=int,
        default=120,
        help="Timeout in seconds for BloodHound API queries (default: 120). Increase for large environments.",
    )

    # BloodHound type selection (mutually exclusive)
    bh_type = bh_group.add_mutually_exclusive_group()
    bh_type.add_argument(
        "--bhce", action="store_true", help="Use BloodHound Community Edition (or set type=bhce in config)"
    )
    bh_type.add_argument("--legacy", action="store_true", help="Use Legacy BloodHound (or set type=legacy in config)")

    bh_group.add_argument("--bh-save", help="Save BloodHound query results to file (or set save_file in config)")

    # BloodHound OpenGraph Integration (BHCE ONLY)
    bhog = ap.add_argument_group(
        "BloodHound OpenGraph Integration",
        description="Automatically generate and optionally upload OpenGraph data to BloodHound CE (BHCE ONLY)",
    )
    bhog.add_argument(
        "--bh-opengraph",
        action="store_true",
        help="Generate BloodHound OpenGraph JSON files (auto-enabled if taskhound.toml has valid BHCE credentials). "
        "REQUIRES --bhce or type=bhce in config - NOT compatible with Legacy BloodHound! "
        "Files are saved to {output_dir}/opengraph/",
    )
    bhog.add_argument(
        "--bh-no-upload",
        action="store_true",
        help="Generate OpenGraph files but skip automatic upload to BloodHound (files still saved)",
    )
    bhog.add_argument(
        "--bh-force-icon",
        action="store_true",
        help="Force icon update even if ScheduledTask icon already exists (icon is set automatically on upload)",
    )
    bhog.add_argument(
        "--bh-icon", default="clock", help="Font Awesome icon name for ScheduledTask nodes (default: clock)"
    )
    bhog.add_argument(
        "--bh-color",
        default="#8B5CF6",
        help="Hex color code for ScheduledTask node icon (default: #8B5CF6 - vibrant purple)",
    )
    bhog.add_argument(
        "--bh-allow-orphans",
        action="store_true",
        help="Create edges even when Computer/User nodes are missing from BloodHound (may create orphaned edges)",
    )

    scan.add_argument(
        "--opsec",
        action="store_true",
        help="OPSEC safe mode: Disables noisy operations. Equivalent to --no-ldap --no-rpc --no-loot --no-credguard --no-validate-creds --threads 1. "
        "Forces sequential scanning and limits SID resolution to BloodHound data and local cache only. "
        "Tip: Combine with --jitter for randomized timing between hosts.",
    )
    scan.add_argument(
        "--no-rpc",
        action="store_true",
        help="Disable RPC operations (LSARPC SID lookup). Does not affect SMB task enumeration. "
        "Note: Also disables Credential Guard detection and credential validation (which require RPC).",
    )
    scan.add_argument(
        "--include-ms", action="store_true", help="Also include \\Microsoft scheduled tasks (WARNING: very slow)"
    )
    scan.add_argument(
        "--include-local",
        action="store_true",
        help="Include tasks running as local system accounts (NT AUTHORITY\\SYSTEM, S-1-5-18, etc.)",
    )
    scan.add_argument(
        "--include-all",
        action="store_true",
        help="Include ALL tasks (equivalent to --include-ms --include-local --unsaved-creds) - WARNING: VERY SLOW AND NOISY!",
    )
    scan.add_argument(
        "--unsaved-creds",
        action="store_true",
        help="Show scheduled tasks that do not store credentials (unsaved credentials)",
    )
    scan.add_argument(
        "--no-credguard",
        action="store_true",
        help="Disable Credential Guard detection via remote registry. Reduces RPC traffic.",
    )
    scan.add_argument(
        "--no-validate-creds",
        action="store_true",
        help="Disable credential validation via Task Scheduler RPC. Reduces RPC traffic.",
    )

    # DPAPI decryption options
    dpapi = ap.add_argument_group("DPAPI Credential Decryption")
    dpapi.add_argument(
        "--no-loot",
        action="store_true",
        help="Disable automatic collection of DPAPI credential blobs. By default, TaskHound collects "
        "credential files for offline decryption or immediate decryption if --dpapi-key is provided.",
    )
    dpapi.add_argument(
        "--dpapi-key",
        help="DPAPI_SYSTEM userkey from LSA secrets dump (hex format, e.g., 0x51e43225...). "
        "When provided, collected credentials are decrypted immediately.",
    )

    # LDAP/SID Resolution options
    ldap = ap.add_argument_group(
        "LDAP/SID Resolution options",
        description='Alternative credentials for SID lookups. Useful with local admin access (domain=".") or when using different privilege levels. Supports both plaintext passwords and NTLM hashes.',
    )
    ldap.add_argument(
        "--no-ldap",
        action="store_true",
        help="Disable LDAP queries for SID resolution (improves OPSEC but reduces user-friendliness)",
    )
    ldap.add_argument(
        "--ldap-user", help="Alternative username for SID lookup (can be different from main auth credentials)"
    )
    ldap.add_argument(
        "--ldap-password",
        help="Alternative password for SID lookup (plaintext only - use with --ldap-hashes for hash-based auth)",
    )
    ldap.add_argument(
        "--ldap-hashes",
        help="Alternative NTLM hashes for SID lookup (format: [LM:]NT, e.g., :2D0AA42EB9B24A64E5427A65552AE1F4 or aad3b435b51404eeaad3b435b51404ee:2D0AA42EB9B24A64E5427A65552AE1F4)",
    )
    ldap.add_argument(
        "--ldap-domain", help="Alternative domain for SID lookup (can be different from main auth domain)"
    )
    ldap.add_argument(
        "--ldap-tier0",
        action="store_true",
        help="Enable LDAP-based Tier-0 detection via group membership queries. Checks if runas accounts are members of privileged groups (Domain Admins, Enterprise Admins, etc.) without requiring BloodHound data.",
    )
    ldap.add_argument(
        "--gc-server",
        help="Global Catalog server IP for resolving foreign domain SIDs. If not specified, auto-discovers via DNS SRV records (_gc._tcp.<domain>). Use this when auto-discovery fails or you want to target a specific GC.",
    )

    # LAPS (Local Administrator Password Solution) options
    laps_group = ap.add_argument_group(
        "LAPS Authentication",
        description="Use LAPS passwords for SMB authentication. Queries AD for LAPS attributes and uses "
        "per-host local admin credentials. Supports both Windows LAPS (msLAPS-Password) and "
        "Legacy LAPS (ms-Mcs-AdmPwd).",
    )
    laps_group.add_argument(
        "--laps",
        action="store_true",
        help="Enable LAPS authentication. Queries LAPS passwords from AD and uses them for SMB auth to each target.",
    )
    laps_group.add_argument(
        "--laps-user",
        help="Override local admin username for LAPS auth (default: from msLAPS-Password JSON or 'Administrator' for legacy LAPS)",
    )
    laps_group.add_argument(
        "--force-laps",
        action="store_true",
        help="Force LAPS usage even in OPSEC mode. LAPS queries may be audited but other OPSEC-unsafe operations will remain disabled.",
    )

    # Cache options
    cache_group = ap.add_argument_group("Cache options")
    cache_group.add_argument(
        "--cache-ttl", type=int, default=86400, help="Cache time-to-live in seconds (default: 86400 / 24h)"
    )
    cache_group.add_argument("--no-cache", action="store_true", help="Disable caching of SID resolutions")
    cache_group.add_argument("--clear-cache", action="store_true", help="Clear the cache before running")
    cache_group.add_argument("--cache-file", help="Path to cache file (default: ~/.taskhound/cache.db)")

    # Output options
    out = ap.add_argument_group(
        "Output options",
        description="Control output formats and directory structure. All outputs go to --output-dir with type-specific subdirectories."
    )
    out.add_argument(
        "-o", "--output",
        help="Output formats (comma-separated): plain,json,csv,html. Example: --output json,html (default: plain)",
    )
    out.add_argument(
        "--output-dir",
        default="./output",
        help="Base output directory (default: ./output). Creates subdirs per output type.",
    )
    out.add_argument(
        "--no-backup",
        action="store_true",
        help="Disable raw backup collection (XML task files + DPAPI loot). By default, backups are saved to <output-dir>/raw_backups/",
    )
    out.add_argument("--no-summary", action="store_true", help="Disable summary table at the end of the run")

    # Misc
    misc = ap.add_argument_group("Misc")
    misc.add_argument("--verbose", action="store_true", help="Enable verbose output")
    misc.add_argument("--debug", action="store_true", help="Enable debug output (print full stack traces)")
    misc.add_argument(
        "--no-confirm",
        action="store_true",
        help="Skip confirmation prompts for noisy operations (useful for automation/CI)",
    )
    # Load defaults from config file
    defaults = load_config()
    if defaults:
        ap.set_defaults(**defaults)

    return ap


# Valid output format types
VALID_OUTPUT_FORMATS = {"plain", "json", "csv", "html"}


def validate_args(args):
    # Initialize no_rpc if not present (for backwards compatibility)
    if not hasattr(args, 'no_rpc'):
        args.no_rpc = False

    # Parse and validate --output formats
    args.output_formats = set()
    if args.output:
        for fmt in args.output.lower().split(","):
            fmt = fmt.strip()
            if fmt not in VALID_OUTPUT_FORMATS:
                print(f"[!] ERROR: Invalid output format '{fmt}'")
                print(f"[!] Valid formats: {', '.join(sorted(VALID_OUTPUT_FORMATS))}")
                sys.exit(1)
            args.output_formats.add(fmt)
    else:
        # Default to plain output
        args.output_formats = {"plain"}

    # Derive backup flag (default ON, --no-backup disables)
    args.backup = not getattr(args, 'no_backup', False)

    # Handle --opsec as alias for all noise-reducing flags
    # --opsec sets all disable flags for maximum stealth
    if args.opsec:
        # Set the underlying flags (--opsec implies all)
        if not args.no_ldap:
            args.no_ldap = True
        if not args.no_rpc:
            args.no_rpc = True
        if not getattr(args, 'no_loot', False):
            args.no_loot = True
        if not getattr(args, 'no_credguard', False):
            args.no_credguard = True
        if not getattr(args, 'no_validate_creds', False):
            args.no_validate_creds = True
        # Force sequential scanning to reduce network noise
        if args.threads > 1:
            args.threads = 1

    # Derive enabled flags from the --no-* flags for cleaner logic
    # These are the "effective" settings after processing --opsec and --no-rpc
    args.credguard_detect = not getattr(args, 'no_credguard', False)
    args.validate_creds = not getattr(args, 'no_validate_creds', False)
    args.loot = not getattr(args, 'no_loot', False)

    # --no-rpc implies no credguard and no validate_creds (they require RPC)
    if args.no_rpc:
        if args.credguard_detect:
            args.credguard_detect = False
        if args.validate_creds:
            args.validate_creds = False

    # Handle LAPS + OPSEC compatibility
    if getattr(args, "laps", False):
        if args.no_ldap and not getattr(args, "force_laps", False):
            print("[!] ERROR: --laps is incompatible with --no-ldap")
            print("[!] LAPS requires LDAP queries to retrieve passwords, which may trigger:")
            print("[!]   - Event ID 4662 (Directory Service Access) for LAPS attribute reads")
            print("[!]   - Event ID 4624 (Logon) for each LAPS-authenticated SMB connection")
            print("[!]")
            print("[!] Options:")
            if args.opsec:
                print("[!]   1. Remove --opsec flag to use LAPS normally")
            else:
                print("[!]   1. Remove --no-ldap flag to use LAPS normally")
            print("[!]   2. Add --force-laps to use LAPS while keeping other protections")
            print("[!]      (RPC operations will still be disabled if --no-rpc/--opsec is set)")
            sys.exit(1)

        if args.no_ldap and getattr(args, "force_laps", False):
            print("[!] WARNING: --laps enabled with --force-laps despite LDAP restrictions")
            print("[!] LAPS LDAP queries may be audited (Event ID 4662)")
            if args.no_rpc:
                print("[!] RPC operations remain disabled (LSARPC, CredGuard, cred validation)")
            print()

        # LAPS requires DC IP for LDAP queries
        if not args.dc_ip:
            print("[!] ERROR: LAPS requires --dc-ip for LDAP queries")
            print("[!] Specify the domain controller IP address with --dc-ip")
            sys.exit(1)

        # LAPS requires domain credentials to query AD
        if not args.domain:
            print("[!] ERROR: LAPS requires --domain for LDAP queries")
            sys.exit(1)

        # Warn if using LAPS with single target (still works, but unusual)
        if args.target and not args.targets_file:
            print("[*] LAPS mode with single target - will query AD for LAPS password")

    # Handle --include-all flag expansion and warnings
    if args.include_all:
        print("[!] WARNING: --include-all flag detected!")
        print("[!] This will include ALL tasks: Microsoft tasks, local system accounts, and unsaved credentials")
        print("[!] This can be VERY SLOW and VERY NOISY - consider using specific flags instead")
        print("[!] Equivalent to: --include-ms --include-local --unsaved-creds")
        print()
        # Automatically enable the other flags
        args.include_ms = True
        args.include_local = True
        args.unsaved_creds = True

    # Auto-enable --bh-live when any BloodHound-specific flag is set
    # This provides a better UX - users don't need to remember to add --bh-live
    if not args.bh_live:
        bh_flags_set = any([
            args.bh_user,
            args.bh_password,
            args.bh_api_key,
            args.bh_api_key_id,
            args.bh_opengraph,
            getattr(args, "bhce", False),
            # Note: --bh-connector has a default, so we check if it's non-default
            args.bh_connector and args.bh_connector != "http://127.0.0.1:8080",
        ])
        if bh_flags_set:
            args.bh_live = True
            print("[+] BloodHound live mode auto-enabled (BloodHound flags detected)")

    # Handle BloodHound OpenGraph integration auto-detection
    # Auto-enable OpenGraph if BHCE credentials are present and user didn't explicitly disable
    if not args.bh_opengraph:
        # Check if we have enough info to connect to BHCE
        has_creds = (args.bh_user and args.bh_password) or (args.bh_api_key and args.bh_api_key_id)
        is_bhce = getattr(args, "bhce", False) or (not getattr(args, "legacy", False))  # Default to BHCE if not legacy

        if is_bhce and has_creds and args.bh_connector:
            args.bh_opengraph = True
            print("[+] BloodHound OpenGraph auto-enabled (found BHCE config)")
            if not args.bh_no_upload:
                print(
                    "[*] OpenGraph files will be automatically uploaded to BloodHound (use --bh-no-upload to disable)"
                )

    # If --bh-opengraph is explicitly set (either by user or auto-enabled above),
    # ensure we have config data for upload
    if args.bh_opengraph:
        # Check for BHCE compatibility
        is_legacy = getattr(args, "legacy", False)
        if is_legacy:
            print("[!] ERROR: OpenGraph generation is NOT compatible with Legacy BloodHound (Neo4j)")
            print("[!] Please use --bhce or remove --legacy flag")
            sys.exit(1)

        # Check for credentials if upload is enabled
        if not args.bh_no_upload:
            has_creds = (args.bh_user and args.bh_password) or (args.bh_api_key and args.bh_api_key_id)
            if not has_creds:
                print("[!] WARNING: OpenGraph enabled but no BloodHound credentials found")
                print("[!] Automatic upload will be skipped (files will still be generated)")
                args.bh_no_upload = True
    # Validate BloodHound live connection parameters
    if args.bh_live:
        # Check if all parameters are provided via command line or config defaults
        has_user = args.bh_user is not None
        has_password = args.bh_password is not None
        has_api_key = args.bh_api_key is not None and args.bh_api_key_id is not None
        has_type = args.bhce or args.legacy

        # Final validation - ensure all required parameters are now available
        # Either API key OR username+password required
        if not has_api_key and not (has_user and has_password):
            print("[!] ERROR: BloodHound authentication requires either:")
            print("[!]   - API key: --bh-api-key (or api_key in taskhound.toml)")
            print("[!]   - Username + password: --bh-user and --bh-password (or in taskhound.toml)")
            sys.exit(1)
        if not has_type:
            # Default to BHCE if not specified
            args.bhce = True
            has_type = True
            from .utils.logging import status
            status("[*] Defaulting to BloodHound Community Edition (BHCE)")

        if args.bh_data:
            print("[!] ERROR: Cannot use both --bh-live and --bh-data simultaneously")
            print("[!] Choose either live connection OR file import")
            sys.exit(1)

    # Offline mode validation
    if args.offline:
        # In offline mode, check that the path exists and is a directory
        if not os.path.exists(args.offline):
            print(f"[!] Offline directory does not exist: {args.offline}")
            sys.exit(1)
        if not os.path.isdir(args.offline):
            print(f"[!] Offline path must be a directory: {args.offline}")
            sys.exit(1)
        # Skip authentication validation for offline mode
        return

    # Offline disk mode validation (mounted Windows filesystem)
    if args.offline_disk:
        if not os.path.exists(args.offline_disk):
            print(f"[!] Offline disk mount point does not exist: {args.offline_disk}")
            sys.exit(1)
        if not os.path.isdir(args.offline_disk):
            print(f"[!] Offline disk path must be a directory: {args.offline_disk}")
            sys.exit(1)
        # Cannot combine with --offline
        if args.offline:
            print("[!] ERROR: Cannot use both --offline and --offline-disk")
            print("[!] Use --offline for TaskHound backup dirs, --offline-disk for mounted Windows filesystems")
            sys.exit(1)
        # Skip authentication validation for offline disk mode
        return

    # Online mode validation - require authentication parameters
    if not args.username:
        print("[!] Username (-u/--username) is required for online mode")
        sys.exit(1)
    if not args.domain:
        print("[!] Domain (-d/--domain) is required for online mode")
        sys.exit(1)

    # Auto-targets or explicit targets required
    auto_targets = getattr(args, "auto_targets", False)
    if not (args.target or args.targets_file or auto_targets):
        print("[!] Either --target, --targets-file, or --auto-targets is required for online mode")
        sys.exit(1)

    # --ldap-filter requires --auto-targets
    if getattr(args, "ldap_filter", None) and not auto_targets:
        print("[!] --ldap-filter requires --auto-targets")
        sys.exit(1)

    # Authentication method validation - require either password, hash, AES key, or Kerberos
    if not args.password and not args.hashes and not getattr(args, "aes_key", None) and not args.kerberos:
        print("[!] ERROR: Authentication required for online mode")
        print("[!] You must specify one of:")
        print("[!]   -p PASSWORD     (password authentication)")
        print("[!]   --hashes HASH   (NTLM hash authentication)")
        print("[!]   --aes-key KEY   (Kerberos with AES key)")
        print("[!]   -k              (Kerberos authentication with ccache)")
        print()
        if "KRB5CCNAME" in os.environ:
            print("[!] Detected KRB5CCNAME environment variable - did you forget the -k flag?")
        sys.exit(1)

    # LDAP password and hashes mutual exclusivity
    if args.ldap_password and args.ldap_hashes:
        print("[!] ERROR: Cannot specify both --ldap-password and --ldap-hashes")
        print("[!] Use --ldap-password for plaintext OR --ldap-hashes for NTLM hashes")
        sys.exit(1)

    # LDAP requires FQDN format - warn if domain appears to be NetBIOS
    if not args.no_ldap and not args.ldap_domain and "." not in args.domain:
        print("[!] WARNING: Domain appears to be NetBIOS format (e.g., 'DOMAIN')")
        print("[!] LDAP features require FQDN format (e.g., 'domain.local')")
        print("[!] Use --ldap-domain with FQDN or change --domain to FQDN")
        print("[!] Continuing, but LDAP SID resolution may fail")
        print()

    # KRB5 cache vs username mismatch
    if args.kerberos and "KRB5CCNAME" in os.environ:
        try:
            out = subprocess.check_output(["klist"], stderr=subprocess.DEVNULL, text=True)
            for line in out.splitlines():
                if "Default principal" in line:
                    cache_principal = line.split(":", 1)[1].strip()
                    cache_user = cache_principal.split("@")[0]
                    if cache_user.lower() != args.username.lower():
                        print("[!] Kerberos ticket cache user mismatch!")
                        print(f"    KRB5CCNAME contains tickets for: {cache_user}")
                        print(f"    But you supplied username     : {args.username}")
                        print("[!] Aborting. Please kdestroy your cache or use the matching user.")
                        sys.exit(1)
        except Exception:
            if args.debug:
                traceback.print_exc()

    # Kerberos + IP check for targets list
    # Exception: LAPS mode can resolve IPs to hostnames via DNS before connecting
    if args.kerberos and args.targets_file and not getattr(args, "laps", False):
        with open(args.targets_file) as f:
            for line in f:
                t = line.strip()
                if t and is_ipv4(t):
                    print(
                        "[!] Targets verification failed. Please supply hostnames or fqdns or switch to NTLM Auth (Kerberos doesn't like IP addresses)"
                    )
                    sys.exit(1)

    # Kerberos + IP for single target
    # Exception: LAPS mode can resolve IPs to hostnames via DNS before connecting
    if args.kerberos and args.target and is_ipv4(args.target.strip()) and not getattr(args, "laps", False):
        print(
            "[!] Targets verification failed. Please supply hostnames or fqdns or switch to NTLM Auth (Kerberos doesn't like IP addresses)"
        )
        sys.exit(1)

    # DPAPI key with multiple targets validation
    if args.dpapi_key and args.targets_file and not args.offline:
        print("[!] ERROR: --dpapi-key cannot be used with --targets-file")
        print("[!] Each target has a unique DPAPI key - you cannot use the same key for multiple targets")
        print()
        print("[*] Valid workflows:")
        print("    1. Single target with key:  --target <host> --dpapi-key <key>")
        print("    2. Collect from multiple:   --targets-file <file> (credentials collected automatically)")
        print("       Then decrypt offline:    --offline dpapi_loot/<target> --dpapi-key <target_key>")
        sys.exit(1)

    # DPAPI messaging for online mode
    if args.loot and not args.offline:
        if args.dpapi_key:
            # Single target with key: will collect and decrypt
            print("[*] DPAPI key provided - credentials will be collected and decrypted immediately")
        else:
            # Multi-target or no key: collect for offline decryption
            print("[*] DPAPI credential collection enabled (use --no-loot to disable)")
            print("[*] Credentials will be saved for offline decryption")
            print("[!] To decrypt immediately, provide --dpapi-key (single target only)")
            print("[!] Obtain dpapi_userkey with: nxc smb <target> -u <user> -p <pass> --lsa")
        print()

    # DPAPI offline decryption validation
    if args.offline and args.dpapi_key:
        # Offline mode with DPAPI key: decrypt previously collected files
        print("[*] Offline mode with --dpapi-key enabled")
        print("[*] Will decrypt DPAPI files from offline directory")
        print()
