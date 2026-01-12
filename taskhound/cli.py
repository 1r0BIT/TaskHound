import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.panel import Panel
from rich.prompt import Confirm

from .auth import AuthContext
from .config import build_parser, validate_args
from .engine import process_offline_directory, process_target
from .engine.async_runner import (
    AsyncConfig,
    AsyncTaskHound,
    aggregate_results,
)
from .laps import (
    LAPSCache,
    LAPSConnectionError,
    LAPSEmptyCacheError,
    LAPSFailure,
    get_laps_passwords,
    print_laps_summary,
)
from .opengraph import generate_opengraph_files
from .output.bloodhound import upload_opengraph_to_bloodhound
from .output.summary import print_decrypted_credentials, print_summary_table
from .output.writer import write_csv, write_json, write_rich_plain
from .parsers.highvalue import HighValueLoader
from .utils.cache_manager import init_cache
from .utils.console import (
    console,
    print_audit_report_section,
    print_backup_section,
    print_banner,
    print_opengraph_section,
)
from .utils.date_parser import parse_timestamp
from .utils.helpers import normalize_targets
from .utils.logging import debug, good, info, set_verbosity, status, warn
from .utils.network import verify_ldap_connection


def _handle_opengraph(
    args: Any,
    all_rows: List[Dict],
    opengraph_json_path: Optional[str],
    opengraph_json_overwrites: bool,
) -> None:
    """Handle BloodHound OpenGraph generation and upload."""
    from .config_model import BloodHoundConfig

    # Create consolidated config from args
    bh_config = BloodHoundConfig.from_args_and_config(args)

    # Build LDAP config for fallback resolution
    ldap_domain = getattr(args, "ldap_domain", None) or args.domain
    ldap_user = getattr(args, "ldap_user", None) or args.username
    ldap_password = getattr(args, "ldap_password", None) or args.password

    ldap_config = None
    if ldap_domain and ldap_user and (ldap_password or args.hashes):
        ldap_config = {
            "domain": ldap_domain,
            "dc_ip": args.dc_ip,
            "username": ldap_user,
            "password": ldap_password,
            "hashes": args.hashes,
            "kerberos": args.kerberos,
        }
        debug("LDAP fallback enabled for objectId resolution")

    # Query NetBIOS domain name for accurate cross-domain detection
    from .resolver import get_netbios_cache

    netbios_name = None
    netbios_cache = get_netbios_cache()
    our_fqdn = args.domain.upper() if args.domain else ""

    # Find our NETBIOS name by reverse lookup in cache
    for nb_name, fqdn in netbios_cache.items():
        if fqdn == our_fqdn:
            netbios_name = nb_name
            debug(f"NetBIOS domain name (from cache): {netbios_name}")
            break

    # Fallback: derive from FQDN first part
    if not netbios_name and args.domain:
        netbios_name = args.domain.split(".")[0].upper()
        debug(f"NetBIOS domain name (derived from FQDN): {netbios_name}")

    # Extract computer SIDs from task rows
    computer_sids = {}
    for row in all_rows:
        if hasattr(row, "host") and hasattr(row, "computer_sid") and row.host and row.computer_sid:
            computer_sids[row.host.upper()] = row.computer_sid

    # Create connector if credentials exist
    bh_connector = None
    if bh_config.has_credentials():
        from .connectors.bloodhound import BloodHoundConnector
        from .output.bloodhound import extract_host_from_connector

        host = extract_host_from_connector(bh_config.bh_connector)
        bh_connector = BloodHoundConnector(
            bh_type=bh_config.bh_type or "bhce",
            ip=host,
            username=bh_config.bh_username,
            password=bh_config.bh_password,
            api_key=bh_config.bh_api_key,
            api_key_id=bh_config.bh_api_key_id,
        )

    # OpenGraph files go to {output_dir}/opengraph/
    opengraph_output_dir = os.path.join(args.output_dir, "opengraph")

    # Generate OpenGraph files
    opengraph_file = generate_opengraph_files(
        output_dir=opengraph_output_dir,
        tasks=all_rows,
        bh_connector=bh_connector,
        ldap_config=ldap_config,
        allow_orphans=getattr(args, "bh_allow_orphans", False),
        computer_sids=computer_sids if computer_sids else None,
        netbios_name=netbios_name,
    )

    # Upload to BloodHound if not disabled and we have credentials
    _upload_opengraph(bh_config, opengraph_file, opengraph_json_path)


def _upload_opengraph(bh_config: Any, opengraph_file: Optional[str], json_data_path: Optional[str] = None) -> None:
    """Upload OpenGraph data to BloodHound if configured."""
    import json

    # Read graph stats first
    node_count = 0
    edge_count = 0
    if opengraph_file:
        try:
            with open(opengraph_file) as f:
                graph_data = json.load(f)
            inner_graph = graph_data.get("graph", graph_data)
            node_count = len(inner_graph.get("nodes", []))
            edge_count = len(inner_graph.get("edges", []))
        except (OSError, json.JSONDecodeError):
            pass

    # Handle no-upload case
    if bh_config.bh_no_upload:
        print_opengraph_section(
            json_path=json_data_path or opengraph_file or "",
            uploaded=False,
            node_count=node_count,
            edge_count=edge_count,
        )
        return

    if not bh_config.has_credentials():
        warn("No BloodHound credentials available - skipping upload")
        print_opengraph_section(
            json_path=json_data_path or opengraph_file or "",
            uploaded=False,
            node_count=node_count,
            edge_count=edge_count,
        )
        return

    if not opengraph_file:
        warn("No OpenGraph file generated - skipping upload")
        return

    if node_count == 0 and edge_count == 0:
        info("Skipping BloodHound upload - no data (0 nodes, 0 edges)")
        print_opengraph_section(
            json_path=json_data_path or opengraph_file or "",
            uploaded=False,
            node_count=0,
            edge_count=0,
        )
        return

    success = upload_opengraph_to_bloodhound(
        opengraph_file=opengraph_file,
        bloodhound_url=bh_config.bh_connector,
        username=bh_config.bh_username,
        password=bh_config.bh_password,
        api_key=bh_config.bh_api_key,
        api_key_id=bh_config.bh_api_key_id,
        set_icon=True,
        force_icon=bh_config.bh_force_icon,
        icon_name=bh_config.bh_icon,
        icon_color=bh_config.bh_color,
    )

    print_opengraph_section(
        json_path=json_data_path or opengraph_file or "",
        uploaded=success,
        node_count=node_count,
        edge_count=edge_count,
    )

    if not success:
        warn("OpenGraph upload failed - files are still saved locally")
        warn("You can upload manually via BloodHound UI")


def _handle_exports(
    args: Any,
    all_rows: List[Dict],
    hv_loaded: bool,
    laps_cache: Optional[LAPSCache],
    laps_successes: int,
    laps_failures: List[LAPSFailure],
) -> tuple:
    """Handle all export formats and summary output.

    Returns:
        Tuple of (opengraph_json_path, opengraph_json_overwrites) for OpenGraph handling.
    """
    output_dir = args.output_dir
    output_formats = args.output_formats

    # Track if we need to auto-generate JSON for OpenGraph
    opengraph_json_path = None
    opengraph_json_overwrites = False

    # Handle OpenGraph JSON (goes to same output_dir/opengraph/ as other OpenGraph files)
    if args.bh_opengraph:
        opengraph_dir = os.path.join(output_dir, "opengraph")
        os.makedirs(opengraph_dir, exist_ok=True)
        opengraph_json_path = os.path.join(opengraph_dir, "taskhound_data.json")
        opengraph_json_overwrites = os.path.exists(opengraph_json_path)
        # Write OpenGraph JSON separately
        if all_rows:
            write_json(opengraph_json_path, all_rows, silent=True)

    # Write outputs based on --output formats
    if all_rows:
        # Plain text output
        if "plain" in output_formats:
            plain_dir = os.path.join(output_dir, "plain")
            write_rich_plain(plain_dir, all_rows)

        # JSON output
        if "json" in output_formats:
            json_dir = os.path.join(output_dir, "json")
            os.makedirs(json_dir, exist_ok=True)
            json_path = os.path.join(json_dir, "taskhound_results.json")
            write_json(json_path, all_rows)

        # CSV output
        if "csv" in output_formats:
            csv_dir = os.path.join(output_dir, "csv")
            os.makedirs(csv_dir, exist_ok=True)
            csv_path = os.path.join(csv_dir, "taskhound_results.csv")
            write_csv(csv_path, all_rows)

        # HTML report output
        if "html" in output_formats:
            from .output.html_report import generate_html_report
            html_dir = os.path.join(output_dir, "html")
            os.makedirs(html_dir, exist_ok=True)
            html_path = os.path.join(html_dir, "taskhound_report.html")
            generate_html_report(all_rows, html_path)
            print_audit_report_section(html_path)

    # Print decrypted credentials summary
    print_decrypted_credentials(all_rows)

    # Print summary table
    if not args.no_summary:
        has_tier0_detection = hv_loaded or args.ldap_tier0
        print_summary_table(all_rows, has_tier0_detection=has_tier0_detection)

        if laps_cache is not None:
            print_laps_summary(laps_cache, laps_successes, laps_failures)

    # Print backup section (if backup was enabled and we have backups)
    if args.backup:
        backup_dir = os.path.join(output_dir, "raw_backups")
        if os.path.exists(backup_dir):
            print_backup_section(backup_dir)

    return opengraph_json_path, opengraph_json_overwrites


def _auto_discover_targets(args: Any, bh_config: Any) -> List[str]:
    """
    Auto-discover computer targets from BloodHound or LDAP.

    Tries BloodHound first (if configured), falls back to LDAP.
    Applies filtering based on:
    - Disabled accounts (excluded by default, --include-disabled to include)
    - Stale accounts (--stale-threshold days, default 60, 0 to disable)
    - Domain Controllers (excluded by default, --include-dcs to include)
    - Custom filters (--ldap-filter with presets or raw LDAP)

    Args:
        args: Parsed CLI arguments
        bh_config: BloodHound configuration

    Returns:
        List of computer hostnames (FQDNs)
    """

    include_dcs = getattr(args, "include_dcs", False)
    include_disabled = getattr(args, "include_disabled", False)
    stale_threshold = getattr(args, "stale_threshold", 60)
    ldap_filter = getattr(args, "ldap_filter", None)

    # Resolve filter presets
    ldap_filter_raw = None
    filter_preset = None
    if ldap_filter:
        preset_lower = ldap_filter.lower().strip()
        if preset_lower == "servers":
            filter_preset = "servers"
            ldap_filter_raw = "(operatingSystem=*Server*)"
        elif preset_lower == "workstations":
            filter_preset = "workstations"
            ldap_filter_raw = "(!(operatingSystem=*Server*))"
        elif ldap_filter.startswith("("):
            # Raw LDAP filter
            ldap_filter_raw = ldap_filter
        else:
            warn(f"Unknown filter preset '{ldap_filter}'. Use 'servers', 'workstations', or raw LDAP '(...)'")
            sys.exit(1)

    # Build status message
    filter_parts = []
    if not include_disabled:
        filter_parts.append("enabled only")
    if stale_threshold > 0:
        filter_parts.append(f"active <{stale_threshold}d")
    if not include_dcs:
        filter_parts.append("excluding DCs")
    if filter_preset:
        filter_parts.append(filter_preset)
    elif ldap_filter_raw:
        filter_parts.append("custom filter")

    filter_msg = f" ({', '.join(filter_parts)})" if filter_parts else ""

    # Try BloodHound first
    computers = []
    source = None

    if bh_config and bh_config.has_credentials():
        try:
            computers, source = _enumerate_from_bloodhound(
                bh_config=bh_config,
                include_dcs=include_dcs,
                include_disabled=include_disabled,
                stale_threshold=stale_threshold,
                filter_preset=filter_preset,
                ldap_filter_raw=ldap_filter_raw,
            )
        except Exception as e:
            debug(f"BloodHound enumeration failed: {e}")
            warn(f"BloodHound query failed ({e}), falling back to LDAP")

    # Fall back to LDAP if BloodHound didn't work
    if not computers and not source:
        try:
            computers, source = _enumerate_from_ldap(
                args=args,
                include_dcs=include_dcs,
                include_disabled=include_disabled,
                stale_threshold=stale_threshold,
                ldap_filter_raw=ldap_filter_raw,
            )
        except Exception as e:
            print(f"[!] Auto-targets failed: {e}")
            sys.exit(1)

    if computers:
        status(f"[Auto-targets] {len(computers)} computers from {source}{filter_msg}")
        good(f"Auto-targets: Found {len(computers)} computer objects")
    else:
        warn("Auto-targets: No computers found matching criteria")

    return computers


def _enumerate_from_bloodhound(
    bh_config: Any,
    include_dcs: bool,
    include_disabled: bool,
    stale_threshold: int,
    filter_preset: Optional[str],
    ldap_filter_raw: Optional[str],
) -> tuple[List[str], Optional[str]]:
    """
    Enumerate computers from BloodHound CE.

    Returns:
        Tuple of (list of hostnames, source string) or ([], None) on failure
    """
    import time

    from .output.bloodhound import normalize_bloodhound_connector
    from .utils.bh_api import (
        enumerate_computers_from_bloodhound,
        get_bloodhound_data_age,
        get_bloodhound_token,
    )

    # Get base URL
    base_url = normalize_bloodhound_connector(bh_config.bh_connector, is_legacy=False)

    # Authenticate
    info("Auto-targets: Querying BloodHound CE...")
    start = time.time()

    token = get_bloodhound_token(
        base_url=base_url,
        username=bh_config.bh_username,
        password=bh_config.bh_password,
    )

    # Get all computers with properties
    all_computers = enumerate_computers_from_bloodhound(base_url=base_url, token=token)
    elapsed = time.time() - start
    debug(f"BloodHound query returned {len(all_computers)} computers in {elapsed:.2f}s")

    if not all_computers:
        return [], None

    # Check data age and warn if stale
    data_age_days, newest_ts = get_bloodhound_data_age(all_computers)
    if data_age_days > 30:
        warn(f"BloodHound data is {data_age_days} days old! Consider re-running SharpHound.")
    elif data_age_days > 7:
        info(f"BloodHound data is {data_age_days} days old", verbose_only=True)

    # Apply filters
    filtered = []
    stats = {"total": len(all_computers), "disabled": 0, "stale": 0, "dc": 0, "os_filter": 0}
    now_ts = int(time.time())

    for comp in all_computers:
        name = comp.get("name", "")
        if not name:
            continue

        # Filter disabled accounts
        if not include_disabled and comp.get("enabled") is False:
            stats["disabled"] += 1
            continue

        # Filter stale accounts (pwdlastset older than threshold)
        if stale_threshold > 0:
            pwd_last_set = comp.get("pwdlastset")
            if pwd_last_set:
                age_days = (now_ts - pwd_last_set) / 86400
                if age_days > stale_threshold:
                    stats["stale"] += 1
                    continue

        # Filter DCs (check for SERVER_TRUST_ACCOUNT bit or OU=Domain Controllers)
        if not include_dcs:
            dn = comp.get("distinguishedname", "").lower()
            if "ou=domain controllers" in dn:
                stats["dc"] += 1
                continue

        # Apply OS filter preset
        if filter_preset:
            os_name = (comp.get("operatingsystem") or "").upper()
            if filter_preset == "servers" and "SERVER" not in os_name or filter_preset == "workstations" and "SERVER" in os_name:
                stats["os_filter"] += 1
                continue

        # Raw LDAP filter can't be applied to BH data directly
        # If user specified raw filter and we're using BH, warn them
        if ldap_filter_raw and not filter_preset:
            # First computer - warn once
            if not filtered:
                warn("Raw LDAP filter requires LDAP source; use presets with BloodHound")
            return [], None  # Force LDAP fallback

        filtered.append(name)

    debug(
        f"BloodHound filter stats: {stats['total']} total, "
        f"{stats['disabled']} disabled, {stats['stale']} stale, "
        f"{stats['dc']} DCs, {stats['os_filter']} OS filtered"
    )

    return filtered, "BloodHound"


def _enumerate_from_ldap(
    args: Any,
    include_dcs: bool,
    include_disabled: bool,
    stale_threshold: int,
    ldap_filter_raw: Optional[str],
) -> tuple[List[str], Optional[str]]:
    """
    Enumerate computers from LDAP with filtering.

    Uses LDAP-specific credentials if provided, otherwise falls back to main auth.

    Returns:
        Tuple of (list of hostnames, source string)
    """
    from .utils.ldap import enumerate_domain_computers_filtered

    info("Auto-targets: Querying LDAP...")

    kerberos_enabled = args.kerberos or getattr(args, "aes_key", None) is not None

    # Use LDAP-specific credentials if provided, otherwise fall back to main auth
    effective_domain = args.ldap_domain if args.ldap_domain else args.domain
    effective_user = args.ldap_user if args.ldap_user else args.username
    effective_password = args.ldap_password if args.ldap_password else args.password
    effective_hashes = args.ldap_hashes if args.ldap_hashes else args.hashes

    computers = enumerate_domain_computers_filtered(
        dc_ip=args.dc_ip,
        domain=effective_domain,
        username=effective_user,
        password=effective_password,
        hashes=effective_hashes,
        kerberos=kerberos_enabled,
        aes_key=getattr(args, "aes_key", None),
        ldap_filter=ldap_filter_raw,
        use_tcp=getattr(args, "dns_tcp", False),
        include_dcs=include_dcs,
        include_disabled=include_disabled,
        stale_threshold=stale_threshold,
    )

    return computers, "LDAP"


def main():
    print_banner()
    ap = build_parser()
    args = ap.parse_args()

    # Set verbosity early
    set_verbosity(args.verbose, args.debug)

    validate_args(args)

    # Adult check for noisy operations (Credential Guard detection)
    if args.credguard_detect and not getattr(args, 'no_confirm', False):
        warning_text = """[bold yellow]WARNING: Credential Guard detection is enabled (default)[/]

This operation involves:
  [dim]•[/] Starting/stopping the [cyan]RemoteRegistry[/] service on targets
  [dim]•[/] Reading registry keys via RPC ([cyan]\\pipe\\winreg[/])

[bold red]This is NOISY(!) and may trigger EDR/SOC alerts![/]

[dim]To disable this check:[/]
  [green]--no-credguard[/]  Skip Credential Guard detection
  [green]--opsec[/]         Disable all noisy operations

[dim]To skip this prompt in the future:[/]
  [green]--no-confirm[/]    Accept warnings automatically"""

        console.print(Panel(warning_text, title="[bold yellow]⚠ OPSEC Warning[/]", border_style="yellow"))
        console.print()
        try:
            if not Confirm.ask("[yellow]Are you an adult?[/]", default=False):
                console.print("[blue][*][/] Aborted. Re-run with --no-credguard or --opsec for stealth mode.")
                sys.exit(0)
            console.print()  # Blank line after confirmation
        except (KeyboardInterrupt, EOFError):
            console.print("\n[blue][*][/] Aborted.")
            sys.exit(0)

    # Initialize Cache
    cache_file = Path(args.cache_file) if args.cache_file else None
    cache = init_cache(ttl_hours=args.cache_ttl / 3600, enabled=not args.no_cache, cache_file=cache_file)
    if args.clear_cache:
        cache.invalidate()
        info("Cache cleared")

    # Load HighValue data - either from file or live BloodHound connection
    hv = None
    hv_loaded = False

    # Try BloodHound live connection first
    bh_connector = None
    if args.bh_live:
        try:
            from .connectors import connect_bloodhound

            users_data, bh_connector = connect_bloodhound(args)
            if users_data:
                # Create a temporary HighValueLoader with the live data
                hv = HighValueLoader("")  # Empty path since we have live data

                # Convert timestamps to datetime objects (like HighValueLoader.load() does)
                for _, user_data in users_data.items():
                    if "pwdlastset" in user_data:
                        user_data["pwdlastset"] = parse_timestamp(user_data["pwdlastset"])
                    if "lastlogon" in user_data:
                        user_data["lastlogon"] = parse_timestamp(user_data["lastlogon"])

                hv.hv_users = users_data
                hv.hv_sids = {}

                # Build SID lookup from users data
                for sam, user_data in users_data.items():
                    if "sid" in user_data and user_data["sid"]:
                        hv.hv_sids[user_data["sid"].upper()] = user_data
                        hv.hv_sids[user_data["sid"].upper()]["sam"] = sam

                # Also load computer SIDs from BHCE for pre-fetch optimization
                if bh_connector and hasattr(bh_connector, "get_all_computers"):
                    hv.hv_computers = bh_connector.get_all_computers()
                    if hv.hv_computers:
                        debug(f"Loaded {len(hv.hv_computers)} computer SIDs from BHCE")

                # Load domain SIDs for unknown domain SID detection
                # BloodHound now provides TrustInfo with trust type from edges:
                # - SameForestTrust = intra-forest (GC works)
                # - CrossForestTrust = external (skip GC, use FQDN)
                if bh_connector and hasattr(bh_connector, "query_all_domain_sids"):
                    hv.hv_domain_sids = bh_connector.query_all_domain_sids()
                    # Logging is done inside query_all_domain_sids()

                hv.loaded = True
                hv.format_type = "bloodhound_live"
                hv_loaded = True
                len(hv.hv_computers) if hv.hv_computers else 0
                good(f"Live BloodHound data loaded ({len(users_data)} users)")

                # Test LDAP SID resolution capability
                verify_ldap_connection(
                    args.domain,
                    args.dc_ip,
                    args.username,
                    args.password,
                    args.hashes,
                    args.kerberos,
                    args.no_ldap,
                    args.ldap_domain,
                    args.ldap_user,
                    args.ldap_password,
                    args.ldap_hashes,
                    hv,
                )
            # No else clause needed - connector already prints specific error messages

        except ImportError as e:
            warn(f"BloodHound connector not available: {e}")
            warn("Continuing without high-value data")

    # Fall back to file-based loading if no live connection
    elif args.bh_data:
        hv = HighValueLoader(args.bh_data)
        if hv.load():
            good("High Value target data loaded from file")
            hv_loaded = True
        else:
            warn("Failed to load High Value target data from file")

    # Fetch domain SIDs via LDAP ONLY if BloodHound didn't provide them
    # BloodHound is preferred because it has trust edge data (SameForestTrust/CrossForestTrust)
    # LDAP is the fallback when no BloodHound connection is available
    has_bh_domain_sids = hv is not None and hv.hv_domain_sids
    if not has_bh_domain_sids and not args.no_ldap and args.domain and args.username:
        from .resolver import fetch_known_domain_sids_via_ldap

        ldap_domain = args.ldap_domain if args.ldap_domain else args.domain
        ldap_user = args.ldap_user if args.ldap_user else args.username
        ldap_pass = args.ldap_password if args.ldap_password else args.password
        ldap_hashes = args.ldap_hashes if args.ldap_hashes else args.hashes

        domain_sids = fetch_known_domain_sids_via_ldap(
            domain=ldap_domain,
            dc_ip=args.dc_ip,
            username=ldap_user,
            password=ldap_pass,
            hashes=ldap_hashes,
            kerberos=args.kerberos,
        )
        if domain_sids:
            if hv is None:
                # Create empty HV loader just to hold domain SIDs
                hv = HighValueLoader("")
                hv.loaded = True
            # LDAP data has TrustInfo with is_intra_forest from trustAttributes
            hv.hv_domain_sids = domain_sids
            intra_count = sum(1 for t in domain_sids.values() if hasattr(t, 'is_intra_forest') and t.is_intra_forest)
            external_count = len(domain_sids) - intra_count
            good(f"Loaded {len(domain_sids)} domain SID prefixes via LDAP ({intra_count} intra-forest, {external_count} external)")

    # Store LDAP credentials for lazy NETBIOS resolution (used when NETBIOS\user format encountered)
    # This enables resolving trusted domain NETBIOS names (e.g., TRUSTEDDOM\user → TRUSTEDDOM.LOCAL\user)
    if not args.no_ldap and args.domain and args.username:
        from .resolver import set_netbios_ldap_credentials

        ldap_domain = args.ldap_domain if args.ldap_domain else args.domain
        ldap_user = args.ldap_user if args.ldap_user else args.username
        ldap_pass = args.ldap_password if args.ldap_password else args.password
        ldap_hashes = args.ldap_hashes if args.ldap_hashes else args.hashes

        set_netbios_ldap_credentials(
            domain=ldap_domain,
            dc_ip=args.dc_ip,
            username=ldap_user,
            password=ldap_pass,
            hashes=ldap_hashes,
            kerberos=args.kerberos,
        )

    # Initialize LAPS if requested (online mode only)
    laps_cache: Optional[LAPSCache] = None
    laps_failures: List[LAPSFailure] = []
    laps_successes: int = 0

    if getattr(args, "laps", False) and not args.offline:
        info("LAPS mode enabled - querying Active Directory for LAPS passwords...")
        try:
            # Use LDAP-specific credentials if provided, otherwise fall back to main auth
            laps_domain = args.ldap_domain if args.ldap_domain else args.domain
            laps_user = args.ldap_user if args.ldap_user else args.username
            laps_password = args.ldap_password if args.ldap_password else args.password
            laps_hashes = args.ldap_hashes if args.ldap_hashes else args.hashes

            laps_cache = get_laps_passwords(
                dc_ip=args.dc_ip,
                domain=laps_domain,
                username=laps_user,
                password=laps_password,
                hashes=laps_hashes,
                kerberos=args.kerberos,
                laps_user_override=getattr(args, "laps_user", None),
                use_cache=not args.no_cache,
            )
            stats = laps_cache.get_statistics()
            good(f"LAPS: Loaded {stats['usable']} usable passwords ({stats['mslaps']} Windows LAPS, {stats['legacy']} Legacy LAPS)")
            if stats["encrypted"] > 0:
                warn(f"LAPS: {stats['encrypted']} encrypted passwords failed to decrypt (check MS-GKDI access)")
        except LAPSConnectionError as e:
            print(f"[!] LAPS initialization failed: {e}")
            print("[!] Cannot continue with LAPS mode - check your credentials and DC connectivity")
            sys.exit(1)
        except LAPSEmptyCacheError as e:
            print(f"[!] {e}")
            print("[!] No LAPS passwords found - your account may lack read permissions")
            print("[!] Required permissions: 'Read ms-Mcs-AdmPwd' or 'Read msLAPS-Password' on computer objects")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Unexpected LAPS error: {e}")
            if args.debug:
                import traceback
                traceback.print_exc()
            sys.exit(1)

    # Process based on mode
    all_rows: List[Dict] = []

    if getattr(args, "offline_disk", None):
        # Offline disk mode: extract from mounted Windows filesystem, then process
        from .engine.disk_loader import extract_dpapi_key_from_registry, find_windows_root, load_from_disk

        # Compute backup directory path (if backup enabled)
        disk_backup_dir = os.path.join(args.output_dir, "raw_backups") if args.backup else None

        hostname, backup_path = load_from_disk(
            mount_path=args.offline_disk,
            backup_dir=disk_backup_dir,
            hostname=getattr(args, "disk_hostname", None),
            no_backup=args.no_backup,
            verbose=args.verbose,
            debug=args.debug,
        )

        if hostname is None or backup_path is None:
            print("[!] Failed to extract data from mounted disk")
            sys.exit(1)

        # Auto-extract DPAPI key from registry if not provided
        dpapi_key = args.dpapi_key
        if not dpapi_key:
            windows_root = find_windows_root(args.offline_disk)
            if windows_root:
                print("[*] No --dpapi-key provided, attempting to extract from registry hives...")
                dpapi_key = extract_dpapi_key_from_registry(windows_root, args.debug)
                if dpapi_key:
                    print(f"[+] Auto-extracted DPAPI key: {dpapi_key[:20]}...")
                else:
                    print("[!] Could not extract DPAPI key from registry")
                    print("[!] DPAPI decryption will be skipped. Provide --dpapi-key manually if needed.")

        # Now process the extracted backup as offline directory
        lines = process_offline_directory(
            offline_dir=backup_path,
            hv=hv,
            show_unsaved_creds=args.unsaved_creds,
            include_local=args.include_local,
            all_rows=all_rows,
            debug=args.debug,
            no_ldap=args.no_ldap,
            dpapi_key=dpapi_key,
            concise=not args.verbose,
        )

    elif args.offline:
        # Offline mode: process XML files from directory
        lines = process_offline_directory(
            offline_dir=args.offline,
            hv=hv,
            show_unsaved_creds=args.unsaved_creds,
            include_local=args.include_local,
            all_rows=all_rows,
            debug=args.debug,
            no_ldap=args.no_ldap,
            dpapi_key=args.dpapi_key,
            concise=not args.verbose,
        )
    else:
        # Online mode: process targets via SMB
        from .config_model import BloodHoundConfig

        bh_config = BloodHoundConfig.from_args_and_config(args)

        # Build targets list
        targets = []

        # Auto-discover targets if requested
        if getattr(args, "auto_targets", False):
            targets.extend(_auto_discover_targets(args, bh_config))

        # Add explicit targets from CLI
        if args.target:
            # Support comma-separated targets: -t 192.168.1.1,192.168.1.2,192.168.1.3
            for t in args.target.split(","):
                t = t.strip()
                if t:
                    targets.append(t)
        if args.targets_file:
            with open(args.targets_file, encoding="utf-8") as f:
                targets.extend([line.strip() for line in f if line.strip()])

        # Normalize (append domain for short names; leave IPs as-is)
        targets = normalize_targets(targets, args.domain)

        # Pre-fetch computer SIDs from BloodHound data (if available) before scan starts
        # This populates the cache so workers don't each need to make LDAP calls
        if targets and (hv or args.domain):
            from .resolver import prefetch_computer_sids

            prefetch_computer_sids(
                targets=targets,
                domain=args.domain,
                hv_loader=hv,
                dc_ip=args.dc_ip,
                username=args.username,
                password=args.password,
                hashes=args.hashes,
                kerberos=args.kerberos,
                ldap_domain=args.ldap_domain,
                ldap_user=args.ldap_user,
                ldap_password=args.ldap_password,
                ldap_hashes=args.ldap_hashes,
            )

        # Build AuthContext from args
        # AES key implies Kerberos authentication
        kerberos_enabled = args.kerberos or getattr(args, "aes_key", None) is not None
        auth = AuthContext(
            username=args.username,
            password=args.password,
            domain=args.domain,
            hashes=args.hashes,
            aes_key=getattr(args, "aes_key", None),
            kerberos=kerberos_enabled,
            dc_ip=args.dc_ip,
            timeout=args.timeout,
            dns_tcp=getattr(args, "dns_tcp", False),
            nameserver=getattr(args, "nameserver", None),
            ldap_domain=args.ldap_domain,
            ldap_user=args.ldap_user,
            ldap_password=args.ldap_password,
            ldap_hashes=args.ldap_hashes,
            gc_server=getattr(args, "gc_server", None),
        )

        # Compute backup directory path for online scanning
        online_backup_dir = os.path.join(args.output_dir, "raw_backups") if args.backup else None

        # Common kwargs for process_target
        process_kwargs = {
            "auth": auth,
            "include_ms": args.include_ms,
            "include_local": args.include_local,
            "hv": hv,
            "debug": args.debug,
            "show_unsaved_creds": args.unsaved_creds,
            "backup_dir": online_backup_dir,
            "credguard_detect": args.credguard_detect,
            "no_ldap": args.no_ldap,
            "no_rpc": getattr(args, 'no_rpc', False),
            "loot": args.loot,
            "dpapi_key": args.dpapi_key,
            "bh_connector": bh_connector,
            "concise": not args.verbose,
            "opsec": args.opsec,
            "laps_cache": laps_cache,
            "validate_creds": args.validate_creds,
            "ldap_tier0": args.ldap_tier0,
        }

        # Parallel mode (--threads > 1) or sequential with jitter
        if args.threads > 1 or getattr(args, 'jitter', None):
            async_config = AsyncConfig(
                workers=args.threads,
                rate_limit=args.rate_limit,
                timeout=args.timeout,
                show_progress=True,
                jitter=getattr(args, 'jitter', None),
            )
            async_engine = AsyncTaskHound(async_config)

            start_time = time.perf_counter()
            results = async_engine.run(targets, process_target, **process_kwargs)
            _ = (time.perf_counter() - start_time) * 1000  # elapsed_ms for future use

            # Aggregate results
            all_rows, laps_failures, laps_successes = aggregate_results(results)

        else:
            # Sequential mode (default, --threads 1)
            for tgt in targets:
                lines, laps_result = process_target(
                    target=tgt,
                    all_rows=all_rows,
                    **process_kwargs,
                )
                # Track LAPS results
                if laps_result is not None:
                    if laps_result is True:
                        laps_successes += 1
                    elif isinstance(laps_result, LAPSFailure):
                        laps_failures.append(laps_result)

    # Handle exports and summary
    opengraph_json_path, opengraph_json_overwrites = _handle_exports(
        args, all_rows, hv_loaded, laps_cache, laps_successes, laps_failures
    )

    # BloodHound OpenGraph Integration
    if args.bh_opengraph:
        _handle_opengraph(args, all_rows, opengraph_json_path, opengraph_json_overwrites)
