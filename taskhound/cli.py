from typing import Dict, List, Optional

from .config import build_parser, validate_args
from .engine import process_offline_directory, process_target
from .output.printer import print_results
from .output.summary import print_summary_table
from .output.writer import write_csv, write_json, write_plain
from .parsers.highvalue import HighValueLoader
from .utils.helpers import BANNER, normalize_targets
from .utils.logging import good, info, warn


def _extract_domain_sid_from_hv(hv_loader):
    """Extract a domain SID from BloodHound high-value data for realistic LDAP testing."""
    if not hv_loader or not hv_loader.loaded:
        return None

    # Check hv_sids first (this is where BloodHound live data is stored)
    if hasattr(hv_loader, "hv_sids") and hv_loader.hv_sids:
        for sid, user_data in hv_loader.hv_sids.items():
            if sid and sid.startswith("S-1-5-21-"):
                # Extract domain part (everything except the RID)
                parts = sid.split("-")
                if len(parts) >= 7:  # S-1-5-21-xxx-xxx-xxx-yyy
                    domain_sid = "-".join(parts[:-1])  # Remove the RID
                    result_sid = f"{domain_sid}-500"  # Replace with Administrator RID
                    return result_sid

    # Fallback: check hv_users if available
    if hasattr(hv_loader, "hv_users") and hv_loader.hv_users:
        for sam, user_data in hv_loader.hv_users.items():
            if "objectid" in user_data or "sid" in user_data:
                sid = user_data.get("objectid") or user_data.get("sid")
                if sid and sid.startswith("S-1-5-21-"):
                    parts = sid.split("-")
                    if len(parts) >= 7:
                        domain_sid = "-".join(parts[:-1])
                        result_sid = f"{domain_sid}-500"
                        return result_sid

    # Legacy fallback: Try tier_zero_users and high_value_users (for file-based data)
    user_collections = []
    if hasattr(hv_loader, "tier_zero_users") and hv_loader.tier_zero_users:
        user_collections.append(hv_loader.tier_zero_users)
    if hasattr(hv_loader, "high_value_users") and hv_loader.high_value_users:
        user_collections.append(hv_loader.high_value_users)

    for users in user_collections:
        for sam, user_data in users.items():
            if "objectid" in user_data:
                sid = user_data["objectid"]
                if sid and sid.startswith("S-1-5-21-"):
                    # Extract domain part (everything except the RID)
                    parts = sid.split("-")
                    if len(parts) >= 7:  # S-1-5-21-xxx-xxx-xxx-yyy
                        domain_sid = "-".join(parts[:-1])  # Remove the RID
                        return f"{domain_sid}-500"  # Replace with Administrator RID

    return None


def _test_ldap_connection(domain: Optional[str], dc_ip: Optional[str], username: Optional[str],
                         password: Optional[str], hashes: Optional[str], kerberos: bool, no_ldap: bool,
                         ldap_domain: Optional[str] = None, ldap_user: Optional[str] = None,
                         ldap_password: Optional[str] = None, hv_loader=None):
    """Test LDAP connection and SID resolution capability during initialization."""
    if no_ldap:
        info("LDAP resolution disabled - skipping connection test")
        return

    # Determine which credentials to use for LDAP test
    # Priority: dedicated LDAP credentials > main auth credentials
    test_domain = ldap_domain if ldap_domain else domain
    test_username = ldap_user if ldap_user else username
    test_password = ldap_password if ldap_password else password

    # For LDAP SID resolution, we need plaintext password - skip if only hashes available
    if not test_password and hashes and not ldap_password:
        warn("LDAP test skipped - SID resolution requires plaintext password, but only hashes provided")
        warn("Consider using --ldap-user and --ldap-password for SID lookup with plaintext credentials")
        return

    if not test_domain or not test_username:
        warn(f"LDAP test skipped - missing credentials (domain={test_domain}, username={test_username})")
        return

    info("Testing LDAP connection and SID resolution...")

    # Show which credentials are being used for the test
    if ldap_user or ldap_domain:
        info(f"Using dedicated LDAP credentials: {test_username}@{test_domain}")
    else:
        info(f"Using main auth credentials for LDAP: {test_username}@{test_domain}")

    # Test with the well-known Administrator SID (RID 500) which should exist in most domains
    # Build the domain SID by taking the first 3 parts and appending -500
    test_sid = None

    # For testing purposes, we'll try to resolve a well-known SID
    # We use the local Administrator account SID pattern: S-1-5-21-<domain>-500
    # Since we don't know the exact domain SID, we'll use a fallback approach
    try:
        # Import the SID resolution function
        from .utils.sid_resolver import resolve_sid_via_ldap

        # Try to get a realistic test SID from BloodHound data first
        test_sid = _extract_domain_sid_from_hv(hv_loader)

        if not test_sid:
            info("No BloodHound data available - skipping SID resolution test")
            info("LDAP connectivity test completed (SID resolution will be tested during actual execution)")
            return
        else:
            info("Using domain SID derived from BloodHound data for realistic testing")

        info(f"Testing SID resolution with: {test_sid}")
        result = resolve_sid_via_ldap(test_sid, test_domain, dc_ip, test_username, test_password, None, kerberos)

        if result:
            good(f"LDAP test successful: {test_sid} -> {result}")
            good("SID resolution initialized and ready")
        else:
            # Check if the domain SID from BloodHound matches the target domain
            if test_sid:
                test_domain_sid = "-".join(test_sid.split("-")[:-1])  # Remove RID to get domain SID
                warn(f"LDAP test failed: Could not resolve {test_sid}")
                info("This may be normal if BloodHound data is from a different domain than the target")
                info(f"BloodHound domain SID: {test_domain_sid}")
                info("SID resolution will still work for actual SIDs from the target domain")
            else:
                warn(f"LDAP test failed: Could not resolve {test_sid}")
                warn("SID resolution may not work properly")

    except ImportError as e:
        warn(f"LDAP test failed: Missing dependencies - {e}")
    except Exception as e:
        warn(f"LDAP test failed: {e}")


def main():
    print(BANNER)
    ap = build_parser()
    args = ap.parse_args()

    validate_args(args)

    # Load HighValue data - either from file or live BloodHound connection
    hv = None
    hv_loaded = False

    # Try BloodHound live connection first
    if args.bh_live:
        try:
            from .connectors import connect_bloodhound

            users_data = connect_bloodhound(args)
            if users_data:
                # Create a temporary HighValueLoader with the live data
                hv = HighValueLoader("")  # Empty path since we have live data

                # Convert timestamps to datetime objects (like HighValueLoader.load() does)
                from .parsers.highvalue import _convert_timestamp
                for sam, user_data in users_data.items():
                    if 'pwdlastset' in user_data:
                        user_data['pwdlastset'] = _convert_timestamp(user_data['pwdlastset'])
                    if 'lastlogon' in user_data:
                        user_data['lastlogon'] = _convert_timestamp(user_data['lastlogon'])

                hv.hv_users = users_data
                hv.hv_sids = {}

                # Build SID lookup from users data
                for sam, user_data in users_data.items():
                    if 'sid' in user_data and user_data['sid']:
                        hv.hv_sids[user_data['sid'].upper()] = user_data
                        hv.hv_sids[user_data['sid'].upper()]['sam'] = sam

                hv.loaded = True
                hv.format_type = "bloodhound_live"
                hv_loaded = True
                good(f"Live BloodHound data loaded ({len(users_data)} users)")

                # Test LDAP SID resolution capability
                _test_ldap_connection(args.domain, args.dc_ip, args.username, args.password, args.hashes, args.kerberos, args.no_ldap,
                                    args.ldap_domain, args.ldap_user, args.ldap_password, hv)
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

    # Process based on mode
    all_rows: List[Dict] = []


    if args.offline:
        # Offline mode: process XML files from directory
        lines = process_offline_directory(
            offline_dir=args.offline,
            hv=hv,
            show_unsaved_creds=args.unsaved_creds,
            include_local=args.include_local,
            all_rows=all_rows,
            debug=args.debug,
            no_ldap=args.no_ldap,
            dpapi_key=args.dpapi_key
        )
        print_results(lines)
    else:
        # Online mode: process targets via SMB
        # Build targets list
        targets = []
        if args.target:
            targets.append(args.target)
        if args.targets_file:
            with open(args.targets_file, encoding="utf-8") as f:
                targets.extend([l.strip() for l in f if l.strip()])

        # Normalize (append domain for short names; leave IPs as-is)
        targets = normalize_targets(targets, args.domain)

        # Process each target
        for tgt in targets:
            lines = process_target(
                target=tgt,
                domain=args.domain,
                username=args.username,
                password=args.password,
                kerberos=args.kerberos,
                dc_ip=args.dc_ip,
                include_ms=args.include_ms,
                include_local=args.include_local,
                hv=hv,
                debug=args.debug,
                all_rows=all_rows,
                hashes=args.hashes,
                show_unsaved_creds=args.unsaved_creds,
                backup_dir=args.backup,
                credguard_detect=args.credguard_detect,
                no_ldap=args.no_ldap,
                ldap_domain=args.ldap_domain,
                ldap_user=args.ldap_user,
                ldap_password=args.ldap_password,
                loot=args.loot,
                dpapi_key=args.dpapi_key,
            )
            print_results(lines)
            if args.plain and lines:
                write_plain(args.plain, tgt, lines)

    # Exports
    if args.json:
        write_json(args.json, all_rows)
    if args.csv:
        write_csv(args.csv, all_rows)

    # Print summary by default (unless disabled)
    if not args.no_summary:
        backup_dir = args.backup if hasattr(args, 'backup') and args.backup else None
        print_summary_table(all_rows, backup_dir, hv_loaded)
