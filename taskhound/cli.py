import sys, traceback, json, csv
from typing import List, Dict
from .utils.helpers import BANNER, normalize_targets
from .utils.logging import good, warn
from .config import build_parser, validate_args
from .parsers.highvalue import HighValueLoader
from .output.printer import print_results
from .output.writer import write_plain, write_json, write_csv
from .output.summary import print_summary_table
from .engine import process_target, process_offline_directory

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
            no_ldap=args.no_ldap
        )
        print_results(lines)
    else:
        # Online mode: process targets via SMB
        # Build targets list
        targets = []
        if args.target:
            targets.append(args.target)
        if args.targets_file:
            with open(args.targets_file, "r", encoding="utf-8") as f:
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
