import argparse, os, subprocess, sys, traceback
from .utils.logging import warn
from .utils.helpers import is_ipv4

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog='taskhound',
        description="TaskHound - Scheduled Task privilege checker with optional High Value enrichment"
    )
    # Authentication options
    auth = ap.add_argument_group('Authentication options')
    auth.add_argument("-u", "--username", help="Username (required for online mode)")
    auth.add_argument("-p", "--password", help="Password (omit with -k if using Kerberos/ccache)")
    auth.add_argument("-d", "--domain", help="Domain (required for online mode)")
    auth.add_argument("--hashes", help="NTLM hashes in LM:NT format (or NT-only 32-hex) to use instead of password")
    auth.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication (supports ccache)")
    
    # Target selection
    target = ap.add_argument_group('Target options')
    target.add_argument("-t", "--target", help="Single target")
    target.add_argument("--targets-file", help="File with targets, one per line")
    target.add_argument("--dc-ip", help="Domain controller IP (required when using Kerberos without DNS)")

    # High value / scanning options
    scan = ap.add_argument_group('Scanning options')
    scan.add_argument("--offline", help="Offline mode: parse previously collected XML files from directory (no authentication required)")
    scan.add_argument("--bh-data", help="Path to High Value Target export (csv/json from Neo4j)")
    scan.add_argument("--include-ms", action="store_true",
                    help="Also include \\Microsoft scheduled tasks (WARNING: very slow)")
    scan.add_argument("--include-local", action="store_true",
                    help="Include tasks running as local system accounts (NT AUTHORITY\\SYSTEM, S-1-5-18, etc.)")
    scan.add_argument("--include-all", action="store_true",
                    help="Include ALL tasks (equivalent to --include-ms --include-local --unsaved-creds) - WARNING: VERY SLOW AND NOISY!")
    scan.add_argument("--unsaved-creds", action='store_true', help="Show scheduled tasks that do not store credentials (unsaved credentials)")
    scan.add_argument("--no-ldap", action='store_true', 
                    help="Disable LDAP queries for SID resolution (improves OPSEC but reduces user-friendliness)")
    scan.add_argument("--credguard-detect", action='store_true', default=False,
        help="EXPERIMENTAL: Attempt to detect Credential Guard status via remote registry (default: off). Only use if you know your environment supports it.")
    
    # DPAPI decryption options
    dpapi = ap.add_argument_group('DPAPI Credential Decryption')
    dpapi.add_argument("--loot", action='store_true', default=False,
        help="Automatically download and decrypt ALL Task Scheduler credential blobs (requires --dpapi-key)")
    dpapi.add_argument("--dpapi-key", 
        help="DPAPI_SYSTEM userkey from LSA secrets dump (hex format, e.g., 0x51e43225e5b43b25d3768a2ae7f99934cb35d3ea)")

    # Output options
    out = ap.add_argument_group('Output options')
    out.add_argument("--plain", help="Directory to save normal text output (per target)")
    out.add_argument("--json", help="Write all results to a JSON file")
    out.add_argument("--csv", help="Write all results to a CSV file")
    out.add_argument("--backup", help="Directory to save raw XML task files (per target)")
    out.add_argument("--no-summary", action="store_true", help="Disable summary table at the end of the run")

    # Misc
    misc = ap.add_argument_group('Misc')
    misc.add_argument("--debug", action="store_true", help="Enable debug output (print full stack traces)")
    return ap

def validate_args(args):
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
    
    # Online mode validation - require authentication parameters
    if not args.username:
        print("[!] Username (-u/--username) is required for online mode")
        sys.exit(1)
    if not args.domain:
        print("[!] Domain (-d/--domain) is required for online mode")
        sys.exit(1)
    if not (args.target or args.targets_file):
        print("[!] Either --target or --targets-file is required for online mode")
        sys.exit(1)

    # KRB5 cache vs username mismatch
    if args.kerberos and "KRB5CCNAME" in os.environ:
        try:
            out = subprocess.check_output(["klist"], stderr=subprocess.DEVNULL, text=True)
            for line in out.splitlines():
                if "Default principal" in line:
                    cache_principal = line.split(":", 1)[1].strip()
                    cache_user = cache_principal.split("@")[0]
                    if cache_user.lower() != args.username.lower():
                        print(f"[!] Kerberos ticket cache user mismatch!")
                        print(f"    KRB5CCNAME contains tickets for: {cache_user}")
                        print(f"    But you supplied username     : {args.username}")
                        print("[!] Aborting. Please kdestroy your cache or use the matching user.")
                        sys.exit(1)
        except Exception:
            if args.debug:
                traceback.print_exc()

    # Kerberos + IP check for targets list
    if args.kerberos and args.targets_file:
        with open(args.targets_file) as f:
            for line in f:
                t = line.strip()
                if t and is_ipv4(t):
                    print("[!] Targets verification failed. Please supply hostnames or fqdns or switch to NTLM Auth (Kerberos doesn't like IP addresses)")
                    sys.exit(1)

    # Kerberos + IP for single target
    if args.kerberos and args.target and is_ipv4(args.target.strip()):
        print("[!] Targets verification failed. Please supply hostnames or fqdns or switch to NTLM Auth (Kerberos doesn't like IP addresses)")
        sys.exit(1)

    # DPAPI key with multiple targets validation
    if args.dpapi_key and args.targets_file and not args.offline:
        print("[!] ERROR: --dpapi-key cannot be used with --targets-file")
        print("[!] Each target has a unique DPAPI key - you cannot use the same key for multiple targets")
        print()
        print("[*] Valid workflows:")
        print("    1. Single target with key:  --target <host> --loot --dpapi-key <key>")
        print("    2. Collect from multiple:   --targets-file <file> --loot (without --dpapi-key)")
        print("       Then decrypt offline:    --offline dpapi_loot/<target> --dpapi-key <target_key>")
        sys.exit(1)
    
    # DPAPI loot validation for online mode
    if args.loot and not args.offline:
        # Online mode: --loot can work with or without --dpapi-key
        # With key: live decryption
        # Without key: offline collection
        if not args.dpapi_key:
            print("[*] --loot specified without --dpapi-key")
            print("[*] Will collect DPAPI files for offline decryption")
            print("[!] To decrypt immediately, obtain dpapi_userkey with: nxc smb <target> -u <user> -p <pass> --lsa")
            print()
    
    # DPAPI offline decryption validation
    if args.offline and args.dpapi_key:
        # Offline mode with DPAPI key: decrypt previously collected files
        print("[*] Offline mode with --dpapi-key enabled")
        print("[*] Will decrypt DPAPI files from offline directory")
        print()
