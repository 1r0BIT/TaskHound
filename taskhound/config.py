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
    
    # BloodHound live connection options
    bh_group = ap.add_argument_group('BloodHound Live Connection')
    bh_group.add_argument("--bh-live", action="store_true", 
                         help="Use live BloodHound connection (parameters can be provided via CLI or bh_connector.config file)")
    bh_group.add_argument("--bh-user", help="BloodHound username (or set in config file)")
    bh_group.add_argument("--bh-password", help="BloodHound password (or set in config file)")
    bh_group.add_argument("--bh-ip", default="127.0.0.1", help="BloodHound IP address (default: 127.0.0.1, or set in config file)")
    
    # BloodHound type selection (mutually exclusive)
    bh_type = bh_group.add_mutually_exclusive_group()
    bh_type.add_argument("--bhce", action="store_true", help="Use BloodHound Community Edition (or set type=bhce in config)")
    bh_type.add_argument("--legacy", action="store_true", help="Use Legacy BloodHound (or set type=legacy in config)")
    
    bh_group.add_argument("--bh-save", help="Save BloodHound query results to file (or set save_file in config)")
    
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
    
    # Validate BloodHound live connection parameters
    if args.bh_live:
        # Check if all parameters are provided via command line
        has_user = args.bh_user is not None
        has_password = args.bh_password is not None
        has_type = args.bhce or args.legacy
        
        # If not all parameters provided, try to load from config file
        if not (has_user and has_password and has_type):
            try:
                config_data = load_bloodhound_config()
                if config_data:
                    # Fill in missing parameters from config
                    if not has_user and 'username' in config_data:
                        args.bh_user = config_data['username']
                        has_user = True
                    
                    if not has_password and 'password' in config_data:
                        args.bh_password = config_data['password']
                        has_password = True
                    
                    if not has_type and 'type' in config_data:
                        bh_type = config_data['type'].lower()
                        if bh_type == 'bhce':
                            args.bhce = True
                            has_type = True
                        elif bh_type == 'legacy':
                            args.legacy = True
                            has_type = True
                    
                    # Set IP from config if not provided
                    if 'ip' in config_data and args.bh_ip == "127.0.0.1":  # Default value
                        args.bh_ip = config_data['ip']
                    
                    # Set save file from config if provided and not set via CLI
                    if 'save_file' in config_data and not args.bh_save:
                        args.bh_save = config_data['save_file']
                    
                    print(f"[+] Loaded BloodHound config: {args.bh_user}@{args.bh_ip} ({config_data.get('type', 'unknown')})")
                else:
                    print("[!] No bh_connector.config found and missing required parameters")
            except Exception as e:
                print(f"[!] Error loading BloodHound config: {e}")
        
        # Final validation - ensure all required parameters are now available
        if not has_user:
            print("[!] ERROR: --bh-user is required when using --bh-live")
            print("[!] Provide via command line or in bh_connector.config file")
            sys.exit(1)
        if not has_password:
            print("[!] ERROR: --bh-password is required when using --bh-live")
            print("[!] Provide via command line or in bh_connector.config file")
            sys.exit(1)
        if not has_type:
            print("[!] ERROR: Must specify either --bhce or --legacy when using --bh-live")
            print("[!] Provide via command line or set 'type' in bh_connector.config file")
            sys.exit(1)
        if args.bh_data:
            print("[!] ERROR: Cannot use both --bh-live and --bh-data simultaneously")
            print("[!] Choose either live connection OR file import")
            sys.exit(1)


def load_bloodhound_config():
    """Load BloodHound configuration from config file"""
    import configparser
    import os
    from pathlib import Path
    
    # Look for config file in current directory first, then user's home
    config_paths = [
        Path.cwd() / "bh_connector.config",
        Path.home() / ".taskhound" / "bh_connector.config",
        Path.home() / "bh_connector.config"
    ]
    
    for config_path in config_paths:
        if config_path.exists():
            try:
                config = configparser.ConfigParser()
                config.read(config_path)
                
                if 'BloodHound' in config:
                    bh_section = config['BloodHound']
                    config_data = {}
                    
                    # Extract configuration values
                    for key in ['ip', 'username', 'password', 'type', 'save_file']:
                        if key in bh_section:
                            value = bh_section[key].strip()
                            # Handle environment variable substitution
                            if value.startswith('${') and value.endswith('}'):
                                env_var = value[2:-1]
                                value = os.environ.get(env_var, value)
                            config_data[key] = value
                    
                    return config_data
                    
            except Exception as e:
                print(f"[!] Warning: Error parsing config file {config_path}: {e}")
                continue
    
    return None
    
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
