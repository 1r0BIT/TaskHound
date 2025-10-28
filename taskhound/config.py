import argparse
import os
import subprocess
import sys
import traceback

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
    bh_group.add_argument("--bh-connector", default="http://127.0.0.1:8080",
                         help="BloodHound connector URI (default: http://127.0.0.1:8080, or set in config file). "
                              "Examples: localhost, http://localhost:8080, https://bh.domain.com, bolt://neo4j.local:7687. "
                              "Supports both BHCE (http/https) and Legacy (bolt) protocols. "
                              "If no protocol specified: defaults to http:// for BHCE, bolt:// for Legacy.")

    # BloodHound type selection (mutually exclusive)
    bh_type = bh_group.add_mutually_exclusive_group()
    bh_type.add_argument("--bhce", action="store_true", help="Use BloodHound Community Edition (or set type=bhce in config)")
    bh_type.add_argument("--legacy", action="store_true", help="Use Legacy BloodHound (or set type=legacy in config)")

    bh_group.add_argument("--bh-save", help="Save BloodHound query results to file (or set save_file in config)")

    # BloodHound OpenGraph Integration (BHCE ONLY)
    bhog = ap.add_argument_group('BloodHound OpenGraph Integration',
                                 description='Automatically generate and optionally upload OpenGraph data to BloodHound CE (BHCE ONLY)')
    bhog.add_argument("--bh-opengraph", action="store_true",
                     help="Generate BloodHound OpenGraph JSON files (auto-enabled if bh_connector.config has valid BHCE credentials). "
                          "REQUIRES --bhce or type=bhce in config - NOT compatible with Legacy BloodHound!")
    bhog.add_argument("--bh-output", default="./opengraph",
                     help="Directory to save BloodHound OpenGraph files (default: ./opengraph)")
    bhog.add_argument("--bh-no-upload", action="store_true",
                     help="Generate OpenGraph files but skip automatic upload to BloodHound (files still saved)")
    bhog.add_argument("--bh-set-icon", action="store_true",
                     help="Automatically set custom icon for ScheduledTask nodes after upload")
    bhog.add_argument("--bh-force-icon", action="store_true",
                     help="Force icon update even if ScheduledTask icon already exists (requires --bh-set-icon)")
    bhog.add_argument("--bh-icon", default="heart",
                     help="Font Awesome icon name for ScheduledTask nodes (default: heart)")
    bhog.add_argument("--bh-color", default="#8B5CF6",
                     help="Hex color code for ScheduledTask node icon (default: #8B5CF6 - vibrant purple)")

    scan.add_argument("--include-ms", action="store_true",
                    help="Also include \\Microsoft scheduled tasks (WARNING: very slow)")
    scan.add_argument("--include-local", action="store_true",
                    help="Include tasks running as local system accounts (NT AUTHORITY\\SYSTEM, S-1-5-18, etc.)")
    scan.add_argument("--include-all", action="store_true",
                    help="Include ALL tasks (equivalent to --include-ms --include-local --unsaved-creds) - WARNING: VERY SLOW AND NOISY!")
    scan.add_argument("--unsaved-creds", action='store_true', help="Show scheduled tasks that do not store credentials (unsaved credentials)")
    scan.add_argument("--credguard-detect", action='store_true', default=False,
        help="EXPERIMENTAL: Attempt to detect Credential Guard status via remote registry (default: off). Only use if you know your environment supports it.")

    # DPAPI decryption options
    dpapi = ap.add_argument_group('DPAPI Credential Decryption')
    dpapi.add_argument("--loot", action='store_true', default=False,
        help="Automatically download and decrypt ALL Task Scheduler credential blobs (requires --dpapi-key)")
    dpapi.add_argument("--dpapi-key",
        help="DPAPI_SYSTEM userkey from LSA secrets dump (hex format, e.g., 0x51e43225e5b43b25d3768a2ae7f99934cb35d3ea)")

    # LDAP/SID Resolution options
    ldap = ap.add_argument_group('LDAP/SID Resolution options',
                                description='Alternative credentials for SID lookups. Useful when you only have NTLM hashes or local admin access (domain="."). SID resolution can use lower-privilege plaintext credentials.')
    ldap.add_argument("--no-ldap", action='store_true',
                    help="Disable LDAP queries for SID resolution (improves OPSEC but reduces user-friendliness)")
    ldap.add_argument("--ldap-user", help="Alternative username for SID lookup (can be different from main auth credentials)")
    ldap.add_argument("--ldap-password", help="Alternative password for SID lookup (plaintext only - hashes not supported)")
    ldap.add_argument("--ldap-domain", help="Alternative domain for SID lookup (can be different from main auth domain)")

    # Output options
    out = ap.add_argument_group('Output options')
    out.add_argument("--plain", help="Directory to save normal text output (per target)")
    out.add_argument("--json", help="Write all results to a JSON file")
    out.add_argument("--csv", help="Write all results to a CSV file")
    out.add_argument("--opengraph", help="Directory to save BloodHound OpenGraph JSON files")
    out.add_argument("--backup", help="Directory to save raw XML task files (per target)")
    out.add_argument("--no-summary", action="store_true", help="Disable summary table at the end of the run")

    # Misc
    misc = ap.add_argument_group('Misc')
    misc.add_argument("--debug", action="store_true", help="Enable debug output (print full stack traces)")
    return ap




def load_bloodhound_config():
    """
    Load BloodHound configuration from config file.
    
    Search order:
    1. TASKHOUND_CONFIG environment variable
    2. config/bh_connector.config (project config directory)
    3. ~/.config/taskhound/bh_connector.config (XDG standard - Linux/macOS)
    4. ~/.taskhound/bh_connector.config (legacy location)
    5. Current working directory (last resort with warning)
    """
    import configparser
    import os
    from pathlib import Path

    # 1. Check environment variable first (highest priority)
    if 'TASKHOUND_CONFIG' in os.environ:
        env_config_path = Path(os.environ['TASKHOUND_CONFIG'])
        if env_config_path.exists():
            config_paths = [env_config_path]
        else:
            print(f"[!] WARNING: TASKHOUND_CONFIG points to non-existent file: {env_config_path}")
            config_paths = []
    else:
        config_paths = []
    
    # 2-5. Standard search paths
    config_paths.extend([
        # 2. Project config directory
        Path.cwd() / "config" / "bh_connector.config",
        
        # 3. User config directory (XDG standard for Linux/macOS)
        Path.home() / ".config" / "taskhound" / "bh_connector.config",
        
        # 4. Legacy location
        Path.home() / ".taskhound" / "bh_connector.config",
        Path.home() / "bh_connector.config",
        
        # 5. Current directory (last resort)
        Path.cwd() / "bh_connector.config",
    ])

    for config_path in config_paths:
        if config_path.exists():
            # Warn if using current working directory (security concern)
            if config_path == Path.cwd() / "bh_connector.config":
                print("[!] WARNING: Using bh_connector.config from current directory")
                print("[!] This can be a security risk - consider moving to config/bh_connector.config")
            
            try:
                config = configparser.ConfigParser()
                config.read(config_path)

                if 'BloodHound' in config:
                    bh_section = config['BloodHound']
                    config_data = {}

                    # Extract configuration values
                    # Support both 'url' (new) and 'ip' (legacy) for backward compatibility
                    for key in ['url', 'ip', 'username', 'password', 'type', 'save_file']:
                        if key in bh_section:
                            value = bh_section[key].strip()
                            # Handle environment variable substitution
                            if value.startswith('${') and value.endswith('}'):
                                env_var = value[2:-1]
                                if env_var not in os.environ:
                                    raise ValueError(
                                        f"Config references undefined environment variable: {env_var}\n"
                                        f"Set it with: export {env_var}=<value>"
                                    )
                                value = os.environ[env_var]
                            config_data[key] = value
                    
                    # Convert legacy 'ip' to 'url' if 'url' not present
                    if 'ip' in config_data and 'url' not in config_data:
                        config_data['url'] = f"http://{config_data['ip']}:8080"
                        print(f"[*] Note: Using legacy 'ip' setting. Consider updating config to use 'url' instead.")

                    return config_data

            except ValueError as e:
                # Re-raise environment variable errors
                raise
            except Exception as e:
                print(f"[!] Warning: Error parsing config file {config_path}: {e}")
                continue

    return None


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

    # Handle BloodHound OpenGraph integration auto-detection
    config_data = load_bloodhound_config()
    
    # Auto-enable OpenGraph if config exists with BHCE credentials and user didn't explicitly disable
    if not args.bh_opengraph and config_data:
        bh_type = config_data.get('type', '').lower()
        has_username = 'username' in config_data
        has_password = 'password' in config_data
        
        if bh_type == 'bhce' and has_username and has_password:
            args.bh_opengraph = True
            # Store config data for later use
            args._bh_config_data = config_data
            print(f"[+] BloodHound OpenGraph auto-enabled (found BHCE config: {config_data['username']}@{config_data.get('ip', '127.0.0.1')})")
            if not args.bh_no_upload:
                print(f"[*] OpenGraph files will be automatically uploaded to BloodHound (use --bh-no-upload to disable)")
    
    # If --bh-opengraph is explicitly set (either by user or auto-enabled above), 
    # ensure we have config data for upload
    if args.bh_opengraph and not hasattr(args, '_bh_config_data') and config_data:
        # Store config data for upload even if not auto-enabled
        args._bh_config_data = config_data

    # Validate BloodHound live connection parameters
    if args.bh_live:
        # Check if all parameters are provided via command line
        has_user = args.bh_user is not None
        has_password = args.bh_password is not None
        has_type = args.bhce or args.legacy

        # If not all parameters provided, try to load from config file
        if not (has_user and has_password and has_type):
            try:
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

                    # Set connector URI from config if not provided or is default
                    if 'connector' in config_data:
                        # Config has connector URI, use it
                        if args.bh_connector == "http://127.0.0.1:8080":  # Default value
                            args.bh_connector = config_data['connector']
                    elif 'url' in config_data:
                        # Legacy config with url field, use it
                        if args.bh_connector == "http://127.0.0.1:8080":  # Default value
                            args.bh_connector = config_data['url']
                    elif 'ip' in config_data:
                        # Legacy config with IP, convert to connector
                        if args.bh_connector == "http://127.0.0.1:8080":  # Default value
                            args.bh_connector = f"http://{config_data['ip']}:8080"

                    # Set save file from config if provided and not set via CLI
                    if 'save_file' in config_data and not args.bh_save:
                        args.bh_save = config_data['save_file']

                    print(f"[+] Loaded BloodHound config: {args.bh_user}@{args.bh_connector} ({config_data.get('type', 'unknown')})")
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

    # Validate BloodHound OpenGraph compatibility - BHCE ONLY!
    if args.bh_opengraph:
        # Check if user is trying to use OpenGraph with Legacy BloodHound
        is_legacy = args.legacy
        
        # Also check config data if available
        if not is_legacy and config_data:
            is_legacy = config_data.get('type', '').lower() == 'legacy'
        
        if is_legacy:
            print("[!] ERROR: BloodHound OpenGraph is NOT compatible with Legacy BloodHound!")
            print("[!] OpenGraph requires BloodHound Community Edition (BHCE)")
            print("[!] Either:")
            print("[!]   - Remove --bh-opengraph flag to continue with Legacy BloodHound")
            print("[!]   - Switch to BHCE by using --bhce or setting type=bhce in config")
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

    # LDAP requires FQDN format - warn if domain appears to be NetBIOS
    if not args.no_ldap and not args.ldap_domain and '.' not in args.domain:
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
