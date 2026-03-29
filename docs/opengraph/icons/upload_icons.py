#!/usr/bin/env python3
"""
Upload TaskHound custom node icons to BloodHound CE.

Uses the /api/v2/custom-nodes endpoint with Bearer token authentication.
Icons are Font Awesome solid icons (no custom SVG/PNG support in BH CE).

Usage:
    python upload_icons.py --url http://localhost:8080 --token YOUR_BEARER_TOKEN
    python upload_icons.py --url http://localhost:8080 --token YOUR_BEARER_TOKEN --dry-run
"""

import argparse
import json
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    print("Error: 'requests' library required. Install with: pip install requests", file=sys.stderr)
    sys.exit(1)

ICONS_FILE = Path(__file__).parent / "icons.json"


def load_icons() -> dict:
    """Load icon definitions from icons.json."""
    with open(ICONS_FILE) as f:
        return json.load(f)


def upload_icons(base_url: str, token: str, dry_run: bool = False) -> bool:
    """Upload custom node icons to BloodHound CE."""
    icons = load_icons()
    url = f"{base_url.rstrip('/')}/api/v2/custom-nodes"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    if dry_run:
        print(f"[DRY RUN] Would POST to {url}")
        print(f"[DRY RUN] Payload:\n{json.dumps(icons, indent=2)}")
        return True

    print(f"Uploading icon definitions to {url}")

    try:
        resp = requests.post(url, json=icons, headers=headers, timeout=30)
    except requests.ConnectionError:
        print(f"Error: Could not connect to {base_url}", file=sys.stderr)
        return False
    except requests.Timeout:
        print(f"Error: Request timed out after 30s", file=sys.stderr)
        return False

    if resp.status_code == 201:
        print("Success: Custom node icons configured.")
        for kind, config in icons["custom_types"].items():
            icon = config["icon"]
            print(f"  {kind}: {icon['name']} ({icon['color']})")
        return True
    else:
        print(f"Error: HTTP {resp.status_code}", file=sys.stderr)
        print(f"Response: {resp.text}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Upload TaskHound custom node icons to BloodHound CE"
    )
    parser.add_argument("--url", required=True, help="BloodHound CE base URL (e.g., http://localhost:8080)")
    parser.add_argument("--token", required=True, help="Bearer token for authentication")
    parser.add_argument("--dry-run", action="store_true", help="Print payload without uploading")
    args = parser.parse_args()

    success = upload_icons(args.url, args.token, args.dry_run)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
