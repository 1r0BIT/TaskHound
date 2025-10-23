# Helpers for enumerating and reading scheduled task XMLs over SMB.
#
# This module traverses the C:\Windows\System32\Tasks directory on a
# remote host using Impacket's SMB APIs and returns a list of (path, data)
# pairs containing the task XML bytes. The implementation intentionally
# keeps errors non-fatal: unreadable files are logged and skipped so a
# single permission issue doesn't abort the entire crawl.

import io
from typing import List, Tuple

from impacket.smbconnection import SMBConnection

from ..utils.logging import warn

TASK_ROOT = r"\Windows\System32\Tasks"


def smb_listdir(smb: SMBConnection, share: str, path: str):
    # Return a list of (is_dir, name) entries for `share:path`.
    #
    # Uses Impacket's listPath and normalizes common '.'/'..' entries out.
    items = []
    for f in smb.listPath(share, path + "\\*"):
        name = f.get_longname()
        if name in (".", ".."):
            continue
        items.append((f.is_directory(), name))
    return items


def smb_readfile(smb: SMBConnection, share: str, path: str) -> bytes:
    # Read a file from SMB into memory and return bytes.
    #
    # The caller is expected to handle large files if needed. Scheduled
    # task XMLs are typically small, so an in-memory buffer is fine.
    buff = io.BytesIO()
    smb.getFile(share, path, buff.write)
    return buff.getvalue()


def crawl_tasks(smb: SMBConnection, include_ms: bool = False) -> List[Tuple[str, bytes]]:
    # Recursively crawl the scheduled tasks tree and collect XMLs.
    #
    # By default the large \Microsoft subtree is skipped for speed unless
    # `include_ms` is True.
    results: List[Tuple[str, bytes]] = []
    share = "C$"

    def recurse(cur: str):
        for is_dir, name in smb_listdir(smb, share, cur):
            # skip Microsoft subtree for speed unless explicitly asked
            if (not include_ms) and name.lower() == "microsoft" and cur.lower().endswith("windows\\system32\\tasks"):
                continue
            full = cur + "\\" + name
            if is_dir:
                recurse(full)
            else:
                try:
                    data = smb_readfile(smb, share, full)
                    # remove leading backslash for normalized relative path
                    rel = full[1:] if full.startswith("\\") else full
                    results.append((rel, data))
                except Exception as e:
                    # Non-fatal: log and continue
                    warn(f"Failed to read {full}: {e}")

    try:
        recurse(TASK_ROOT)
    except Exception as e:
        warn(f"Crawl error under {TASK_ROOT}: {e}")
    return results
