# Getting Started

So you want to find scheduled tasks running as Domain Admin with stored credentials that nobody remembers setting up. (There are always more than you think.)

TaskHound connects to Windows machines over SMB, pulls scheduled task XMLs, figures out which ones are running as someone important, and tells you about it. It's not going to win any design awards, but it finds things that matter.

## Installation

```bash
git clone https://github.com/1r0BIT/TaskHound.git
cd TaskHound
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt && pip install .
```

Requires Python 3.11+. If you're on an older version, I'm sorry but you'll need to upgrade. The f-strings alone demand it.

## Your First Scan

```bash
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local -t reactor01.shinra.local
```

Breaking that down:

| Flag | What it does |
|------|-------------|
| `-u cloud.strife` | Domain username |
| `-p 'Buster$word97!'` | Password (quote it, shells are vindictive) |
| `-d shinra.local` | Domain FQDN |
| `-t reactor01.shinra.local` | Target host to scan |

## What to Expect

TaskHound will connect over SMB, enumerate scheduled tasks, and classify each one:

- **TIER-0**: Tasks running as Domain Admins, Enterprise Admins, etc. The ones that make you wince.
- **PRIV**: High-value accounts per BloodHound or custom lists. Still bad.
- **TASK**: Normal accounts. Probably fine. Probably.

You'll get a summary table at the end showing task counts per host. Default output is plain text to stdout. For fancier formats, see [output-formats.md](output-formats.md).

## Multiple Targets

```bash
# From a file (one host per line)
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local --targets-file targets.txt --threads 10

# Auto-discover every domain computer (this will make any decent SOC light up like a Christmas tree)
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local --dc-ip 10.0.0.1 --auto-targets --threads 20
```

## Common First-Run Issues

**"Connection refused" / timeouts**: SMB (port 445) needs to be reachable. Check firewalls, check that the host is actually up. TaskHound can't help you if packets don't arrive.

**"Access denied"**: You need local admin on the target to read task XMLs from the `C$` share. A regular domain user won't cut it. This is where [LAPS integration](authentication.md#laps-integration) comes in handy for multi-host scans.

**DNS failures**: If hostnames aren't resolving, point TaskHound at a DC with `--dc-ip 10.0.0.1`. It uses that for DNS too. Or use `--nameserver` if your DNS server is different from the DC (it happens).

**"No tasks found"**: By default, TaskHound skips the `\Microsoft` folder (it's mostly noise). If you genuinely want everything, use `--include-all`, but fair warning: it's slow and mostly built-in Windows tasks.

## Authentication Methods

TaskHound supports password, NTLM hash, Kerberos, and AES key authentication. Because in a real engagement, you work with whatever credentials you've got.

See [authentication.md](authentication.md) for the full rundown.

## Next Steps

- [Authentication options](authentication.md) - pass-the-hash, Kerberos, LAPS
- [Configuration file](configuration.md) - stop typing the same flags every time
- [Output formats](output-formats.md) - JSON, CSV, HTML reports
