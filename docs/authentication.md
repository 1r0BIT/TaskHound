# Authentication

TaskHound needs credentials. Ideally ones that work. Here are all the ways to provide them.

## Password Authentication

The obvious one:

```bash
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local -t reactor01.shinra.local
```

Quote your password. Shells love to eat special characters and then you'll spend 20 minutes debugging an auth problem that isn't one.

## NTLM Hash (Pass-the-Hash)

When you have a hash but not a password. As one does.

```bash
taskhound -u cloud.strife --hashes aad3b435b51404eeaad3b435b51404ee:1fc552f8c075075c4e76aece1b9a2c58 \
  -d shinra.local -t reactor01.shinra.local
```

Accepts `LM:NT` format or just the 32-char NT hash by itself. The LM half is almost always `aad3b435b51404eeaad3b435b51404ee` these days (because LM hashes are disabled on anything modern), so either works.

## Kerberos Authentication

For when you want to avoid sending NTLM over the wire, or when the environment forces Kerberos.

```bash
# Step 1: Get a TGT (using impacket's getTGT.py)
getTGT.py shinra.local/cloud.strife:'Buster$word97!' -dc-ip 10.0.0.1

# Step 2: Use the ccache
export KRB5CCNAME=cloud.strife.ccache
taskhound -u cloud.strife -d shinra.local -t reactor01.shinra.local -k
```

The `-k` flag tells TaskHound to use Kerberos. It picks up the TGT from `KRB5CCNAME`. Make sure DNS is working or use `--dc-ip` — Kerberos is famously allergic to DNS problems.

If you already have a ccache from some other tool, just point `KRB5CCNAME` at it and go.

## AES Key Authentication

For the rare occasion you have an AES key (post-exploitation, DCSync, etc.):

```bash
# AES-256 (64 hex chars)
taskhound -u cloud.strife --aes-key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  -d shinra.local -t reactor01.shinra.local

# AES-128 (32 hex chars)
taskhound -u cloud.strife --aes-key 0123456789abcdef0123456789abcdef \
  -d shinra.local -t reactor01.shinra.local
```

This implicitly uses Kerberos under the hood.

## LAPS Integration

LAPS lets you use per-host local admin passwords that Active Directory manages. This is genuinely useful for multi-host scans — one set of domain creds retrieves a unique local admin password for each target.

### Basic Usage

```bash
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local --targets-file targets.txt --laps --threads 10
```

TaskHound queries LDAP for each target's LAPS password, then authenticates to that host with it. Your domain account needs read permissions on the LAPS attributes (which is a common delegation).

### Custom Admin Username

If the LAPS-managed account isn't called `Administrator` (some orgs rename it, and honestly, they should):

```bash
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local -t reactor01.shinra.local --laps --laps-user localadmin
```

### LAPS + OPSEC Mode

OPSEC mode disables LDAP and RPC operations for stealth, which conflicts with LAPS (it needs LDAP). If you want LAPS anyway, use `--force-laps`:

```bash
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local -t reactor01.shinra.local --laps --opsec --force-laps
```

I know this is far from ideal and will certainly blow up in edge cases, but sometimes you need LAPS more than you need stealth.

### Supported LAPS Types

| Type | LDAP Attribute | Encrypted | Notes |
|------|---------------|-----------|-------|
| Windows LAPS | `msLAPS-Password` | No | JSON blob with account name + password |
| Windows LAPS | `msLAPS-EncryptedPassword` | Yes (MS-GKDI) | Decrypted automatically via Group Key Distribution Service |
| Legacy LAPS | `ms-Mcs-AdmPwd` | No | Plain text password, no account name (assumes Administrator) |

TaskHound tries all three attributes and uses whatever it finds. If a host has both legacy and Windows LAPS attributes (migration period), Windows LAPS wins.

## Separate LDAP Credentials

Sometimes the account you're scanning with doesn't have the best LDAP access for SID resolution (or you want to use a different account for the LDAP-heavy operations). You can specify separate LDAP credentials:

```bash
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local -t reactor01.shinra.local \
  --ldap-user svc_materia --ldap-password 'LdapPass!456'
```

This uses `cloud.strife` for SMB connections to targets but `svc_materia` for all LDAP/GC SID resolution queries. Niche, but it comes up.

## Pre-Flight Credential Validation

TaskHound validates your credentials before scanning any targets. This exists to prevent a common and painful scenario: you fat-finger the password, launch a 200-host scan, and every single authentication attempt counts toward the domain lockout threshold. By the time you notice, the account is locked.

### How it works

During initialization (before any targets are touched), TaskHound makes:

1. **One SMB authentication attempt** against `--dc-ip` (or the first target if no DC is specified) using your main credentials
2. **One LDAP bind attempt** against the DC using your dedicated LDAP credentials (only if `--ldap-user` or `--ldap-domain` is specified separately from main auth)

If either check detects an authentication failure (`STATUS_LOGON_FAILURE`, `STATUS_ACCOUNT_LOCKED_OUT`, `STATUS_PASSWORD_EXPIRED`, Kerberos pre-auth failures, LDAP `invalidCredentials`, etc.), the tool **hard-aborts immediately** with a clear error message. No targets are scanned. No further authentication attempts are made.

Network errors (timeouts, connection refused) produce a warning but don't abort — the DC might just be unreachable, which isn't a lockout risk.

### When it's skipped

- **Local auth** (`-d '.'`): No domain lockout policy applies to local accounts
- **Offline mode** (`--offline`, `--offline-disk`): No network authentication at all
- **No DC or target available**: If neither `--dc-ip` nor `-t` is specified (e.g., `--auto-targets` only), the check is skipped with a warning

### Cost

One extra SMB connection to the DC at startup (plus one LDAP bind if using separate LDAP creds). For a multi-target scan, this is negligible compared to what follows. For a single-target scan, it's one extra round-trip. For the account lockout it prevents, it's worth it.
