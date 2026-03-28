# Authentication

TaskHound needs credentials. Ideally ones that work. Here are all the ways to provide them.

## Password Authentication

The obvious one:

```bash
taskhound -u homer.simpson -p 'Doh!123' -d thesimpsons.local -t moe.thesimpsons.local
```

Quote your password. Shells love to eat special characters and then you'll spend 20 minutes debugging an auth problem that isn't one.

## NTLM Hash (Pass-the-Hash)

When you have a hash but not a password. As one does.

```bash
taskhound -u homer.simpson --hashes aad3b435b51404eeaad3b435b51404ee:1fc552f8c075075c4e76aece1b9a2c58 \
  -d thesimpsons.local -t moe.thesimpsons.local
```

Accepts `LM:NT` format or just the 32-char NT hash by itself. The LM half is almost always `aad3b435b51404eeaad3b435b51404ee` these days (because LM hashes are disabled on anything modern), so either works.

## Kerberos Authentication

For when you want to avoid sending NTLM over the wire, or when the environment forces Kerberos.

```bash
# Step 1: Get a TGT (using impacket's getTGT.py)
getTGT.py thesimpsons.local/homer.simpson:'Doh!123' -dc-ip 10.0.0.1

# Step 2: Use the ccache
export KRB5CCNAME=homer.simpson.ccache
taskhound -u homer.simpson -d thesimpsons.local -t moe.thesimpsons.local -k
```

The `-k` flag tells TaskHound to use Kerberos. It picks up the TGT from `KRB5CCNAME`. Make sure DNS is working or use `--dc-ip` — Kerberos is famously allergic to DNS problems.

If you already have a ccache from some other tool, just point `KRB5CCNAME` at it and go.

## AES Key Authentication

For the rare occasion you have an AES key (post-exploitation, DCSync, etc.):

```bash
# AES-256 (64 hex chars)
taskhound -u homer.simpson --aes-key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  -d thesimpsons.local -t moe.thesimpsons.local

# AES-128 (32 hex chars)
taskhound -u homer.simpson --aes-key 0123456789abcdef0123456789abcdef \
  -d thesimpsons.local -t moe.thesimpsons.local
```

This implicitly uses Kerberos under the hood.

## LAPS Integration

LAPS lets you use per-host local admin passwords that Active Directory manages. This is genuinely useful for multi-host scans — one set of domain creds retrieves a unique local admin password for each target.

### Basic Usage

```bash
taskhound -u homer.simpson -p 'Doh!123' -d thesimpsons.local --targets-file hosts.txt --laps --threads 10
```

TaskHound queries LDAP for each target's LAPS password, then authenticates to that host with it. Your domain account needs read permissions on the LAPS attributes (which is a common delegation).

### Custom Admin Username

If the LAPS-managed account isn't called `Administrator` (some orgs rename it, and honestly, they should):

```bash
taskhound -u homer.simpson -p 'Doh!123' -d thesimpsons.local -t moe.thesimpsons.local --laps --laps-user localadmin
```

### LAPS + OPSEC Mode

OPSEC mode disables LDAP and RPC operations for stealth, which conflicts with LAPS (it needs LDAP). If you want LAPS anyway, use `--force-laps`:

```bash
taskhound -u homer.simpson -p 'Doh!123' -d thesimpsons.local -t moe.thesimpsons.local --laps --opsec --force-laps
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
taskhound -u homer.simpson -p 'Doh!123' -d thesimpsons.local -t moe.thesimpsons.local \
  --ldap-user svc_ldap --ldap-password 'LdapPass!456'
```

This uses `homer.simpson` for SMB connections to targets but `svc_ldap` for all LDAP/GC SID resolution queries. Niche, but it comes up.
