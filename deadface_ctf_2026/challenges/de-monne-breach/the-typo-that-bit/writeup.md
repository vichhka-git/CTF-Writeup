# The Typo That Bit

- **Category:** De Monne Breach
- **Points:** 75

## Challenge

Nathan's workstation tried to reach an executive share through a misspelled server name. Identify one mistyped server hostname visible in memory. Submit the hostname, without slashes or the share name. Submit the flag as `deadface{share-name}`. Use the memory dump evidence from **Who Goes There?**

## Solution

Real server is dmf-field-01 (LAN list DMF-FIELD-01 + PROPFIND /executive); misspelled variant in Explorer/WebDAV: \\dmf-fiels-01 and @http://dmf-fiels-01/executive (4 occurrences). Second typo \\dmf-fiel-01 seen once (1 occ) if checker wants it.
