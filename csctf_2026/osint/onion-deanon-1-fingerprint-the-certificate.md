# Onion Deanon 1: Fingerprint the Certificate

**Category:** OSINT · **Points:** 134 · **Flag:** `CSCTF{14:BF:CD:53:D5:09:FE:DF:0C:A4:FE:7E:9A:3D:6F:E2:A0:45:1F:4E:DA:F7:76:39:EB:BC:0F:ED:93:EB:23:80}`

## What the handout gives you

The task continues the ParsnipLocker investigation and asks for the SHA-256 fingerprint of the certificate presented by its HTTPS onion site. The earlier briefing supplies the site address and limits the work to passive inspection of that host. There are no separate files attached to this task.

- `README.md` defines the requested answer as uppercase hexadecimal bytes separated by colons and gives the flag format.
- The handout names `https://4uybrxybehxbf646wqbnyjxyjk2xis6mpvo4d57dv25zf5jsazf5tsad.onion` as the target. Tor is needed to reach it.

## Walkthrough

1. Route the TLS connection through Tor to the exact onion hostname from the handout. Keep the hostname in the connection so the server presents the certificate for the intended virtual host. Do not scan other addresses; the briefing permits passive inspection of this one service.

2. Ask OpenSSL to display the certificate chain from the TLS handshake, then let `openssl x509` calculate the SHA-256 fingerprint of the first certificate, which is the server's leaf certificate:

   `torsocks openssl s_client -connect 4uybrxybehxbf646wqbnyjxyjk2xis6mpvo4d57dv25zf5jsazf5tsad.onion:443 -servername 4uybrxybehxbf646wqbnyjxyjk2xis6mpvo4d57dv25zf5jsazf5tsad.onion -showcerts </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256`

   OpenSSL prints the digest as 32 uppercase hexadecimal bytes separated by colons. This is a certificate fingerprint, not the certificate serial number requested by the preceding lab task. The output to preserve is `14:BF:CD:53:D5:09:FE:DF:0C:A4:FE:7E:9A:3D:6F:E2:A0:45:1F:4E:DA:F7:76:39:EB:BC:0F:ED:93:EB:23:80`.

   The command parses the PEM certificate and fingerprints its DER-encoded certificate data. The PEM delimiters and line breaks do not enter the digest. SHA-256 returns 32 bytes, shown here as 64 hexadecimal characters; OpenSSL's fingerprint display adds a colon between each byte. The separators make the result easier to compare and are part of the requested flag text, even though they are not part of the digest itself.

3. Copy that full value into the `CSCTF{...}` wrapper. Keep the colons and letter case: the answer format explicitly asks for uppercase hexadecimal with colons, so removing separators or converting to lowercase changes the submitted answer.

## Answer

The handshake certificate's SHA-256 fingerprint is `14:BF:CD:53:D5:09:FE:DF:0C:A4:FE:7E:9A:3D:6F:E2:A0:45:1F:4E:DA:F7:76:39:EB:BC:0F:ED:93:EB:23:80`. The flag is `CSCTF{14:BF:CD:53:D5:09:FE:DF:0C:A4:FE:7E:9A:3D:6F:E2:A0:45:1F:4E:DA:F7:76:39:EB:BC:0F:ED:93:EB:23:80}`.

## Notes

Use the fingerprint from the onion service's own TLS handshake. A matching certificate found on another host would require separate evidence that it is the same leaf certificate; the task asks for the certificate presented by this specific service. Do not substitute a certificate serial, issuer fingerprint, or a fingerprint computed from a different certificate in the chain.
