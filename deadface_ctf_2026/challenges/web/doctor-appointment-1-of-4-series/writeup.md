# Doctor Appointment (1 of 4 series)

- **Category:** Web
- **Points:** 26

## Challenge

Web applications are tricky these days and we are seeing an influx of vibe coded platforms. Well, time to put your black hat on and see if you can gain access to this website. Don't just brute force a massive dictionary. Take a look at GhostTown for potential resources to gain access. > NOTE: Do not perform port scanning on this host, only the address and port discovered in OSINT matter. Submit the flag as: `deadface{flag-text}` http://45.79.200.170:3000/

## Solution

SQL injection on the JSON login endpoint. A classic always-true payload in the username field returns HTTP 200 with a JSON body that the server itself labels as containing the flag, alongside a working username and password that the rest of the series depends on. The server's own message points at reading the raw response body rather than the rendered page. Note a second flag-shaped string is planted in an HTML comment on the dashboard; the response-body value is the intended one.
