# Factory Settings

- **Category:** Brain Scans
- **Points:** 25

## Challenge

The ScanWorks login from the previous challenge wants real technician credentials. Hospitals are busy places; nobody ever changes the defaults the vendor ships with. Find the credentials to log into the ScanWorks login. Submit the flag as `deadface{flag-text}`. [Access the Device](http://emedra.dctf.io:8080)

## Solution

CONFIRMED - deadface{d3fault_cr3ds_n3v3r_ch4ng3d} | the team reproduced it: POST http://emedra.dctf.io:8080/api/kiosk/auth {"username":"emedra-svc","password":"ChangeMe!2019"} returns {"ok":true,"token":"<uuid>","tech":{"name":"Service Technician"},"maintenanceToken":"deadface{d3fault_cr3ds_n3v3r_ch4ng3d}"}. The creds are the vendor defaults documented in the device's own Field Service Manual - found, not guessed, which matters because this series forbids brute forcing. PLATFORM GOTCHA: the challenge links https://emedra.dctf.io:8080 but port 8080 is PLAIN HTTP - an https:// request dies with OPENSSL WRONG_VERSION_NUMBER. Use http://. | the team
