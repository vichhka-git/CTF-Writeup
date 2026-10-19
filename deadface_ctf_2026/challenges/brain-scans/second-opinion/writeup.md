# Second Opinion

- **Category:** Brain Scans
- **Points:** 50

## Challenge

On the touchscreen, the current patient is redacted to initials and a masked record number. Even without a login, it might be possible to determine sensitive information about the patient. There are ports available on the device that are used for maintenance, but they're not locked or concealed with a plate. See if you can find information by using a tool from your toolkit. Submit the flag as `deadface{flag-text}`. [Access the Device](http://emedra.dctf.io:8080)

## Solution

CONFIRMED - deadface{hdm1_l34ks_th3_wh0l3_p4t13nt} | the team reproduced it independently. The challenge's "unlocked maintenance ports, use a tool from your toolkit" means the HDMI port: POST /api/connect {"tool":"hdmi","port":"hdmi"} returns a session token with windowType "external-display". GET /api/external-display?level=1 (Bearer token) returns the redacted kiosk view - patient {"initials":"G.M.","maskedMrn":"****13"}, raw:false. The response itself advertises maxLevel:3, and requesting level=3 flips raw:true and drops redaction entirely: patient {"name":"Gideon Marsh","dob":"1981-10-31","mrn":"100413"}, plus technician, study and a diagSession field holding the flag. The vulnerability is that the OSD verbosity level is client-controlled with no authorisation check - exactly the "determine sensitive information without a login" premise. No brute forcing; the API discloses maxLevel itself. Corroborates the BLE log's last_patient Gideon Marsh / MRN 100413. | the team
