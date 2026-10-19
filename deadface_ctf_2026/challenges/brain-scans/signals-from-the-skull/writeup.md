# Signals from the Skull

- **Category:** Brain Scans
- **Points:** 300

## Challenge

The CS-9000 chatters constantly over Bluetooth Low Energy for remote maintenance. Use the correct tool in your toolkit to capture what it's leaking into the air. Most of the traffic is boring vitals telemetry. One characteristic is quietly dribbling out a maintenance log, a few bytes at a time. Capture it, reassemble it, and decode it. Submit the flag as `deadface{flag-text}`. [Access the Device](https://emedra.dctf.io:8080)

## Solution

CONFIRMED - deadface{un3ncrypt3d_b4bbl3_fr0m_th3_sku11} (300 pts) | the team reproduced the whole capture independently. GET /api/device lists the simulated toolkit (hdmi, displayport, live-linux, rubber-ducky, ble-sniffer) with compatiblePorts; the BLE sniffer binds to port "usb-a". POST /api/connect {"tool":"ble-sniffer","port":"usb-a"} returns {"ok":true,"windowType":"ble-capture","token":"<uuid>"}, and GET /api/capture?token=<uuid> then returns 96 packets (without the token it 403s "No BLE sniffer attached"). 72 packets are on handle 0x2a - the boring vitals telemetry the challenge warns about - and 24 are on handle 0x37. Sorting the 0x37 packets by seq, hex-decoding and concatenating gives 280 bytes of base64, which decodes to: "St.Dymphna CS-9000 maint log | site=stdymphna-rmc-01 | tech=emedra-svc / last_patient: Gideon Marsh (MRN 100413) / note: telemetry unencrypted per EM-2019 default; flag deadface{un3ncrypt3d_b4bbl3_fr0m_th3_sku11}". | the team
