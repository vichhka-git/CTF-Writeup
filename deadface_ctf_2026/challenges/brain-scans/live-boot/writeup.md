# Live Boot

- **Category:** Brain Scans
- **Points:** 50
- **Flag:** `deadface{h4rdc0d3d_k3ys_1n_th3_c0nf1g}`

## Challenge

We think DEADFACE was able to gain a live shell on the device, but the hospital staff insists there is no way to access the device's underlying OS. Somehow, DEADFACE was able to utilize keys for this device that aren't spelled out in the Field Manual. Access the device's file system and determine what hardcoded keys you can find. Submit the flag as `deadface{flag-text}`. [Access the Device](http://emedra.dctf.io:8080)

## Solution

CONFIRMED - deadface{h4rdc0d3d_k3ys_1n_th3_c0nf1g} | the team reproduced it. POST /api/connect {"tool":"live-linux","port":"usb-a"} -> windowType "terminal" + token. The shell endpoint is POST /api/shell {"token":<uuid>,"line":"<cmd>"} (NOT cmd/Bearer - those 400 with "token and line are required"), and it tracks cwd between calls. `sudo mount /dev/sda2 /mnt` (plain mount fails: only root), then `cat /mnt/opt/scanworks/config.yaml` yields api_key: deadface{h4rdc0d3d_k3ys_1n_th3_c0nf1g}, with the comment "TODO: move to secrets store before GA". That same file hands you the next two challenges: integrity.salt EM-2019 and debug_console {enabled:true, function: debug.dump, tables:[patients..]}.
