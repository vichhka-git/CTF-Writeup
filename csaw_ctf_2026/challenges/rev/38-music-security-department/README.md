# Music Security Department

- Category: Rev
- ID: 38
- Type: dynamic
- Value: 481
- Solves: 58
- Author: aarch_angel // \<Maya/>
- Files:
  - `csirac.zip`

## Description

You've heard rumours of a flag stashed away in the production studio of a prominent EDM artist - but she's contracted the infamous Music Security Department to lock it up inside a decommissioned CDJ! Can you manage to heist the flag?

The deck is still powered up and answering on its patch port - connect to it, then hit 'Run'!
```
$ nc localhost 4562
 
=[ CSIRAC CDJ-4562 ]==========================
MUSIC SECURITY DEPARTMENT :: DRM enforcement unit
unit CSIRAC   project I_LOVE_MY_COMPUTER
1 stem SEALED -- type HELP
 
CSIRAC>
```

*Notes:*
* Purr-Data or pd-l2ork is required, vanilla Pure Data will not work.
* You might want to check out [this Purr-Data theme](https://github.com/aarch-angel/Horizon-Purr-Data-Theme ) :)
* csirac.pd_linux / csirac.dll will not lead you to the flag.
* The console needs one LF-terminated line at a time.
* Frequency starts at 10Hz - you'll likely want to increase it to speed up the `nc` interface, or slow it down to analyse the patch.
* There's a "Reset" button.
