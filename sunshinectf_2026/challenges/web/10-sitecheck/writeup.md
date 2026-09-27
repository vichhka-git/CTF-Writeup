# Sunshine CTF 2026 Writeup: SiteCheck

- **Category:** web
- **ID:** 10
- **Points / Solves:** 488 pts / 102 solves
- **Connection:** `https://spaceship.web.2026.sunshinectf.games`
- **Flag:** `sun{fr4gm3nt3d_r3fl3ct10ns_1n_th3_futur3}`

---

## Challenge

> Welcome to **SiteCheck**, the SkyCity fleet's favorite web-diagnostics service since 2062!
> 
> Enlist for a free inspector account and put any website through its paces: our autonomous
> inspection drone flies out to the address you provide, clocks how long the page takes to
> load, tallies how many files it pulls down, and beams back a crisp viewport snapshot — all
> without you lifting a finger.
> 
> Kick the tires on the future of web monitoring.
> 
> > The drone politely refuses to inspect internal or local addresses. Safety first!

---

## Summary

The drone's "internal address" blocklist misses the **IPv6 loopback `[::1]`** — and over that
address the drone is already authenticated as `admin` with OMEGA clearance. A URL fragment then
scrolls the capture to the flag.

## Solution

Register an inspector, submit a URL, and a headless browser visits it and returns load time, a
files-fetched count and a 1280x800 viewport screenshot. `/profile` has a CLASSIFIED clearance section
whose plate reads `REDACTED · insufficient clearance` for a BRONZE account.

**The discriminator was a single bit.** Sweeping loopback *spellings* through the scan endpoint and
comparing files-fetched:

| target | accepted | files | capture |
| --- | --- | --- | --- |
| `http://localhost:3000/` | no (400) | - | - |
| `http://127.0.0.1:3000/`, `127.1`, `0.0.0.0`, `2130706433`, `0177.0.0.1` | no (400) | - | - |
| `http://localtest.me:3000/`, `localhost.`, `127.0.0.1.nip.io` | yes | **10** | login page |
| `http://[::1]:3000/` | **yes** | **9** | **admin profile** |

Ten files included a redirect hop to `/login`; **nine meant no redirect** — the page was served
directly. The capture shows `Inspector: admin — Chief Inspection Drone · Clearance OMEGA`.

**The fragment.** The flag plate sits below the 800px fold behind a deliberate
`<div class="spacer" style="height:1400px">`. A fragment never reaches the server but does move a
browser's scroll position, so:

```
http://[::1]:3000/profile#clearance
```

captures the clearance section directly — `sun{fr4gm3nt3d_r3fl3ct10ns_1n_th3_futur3}`.

**A methodology note worth more than the flag.** The fragment idea had been proposed early and
retired on a measurement showing byte-identical captures with and without `#clearance`. That
measurement was correct — and it was about the *login page*, because the drone was anonymous at the
time; no anchor existed to scroll to. A negative is only about the conditions it was taken under,
and a precondition nobody knew about is still a precondition.

## Ruled Out

All measured against a two-account noise floor (`register=(302,32)`, `profile=(200,3182)`, identical hashes):

- **Mass assignment**: 15 field names (`clearance`, `role`, `tier`, `level`, `admin`, `is_admin`,
  `isAdmin`, `rank`, `grade`, `access`, `privilege`, `inspector_grade`, `clearance_level`, `badge`,
  `certification`) across string/numeric/boolean, plus `user[clearance]`, `user.clearance` and JSON
  bodies — every response byte-identical to control.
- **Prototype pollution** (`__proto__[clearance]`, `constructor[prototype][clearance]`), checked on
  *subsequent* requests: no effect.
- **Username collision**: registration validates `^[A-Za-z0-9_-]{3,24}$` on a trimmed value, and
  login resolves names by the same rule (case-insensitive + trim). No asymmetry.
- **Headers / cookies**: `X-Forwarded-For`, `X-Clearance`, `X-Admin`, `Authorization`, and six cookie
  names — all byte-identical.
- **`file://`, `view-source:`, `about:`** on the scan endpoint: rejected at submission.
- **Internal port sweep through the drone**: only port 3000 listens.
- **`/result` reflection**: the target URL is HTML-escaped.
- **Scan-count-derived clearance**: five scans moved nothing; the service record ("4,102 nominal
  inspections") is static flavour text identical on a brand-new account.
- **`/result` and `/screenshots` ownership**: owner-checked, ids are v4, `GET /screenshots/` 404s.

## Files

- `files/flag-capture.png`
- `files/flagshot.py`
- `files/ipv6-admin-profile.png`
- `files/sc.py`
