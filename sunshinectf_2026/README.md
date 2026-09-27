# Sunshine CTF 2026

Writeups for **Sunshine CTF 2026**.

**27 challenges solved.**

Every challenge that carried points was solved. Counted here are the 27 whose flags we actually
recovered; the platform also credits the 1-point `Greetings` entry, whose flag is printed verbatim
in its own description, so it is not included as a writeup. The nine remaining entries were BSides Orlando
on-site challenges (a badge UART header, an FM radio, a PCB pendant, a physical dead drop, printed
books and a bingo card) plus a `???` placeholder; all finished the event weighted to 0 points and
none has a remote component — verified against the platform API, which returns empty `files`,
`hints` and `tags` arrays for all of them.

Each challenge directory holds the original description, `writeup.md`, the final `solve.py` where a
scripted solver existed, and the downloaded handouts under `files/`. Agent workspaces, session
cookies and platform metadata are excluded.

| Category | Challenge | Pts | Solves | Writeup | Solver |
| --- | --- | ---: | ---: | --- | --- |
| Pwn | [Safe House](challenges/pwn/07-safe-house/) | 488 | 99 | [writeup](challenges/pwn/07-safe-house/writeup.md) | [solve.py](challenges/pwn/07-safe-house/solve.py) |
| Pwn | [Code Breaker](challenges/pwn/03-code-breaker/) | 487 | 104 | [writeup](challenges/pwn/03-code-breaker/writeup.md) | [solve.py](challenges/pwn/03-code-breaker/solve.py) |
| Pwn | [Homemaker](challenges/pwn/14-homemaker/) | 484 | 116 | [writeup](challenges/pwn/14-homemaker/writeup.md) | [solve.py](challenges/pwn/14-homemaker/solve.py) |
| Pwn | [Cache Money](challenges/pwn/02-cache-money/) | 483 | 120 | [writeup](challenges/pwn/02-cache-money/writeup.md) | [solve.py](challenges/pwn/02-cache-money/solve.py) |
| Pwn | [Print Print Revolution](challenges/pwn/05-print-print-revolution/) | 483 | 120 | [writeup](challenges/pwn/05-print-print-revolution/writeup.md) | [solve.py](challenges/pwn/05-print-print-revolution/solve.py) |
| Pwn | [Mad Libs](challenges/pwn/04-mad-libs/) | 482 | 123 | [writeup](challenges/pwn/04-mad-libs/writeup.md) | [solve.py](challenges/pwn/04-mad-libs/solve.py) |
| Pwn | [Total Recall](challenges/pwn/08-total-recall/) | 467 | 165 | [writeup](challenges/pwn/08-total-recall/writeup.md) | [solve.py](challenges/pwn/08-total-recall/solve.py) |
| web | [Planetary Probe](challenges/web/15-planetary-probe/) | 496 | 64 | [writeup](challenges/web/15-planetary-probe/writeup.md) | [solve.py](challenges/web/15-planetary-probe/solve.py) |
| web | [SiteCheck](challenges/web/10-sitecheck/) | 488 | 102 | [writeup](challenges/web/10-sitecheck/writeup.md) | [solve.py](challenges/web/10-sitecheck/solve.py) |
| web | [CookieCorp](challenges/web/09-cookiecorp/) | 487 | 104 | [writeup](challenges/web/09-cookiecorp/writeup.md) | [solve.py](challenges/web/09-cookiecorp/solve.py) |
| web | [Groundhog Day](challenges/web/50-groundhog-day/) | 467 | 164 | [writeup](challenges/web/50-groundhog-day/writeup.md) | [solve.py](challenges/web/50-groundhog-day/solve.py) |
| web | [You Are Kidding Me](challenges/web/12-you-are-kidding-me/) | 422 | 252 | [writeup](challenges/web/12-you-are-kidding-me/writeup.md) | [solve.py](challenges/web/12-you-are-kidding-me/solve.py) |
| web | [Used Goods of Tomorrow](challenges/web/11-used-goods-of-tomorrow/) | 400 | 284 | [writeup](challenges/web/11-used-goods-of-tomorrow/writeup.md) | — |
| RE | [RoboCall](challenges/rev/24-robocall/) | 485 | 111 | [writeup](challenges/rev/24-robocall/writeup.md) | [solve.py](challenges/rev/24-robocall/solve.py) |
| RE | [IntMod](challenges/rev/44-intmod/) | 482 | 121 | [writeup](challenges/rev/44-intmod/writeup.md) | [solve.py](challenges/rev/44-intmod/solve.py) |
| RE | [FlameOn](challenges/rev/47-flameon/) | 458 | 186 | [writeup](challenges/rev/47-flameon/writeup.md) | — |
| Forensics | [ghost in the thread - 4](challenges/forensics/31-ghost-in-the-thread-4/) | 481 | 127 | [writeup](challenges/forensics/31-ghost-in-the-thread-4/writeup.md) | — |
| Forensics | [ghost in the thread - 2](challenges/forensics/29-ghost-in-the-thread-2/) | 480 | 129 | [writeup](challenges/forensics/29-ghost-in-the-thread-2/writeup.md) | — |
| Forensics | [ghost in the thread - 3](challenges/forensics/30-ghost-in-the-thread-3/) | 470 | 156 | [writeup](challenges/forensics/30-ghost-in-the-thread-3/writeup.md) | — |
| Forensics | [ghost in the thread - 1 - start here](challenges/forensics/28-ghost-in-the-thread-1-start-here/) | 461 | 179 | [writeup](challenges/forensics/28-ghost-in-the-thread-1-start-here/writeup.md) | — |
| Forensics | [Welcome Call!](challenges/forensics/25-welcome-call/) | 434 | 232 | [writeup](challenges/forensics/25-welcome-call/writeup.md) | — |
| Forensics | [you cut me off](challenges/forensics/26-you-cut-me-off/) | 417 | 260 | [writeup](challenges/forensics/26-you-cut-me-off/writeup.md) | — |
| Forensics | [my eyes burn](challenges/forensics/27-my-eyes-burn/) | 389 | 300 | [writeup](challenges/forensics/27-my-eyes-burn/writeup.md) | — |
| Forensics | [suntrail](challenges/forensics/23-suntrail/) | 377 | 315 | [writeup](challenges/forensics/23-suntrail/writeup.md) | — |
| Forensics | [NAS coal](challenges/forensics/13-nas-coal/) | 365 | 330 | [writeup](challenges/forensics/13-nas-coal/writeup.md) | — |
| misc | [Vecnet](challenges/misc/51-vecnet/) | 495 | 67 | [writeup](challenges/misc/51-vecnet/writeup.md) | [solve.py](challenges/misc/51-vecnet/solve.py) |
| misc | [If you have questions!](challenges/misc/20-if-you-have-questions/) | 50 | 380 | [writeup](challenges/misc/20-if-you-have-questions/writeup.md) | — |

## Notes worth keeping

A few mechanisms from this event generalise beyond it:

- **Fingerprint the client before theorising about it.** *Groundhog Day* was stuck for two rounds on
  the assumption that the fetcher was Python's `urllib`. Two error strings —
  `Failed to connect ... after 0 ms` and `URL rejected: Malformed input to a URL function` — are
  libcurl naming itself. Once the client was known to be pycurl, `gopher://` turned a GET-only SSRF
  into an arbitrary POST. Error text is the one place a library identifies itself for free.
- **State the scope of a negative.** *SiteCheck* was nearly lost because "adding `#clearance` changes
  nothing" was recorded as a fact about fragments when it was a fact about the *login page* — the
  drone was anonymous when it was measured, so no anchor existed to scroll to. A negative is only
  about the conditions it was taken under, and a precondition nobody knew about is still a
  precondition.
- **An error can be indistinguishable from a false.** On *Planetary Probe* an unbalanced quote
  returns exactly the FALSE length, so a malformed payload silently reports every bit as zero. Every
  predicate has to carry its own negation. The same shape appears in *Cache Money* and
  *Code Breaker*, where a permission denial and an empty object look identical.
- **Ask what a catalog *grants*, not just what it *contains*.** This is the lesson that cost the most.
  On *Planetary Probe* the whole team treated the database as a place to read *from* — enumerating
  tables, columns, config parameters, role names, rule and constraint text — and never once asked what
  the database let us **do**. The answer was `COPY ... TO/FROM PROGRAM`, which needs membership in
  `pg_execute_server_program`. The role catalog was already on the list of things to enumerate, but
  with the wrong question attached: we wanted `pg_roles.rolname` in case the flag was a username, when
  the useful read was `pg_auth_members` — not what the roles are *called*, but what they *permit*. One
  probe on role membership points straight at the answer.

  *SiteCheck* is the same blind spot in different clothes: every lane hunted for a privileged **viewer**
  to borrow, and nobody asked what **grants** privilege in the first place.
- **Counting beats guessing.** On *Planetary Probe*, eleven keyword searches for a flag-shaped table
  or column all came back empty — and all of them were negatives about a wordlist. A one-request
  check of the *column count* invalidated the lot.
