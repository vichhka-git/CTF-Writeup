# CSAW CTF 2026 - House of Hollow Houses (Misc) Writeup

## Challenge Overview
- **Category:** Misc
- **Points:** 215
- **Description:** A labyrinth of "hollow" rooms served as a static website — each room links to others, and the flag lies waiting in the sanctum. Players wander the interlinked rooms (and read what the pages are quietly telling them) to find the way in.
- **Target URL:** `https://hollow-houses.ctf.csaw.io/`

## Solution Methodology
Rather than brute-forcing or blind-crawling the massive cyclic graph of room links, the solution relies on reading the subtle text clues, comments, and hidden elements embedded in each page:

1. **The Threshold / Landing Page (`/`):**
   - An HTML comment reveals: `<!-- the obedient ask the robots first. the rest read the walls. every word is a door. most doors are walls pretending. -->`
   - Section "ii. on the obedient" reiterates that the answer for the obedient is kept in a small text file at the front gate.

2. **The Robots File (`/robots.txt`):**
   - Inspecting `https://hollow-houses.ctf.csaw.io/robots.txt`:
     ```
     User-agent: *
     Disallow: /atrium/
     ```
   - This points directly to the first hidden chamber: `/atrium/`.

3. **The Atrium (`/atrium/`):**
   - An HTML comment advises: `<!-- not every word is the colour it appears to be. select all, if you must. -->`
   - Section "i. on the colour of the walls" contains a list of paragraphs with nearly invisible first-letter spans (`class="h"`):
     - **O**ften...
     - **S**ometimes...
     - **S**elect...
     - **U**nder...
     - **A**sk...
     - **R**ooms...
     - **Y**ou...
   - The acrostic spells `OSSUARY`, pointing to `/ossuary/`.

4. **The Ossuary (`/ossuary/`):**
   - Section "i. the rite" contains a base64 encoded string:
     `d2hhdCB0aGUgbWlycm9yIHNlZXMsIHRoZSBtaXJyb3Iga2VlcHM=`
   - Decoding this produces: `"what the mirror sees, the mirror keeps"`.
   - The prose explains that the sentence contains a noun which is the name of the next room: `/mirror/`.

5. **The Mirror (`/mirror/`):**
   - Section "ii. on the next chamber" explicitly instructs:
     `"The next chamber is called the wellspring. It lies beneath this one, in a sense that has nothing to do with elevation. Knock once, in lower case. Enter. Do not speak above the water."`
   - This leads to `/wellspring/`.

6. **The Sanctum (`/sanctum/`):**
   - The challenge description explicitly specifies: `"and the flag lies waiting in the sanctum."`
   - Accessing `/sanctum/` reveals the sanctum chamber:
     `"you have walked through robots, and under near-invisible letters, and across a sixty-four-character rite, and into a mirror, and down a half-turned alphabet, and arrived here."`
   - Under `"the artifact"`:
     `<span class="flag breathe">csaw{w4nd3r3r_0f_th3_h0ll0w_h0us3}</span>`

## Flag
```
csaw{w4nd3r3r_0f_th3_h0ll0w_h0us3}
```
