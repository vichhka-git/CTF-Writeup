# Harvest

**Category:** OSINT · **Points:** 270 · **Flag:** `CSCTF{PP-7_SNOP}`

## What the handout gives you

The handout contains an intelligence briefing, a social media post, a photograph, and internal military planning documents from the 417th Separate Helicopter Squadron at Korlevo aerodrome:

- `00_brief.txt` — context regarding a regional Telegram report alleging helicopter sling-load delivery near Staroselye.
- `01_telegram_post.txt` — post claiming tail number "bort 34" delivered cargo to Staroselye on the afternoon of 14 August 2026.
- `02_photo.png` (2,115,304 bytes) — photograph showing a helicopter carrying an external sling load over agricultural land.
- `03_flight_schedule_14AUG.txt` — flight board listing tail numbers, aircraft types, assigned callsigns, missions, and maintenance remarks.
- `04_signals_instruction_extract.txt` — communications security extract defining message formats, Vigenère cipher rules, and Russian radio vocabulary.
- `05_logistics_sheet_14AUG.txt` — squadron logistics inventory mapping cargo code words, loading manifests, and designated landing points (PP).
- `06_intercepts_14AUG.txt` — two encrypted radio transmissions intercepted on the squadron network on 14 August.

## Walkthrough

1. **Evaluate the Telegram report against squadron records.** The Telegram channel claimed tail number 34 delivered cargo near Staroselye on the afternoon of 14 August. Cross-referencing `03_flight_schedule_14AUG.txt` refutes this:
   - Bort 34 is grounded (`U/S. Main gearbox replacement. Not before 18.08`).
   - `05_logistics_sheet_14AUG.txt` notes that landing site `PP-2` (Staroselye) has been closed since 2 August due to mines.
   - The flight schedule records a strict flight ban after 15:00 due to a severe thunderstorm warning.
   The public Telegram post is disinformation.

2. **Identify the authentic sling-load mission.** The flight schedule lists two external sling-load flights on 14 August:
   - Bort 25 (callsign `BEREG`): scheduled 13:20–14:35 MSK to `PP-5`.
   - Bort 22 (callsign `ZHATVA`, Mi-8MTV-5): scheduled 09:00–10:55 MSK with destination landing site per separate order.
   `06_intercepts_14AUG.txt` records two intercepted transmissions:
   - Intercept #1 was received at 10:21 MSK, falling inside Bort 22's flight window.
   - Intercept #2 was received at 16:34 MSK, well after the 15:00 weather grounding.

3. **Decode Intercept #1.** Per `04_signals_instruction_extract.txt`, reports are encrypted using a standard Vigenère cipher over the Latin alphabet. The daily key is the crew's assigned callsign, and `X` denotes word boundaries. Decrypting the ciphertext of Intercept #1 using key `ZHATVA`:

   Ciphertext:
   `CVKEVDWGHTOVZEGKPZWZNHKXBOEMTRDEMXNTZEDHNTZCLXIXOWXLZMWCRXHYZEDXNYZAXWQACASTOXAVRMSDUHDMNASEDOVXJVNXX`

   Plaintext:
   `DOKLADXZHATVAXGRUZXSNOPXCHETYREXMESTAXDOSTAVLENXPPXSEMXVREMYAXDESYATXDVADTSATXBORTXDVADTSATXDVAKONECXX`

4. **Translate the radio report.** Parsing the words separated by `X` and consulting the glossary in `04_signals_instruction_extract.txt`:
   - `DOKLAD ZHATVA`: Report from Zhatva.
   - `GRUZ SNOP CHETYRE MESTA`: Cargo SNOP, four pieces.
   - `DOSTAVLEN PP SEM`: Delivered to landing point 7 (`SEM` = 7).
   - `VREMYA DESYAT DVADTSAT`: Time 10:20 MSK.
   - `BORT DVADTSAT DVA KONEC`: Tail number 22, end of transmission.

5. **Cross-reference logistics manifests.** In `05_logistics_sheet_14AUG.txt`:
   - `PP-7` corresponds to Mirnoe (`harvested field west of the dairy farm`).
   - `SNOP` designates portable electronic warfare (EW) jamming equipment.
   - The loading plan confirms Bort 22 carried `SNOP x4` via external sling.

## Answer

The mission delivered cargo `SNOP` to landing site `PP-7`. Formatting as `CSCTF{PP-N_CODEWORD}` gives:

`CSCTF{PP-7_SNOP}`

## Notes

Intercept #2 was transmitted at 16:34 MSK during the squadron-wide weather grounding, and its decrypted content attempts to confirm the false Staroselye narrative. Discarding Intercept #2 is required based on the maintenance logs and flight timetable.
