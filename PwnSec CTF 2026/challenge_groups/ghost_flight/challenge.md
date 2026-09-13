# Ghost Flight

- **Nature:** BlueTeam
- **Type:** Classic
- **Total Tasks:** 6
- **Unlocked Tasks:** 6
- **Solved Tasks:** 6
- **Attachment Password:** `infected`

## Description & Scenario

Trouble follows **Ge0caching** wherever they go. In **September 2016** our
user took a flight from **Shenzhen Bao'an Airport** to
**Hangzhou Xiaoshan Airport**.



Identify the aircraft used for that flight and trace what became of it. The
aircraft is no longer in service and has since been withdrawn. In the same year as
the user's flight, another aircraft of the same model operated by the same airline
was involved in an onboard fire incident: the first officer smoked in the cockpit,
dropped a lit cigarette into the oxygen mask container, then mistakenly switched
the oxygen system to emergency mode (high oxygen flow), causing a fire that was
extinguished with a bottle of water.


**- @S4LEM**

## Tasks Overview

| # | Task Name | Status | Difficulty | Points | Solves | Solved |
|---|---|---|---|---|---|---|
| 1 | Ghost Flight - 1 - The Aircraft | 🔓 Unlocked | Easy | 1 | 52 | ✅ `B-5360` |
| 2 | Ghost Flight - 2 - Withdrawn From Use | 🔓 Unlocked | Easy | 1 | 52 | ✅ `12/04/2019` |
| 3 | Ghost Flight - 3 - Storage Location | 🔓 Unlocked | Easy | 1 | 44 | ✅ `Castellón-Costa Azahar Airport` |
| 4 | Ghost Flight - 4 - Final Flight | 🔓 Unlocked | Easy | 1 | 48 | ✅ `HEL-SNN` |
| 5 | Ghost Flight - 5 - The Twin's Fire | 🔓 Unlocked | Easy | 1 | 49 | ✅ `B-5363` |
| 6 | Ghost Flight - 6 - Claim your points | 🔓 Unlocked | Easy | 174 | 44 | ✅ `pwnsec{29c58d587d4e5e0a8380753406daf02c3b4346b7f02d8899ad22888ca74b8b9c}` |

## Unlocked Task Questions

### Task 1: Ghost Flight - 1 - The Aircraft

- **Slug:** `ghost-flight---1---the-aircraft`
- **Difficulty:** Easy | **Points:** 1 | **Solves:** 52

Identify the registration code of the aircraft used for the September 2016 flight (Shenzhen Bao'an &rarr; Hangzhou Xiaoshan).



**Answer format:** `Aircraft registration code`

### Task 2: Ghost Flight - 2 - Withdrawn From Use

- **Slug:** `ghost-flight---2---withdrawn-from-use`
- **Difficulty:** Easy | **Points:** 1 | **Solves:** 52

For that aircraft, determine the date it was withdrawn from use.



**Answer format:** `DateOfWFU(DD/MM/YYYY)`



**Example:** `05/11/2020`

### Task 3: Ghost Flight - 3 - Storage Location

- **Slug:** `ghost-flight---3---storage-location`
- **Difficulty:** Easy | **Points:** 1 | **Solves:** 44

For that aircraft, determine where it was stored on 4 June 2019.



**Answer format:** `StorageLocation`



**Example:** `Alice Springs Airport`

### Task 4: Ghost Flight - 4 - Final Flight

- **Slug:** `ghost-flight---4---final-flight`
- **Difficulty:** Easy | **Points:** 1 | **Solves:** 48

For that aircraft, determine the origin and destination of its final flight on 3 June 2019, immediately before it entered storage.



**Answer format:** `ORIGIN-DESTINATION`



**Example:** `PEK-SZX`

### Task 5: Ghost Flight - 5 - The Twin's Fire

- **Slug:** `ghost-flight---5---the-twin-s-fire`
- **Difficulty:** Easy | **Points:** 1 | **Solves:** 49

Identify the registration code of the other aircraft (same model, same airline) involved in the 2016 cockpit fire incident.



**Answer format:** `Aircraft registration code`

### Task 6: Ghost Flight - 6 - Claim your points

- **Slug:** `ghost-flight---6---claim-your-points`
- **Difficulty:** Easy | **Points:** 181 | **Solves:** 43

You've completed the whole investigation. Now claim your points. Take every
answer you submitted in this group, in order (question 1 through 5), and
concatenate them **directly with no separators, spaces, or newlines**,
each answer written **exactly** as it was accepted (case-sensitive). The
seal is the SHA-256 of that string.



**Flag:** `pwnsec{ sha256(answer1 + answer2 + ... + answer5) }`

