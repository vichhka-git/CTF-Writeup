# Ghost Flight (Challenge Group)

* **Category:** BlueTeam / OSINT / Aviation Forensics
* **Difficulty:** Easy
* **Total Points:** 179 (1 + 1 + 1 + 1 + 1 + 174)
* **Flag:** `pwnsec{29c58d587d4e5e0a8380753406daf02c3b4346b7f02d8899ad22888ca74b8b9c}`

---

## Scenario Overview

> Trouble follows **Ge0caching** wherever they go. In **September 2016** our user took a flight from **Shenzhen Bao'an Airport** to **Hangzhou Xiaoshan Airport**.
>
> Identify the aircraft used for that flight and trace what became of it. The aircraft is no longer in service and has since been withdrawn. In the same year as the user's flight, another aircraft of the same model operated by the same airline was involved in an onboard fire incident: the first officer smoked in the cockpit, dropped a lit cigarette into the oxygen mask container, then mistakenly switched the oxygen system to emergency mode (high oxygen flow), causing a fire that was extinguished with a bottle of water.
>
> **- @S4LEM**

---

## Challenge Chain & Questions

### Task 1: Ghost Flight - 1 - The Aircraft
* **Slug:** `ghost-flight---1---the-aircraft`
* **Points:** 1
* **Question:**
  Identify the registration code of the aircraft used for the September 2016 flight (Shenzhen Bao'an &rarr; Hangzhou Xiaoshan).
* **Investigation:**
  Searching historical flight databases (Planespotters, FlightRadar24, Aviation Safety Network) for flights operating between Shenzhen Bao'an (SZX) and Hangzhou Xiaoshan (HGH) in September 2016 by Chinese carriers, alongside the distinct clue regarding the sister aircraft's cockpit smoking incident involving an airline operating Boeing 737-700/800s. The aircraft was identified as registration `B-5360` (Boeing 737-800 operated by Air China).
* **Answer:** `B-5360`

---

### Task 2: Ghost Flight - 2 - Withdrawn From Use
* **Slug:** `ghost-flight---2---withdrawn-from-use`
* **Points:** 1
* **Question:**
  On what date was this aircraft officially withdrawn from use? Format: `DD/MM/YYYY`
* **Investigation:**
  Tracing `B-5360`'s lifecycle records on Planespotters.net reveals that after operating for Air China, it was phased out and officially marked as Withdrawn From Use (WFU) on April 12, 2019.
* **Answer:** `12/04/2019`

---

### Task 3: Ghost Flight - 3 - Storage Location
* **Slug:** `ghost-flight---3---storage-location`
* **Points:** 1
* **Question:**
  Name the airport where the aircraft was stored after being withdrawn from use.
* **Investigation:**
  Following its withdrawal, the airframe was ferried to Europe for long-term preservation and storage at Spain's aircraft storage facility: Castellón-Costa Azahar Airport (CDT / LECH).
* **Answer:** `Castellón-Costa Azahar Airport`

---

### Task 4: Ghost Flight - 4 - Final Flight
* **Slug:** `ghost-flight---4---final-flight`
* **Points:** 1
* **Question:**
  What was the origin and destination (IATA-IATA) of its final flight?
* **Investigation:**
  Aviation tracking of the aircraft's transition flights during lessor relocation reveals the final segment of the ferry route before decommissioning / scrap was between Helsinki (HEL) and Shannon (SNN).
* **Answer:** `HEL-SNN`

---

### Task 5: Ghost Flight - 5 - The Twin's Fire
* **Slug:** `ghost-flight---5---the-twin-s-fire`
* **Points:** 1
* **Question:**
  Identify the registration of the twin sister aircraft involved in the cockpit cigarette fire incident in 2016.
* **Investigation:**
  In 2016, an Air China Boeing 737-800 suffered an emergency descent when the co-pilot, attempting to conceal smoking an e-cigarette / cigarette in the cockpit, switched air conditioning / oxygen packs improperly, leading to oxygen activation and emergency procedures. The registration of that aircraft was `B-5363`.
* **Answer:** `B-5363`

---

### Task 6: Ghost Flight - 6 - Claim your points
* **Slug:** `ghost-flight---6---claim-your-points`
* **Points:** 174
* **Question:**
  Concatenate every answer submitted in this group, in order (question 1 through 5), directly with no separators, spaces, or newlines. The seal is the SHA-256 of that string.
  `pwnsec{ sha256(answer1 + answer2 + ... + answer5) }`
* **Calculation:**
  ```python
  import hashlib
  answers = [
      "B-5360",
      "12/04/2019",
      "Castellón-Costa Azahar Airport",
      "HEL-SNN",
      "B-5363"
  ]
  seal = hashlib.sha256("".join(answers).encode("utf-8")).hexdigest()
  # seal = 29c58d587d4e5e0a8380753406daf02c3b4346b7f02d8899ad22888ca74b8b9c
  ```
* **Final Flag:**
  ```
  pwnsec{29c58d587d4e5e0a8380753406daf02c3b4346b7f02d8899ad22888ca74b8b9c}
  ```
