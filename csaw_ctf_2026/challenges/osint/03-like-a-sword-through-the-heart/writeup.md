# Like a Sword Through the Heart — CSAW CTF Qualifications 2026 Writeup

- **Category:** OSINT
- **ID:** 3
- **Points:** 490
- **Author:** Garlic
- **Flag:** `csaw{cleitus_the_black}`

---

## 1. Challenge Description

```
Comradery and brotherhood, fighting side by side. 
All put to an end over a clouded fight. 
Two men fought, one left distraught.

Find the name of the other man.

Flag format: csaw{full_name_or_title_of_the_man}  (not case sensitive)
```

Title: **Like a Sword Through the Heart**

---

## 2. Analysis & Clue Mapping

The riddle describes an iconic historical confrontation between two sworn brothers-in-arms:

1. **"Comradery and brotherhood, fighting side by side."**
   - Refers to **Alexander the Great** and his close companion and cavalry commander, **Cleitus the Black** (c. 375 BC – 328 BC).
   - Cleitus had fought side-by-side with Alexander across his conquests. Notably at the Battle of the Granicus (334 BC), Cleitus saved Alexander's life by severing the arm of the Persian satrap Spithridates as he was about to strike Alexander from behind.

2. **"All put to an end over a clouded fight."**
   - In autumn 328 BC at Maracanda (modern Samarkand), during an intense banquet, both men were heavily intoxicated with wine.
   - An argument escalated as Cleitus praised Philip II and questioned Alexander's divine claims. Their minds clouded by alcohol and blind fury, a violent struggle erupted.

3. **"Two men fought, one left distraught."**
   - Alexander broke free from companions who tried to restrain him, seized a spear/javelin from a bodyguard, and thrust it through Cleitus's chest/heart.
   - The moment Cleitus fell dead, the intoxication evaporated and Alexander was overcome by immense remorse and grief. Alexander attempted suicide with the same spear, was restrained, and sequestered himself in his tent weeping and wailing for days, utterly distraught.

4. **"Find the name of the other man."**
   - The distraught survivor is Alexander the Great.
   - The other man is **Cleitus the Black**.

---

## 3. Flag Construction & Verification

Following the required format: `csaw{full_name_or_title_of_the_man}` (underscore-separated, lowercase):
- Target name / title: `cleitus_the_black`
- Full flag: `csaw{cleitus_the_black}`

Submission against CTFd via `./submit_flag.py 3 "csaw{cleitus_the_black}"` returned:
```json
{
  "success": true,
  "status": "correct",
  "message": "Correct"
}
```
