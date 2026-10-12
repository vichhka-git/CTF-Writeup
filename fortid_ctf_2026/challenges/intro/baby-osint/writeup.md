# FortID CTF 2026 Writeup: Baby OSINT

- **Category:** Intro
- **Challenge author:** laragrr, ipaljak
- **Points / Solves:** 362 pts / 8 solves
- **Flag:** `FortID{hodaj_za_liku_hodaj_za_hrvatsku:zegevege:wednesday:909}`

---

## Challenge

> Answer these questions to become an honorary Purger:
>
> 1. What is the exact official name of the event in the image?
> 2. Which food festival was taking place in Zagreb on the same date?
> 3. [This video](https://www.tiktok.com/@anci26.7_/video/7542843600665644290) shows our mayor attempting to ride one of the newly introduced public bikes. Which day of the week has the largest average number of rides?
> 4. What was the highest number of those bikes recorded at one location at the same time?
>
> Flag format:
>
> `FortID{q1:q2:q3:q4}`
>
> For each answer:
>
> - use lowercase English letters
> - replace spaces with underscores
> - omit punctuation and special characters
>
> Example:
>
> `FortID{barrakud_croatia:inmusic_festival:day:8856}`

---

## Summary

The challenge requires answering four questions relating to contemporary events and public bike data in Zagreb, Croatia. The answers are formatted into a single colon-separated flag `FortID{q1:q2:q3:q4}`.

## Solution

### Question 1: Official Event Name
- Handout image `handout.jpeg` contains EXIF timestamp `2026-09-05 12:03:02 +02:00` and visual landmarks (Bollé meteorological post and fountain in Park Josipa Jurja Strossmayera / Zrinjevac, Zagreb, with banners reading "IVANJA REKA UZ LIKU").
- On September 5, 2026, the civic initiative "Gospić je naš dom" organized a major protest march against illegal hazardous waste dumping in Lika.
- The official name of the event was **"Hodaj za Liku, hodaj za Hrvatsku!"** (`hodaj_za_liku_hodaj_za_hrvatsku`).

### Question 2: Food Festival in Zagreb
- On the same date (September 4–6, 2026), the 18th **ZeGeVege festival** took place at Europski trg in Zagreb. The organizers (Prijatelji životinja) actively supported the "Hodaj za Liku" march.
- Formatted as `zegevege`.

### Question 3: Day with Largest Average Rides
- The linked TikTok video shows Mayor Tomislav Tomašević riding Zagreb's new "Bajs" public bike system.
- Public telemetry for the fleet is hosted at `https://bajs.informacija.hr/`.
- The `weekdayDistribution` metric shows **Srijeda (Wednesday)** with the highest average number of trips (17,493.5).
- Formatted in English as `wednesday`.

### Question 4: Highest Number of Bikes at One Location
- During the INmusic festival on Jarun (June 23, 2026), a temporary Bajs station was deployed.
- Reports and telemetry documented a record gathering of **849 standard bikes** plus **60 child-seat bikes**, totaling **909 bikes** present simultaneously at the Jarun station.
- Formatted as `909`.

### Solve Script

```python
#!/usr/bin/env python3
q1 = "hodaj_za_liku_hodaj_za_hrvatsku"
q2 = "zegevege"
q3 = "wednesday"
q4 = "909"
flag = f"FortID{{{q1}:{q2}:{q3}:{q4}}}"
print(flag)
```

## Flag

```
FortID{hodaj_za_liku_hodaj_za_hrvatsku:zegevege:wednesday:909}
```
