## 15 — The Browser Never Forgot (DFIR)

1. Open the Chrome `History` SQLite database from the supplied evidence.
2. Query the `visits` table. Visit 1 is `portal.html`. Visit 3 is `download.html` and has `from_visit = 2`, but visit 2 is missing.
3. Query the `urls` table. URL id 2 is `http://127.0.0.1:8000/review.html`.
4. Query the `downloads` table. The row has `tab_referrer_url = http://127.0.0.1:8000/review.html`, `state = 1` (complete), and `start_time = 13436144162088011`.
5. Convert the Chrome timestamp from microseconds since 1601-01-01 to UTC. The download completed at `2026-10-10 22:16:02`.

`TVX{2,http://127.0.0.1:8000/review.html,completed,2026-10-10_22-16-02}`
