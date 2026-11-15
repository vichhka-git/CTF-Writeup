# Sign Post (osint)

**Flag:** `PP{any0ne-w4nts-to-h1k3-n0w?::_yBN0c-PNe9N}`

## Steps

1. The challenge photo shows a wooden signpost at an alpine pass, with a
   white top plate reading **"Peiljoch 2676 m"** and yellow directional signs
   to **Dresdner Hütte (1 1/2 h)** and **Sulzenauhütte (DAV Sektion
   Leipzig)**.

2. Those hut names pin it to the **Stubaier Höhenweg (trail 502)** in the
   Stubai Alps, Tyrol, Austria — the section between Dresdner Hütte and
   Sulzenauhütte over the **Peiljoch / Beiljoch** pass (2676 m).

3. OpenStreetMap has the exact guidepost: node **9088505277**
   (`information=guidepost`) at `46.9922643, 11.1542146`
   (the saddle node 295209986 sits at `46.9922748, 11.1541140`).

4. The challenge's location picker (on the instance) expects

   ```
   POST /check_location  {"lat": 46.9922643, "lng": 11.1542146, "messageState": true}
   ```

   Rate limit: 3 submissions/minute. The correct point passes the tolerance
   and the response contains the flag.
