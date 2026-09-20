# High_tide - Writeup

- Category: OSINT
- Challenge ID: 41
- Author: Garlic
- Flag: `csaw{mont_saint_michel}`

## Challenge Summary

The challenge provides a single image `high_tide.png` with the prompt:
> "As per popular request, we present to you guys High_tide!! flag format: csaw{name_of_place} (not case sensitive)"

## Investigation & Solution

1. **Visual Clues & Geolocation Analysis:**
   - The image `high_tide.png` depicts a round stone fortification tower with putlog holes and a horizontal stone torus/string course molding near the top.
   - Atop the tower flies a tall flagpole with the **French national flag** (blue, white, red tricolor).
   - In the background, slate-roofed buildings with stone mullioned windows and ascending rampart walls are visible, along with an arched gate at the lower left of the tower base.
   - At the bottom of the image, Google Maps navigation arrows (`<`, `>`) and the text "Google Maps" reveal that the screenshot was captured from a Google Street View panorama/photosphere.

2. **Connecting the Title and Landmark:**
   - The challenge is titled **High_tide**.
   - In France, the most globally renowned tidal landmark is **Mont Saint-Michel** (Normandy), famed for having the highest tidal range in continental Europe (up to 15 meters) where the high tide famously turns the mount into an island.
   - Examining the fortifications of Mont Saint-Michel on Google Maps and architectural archives:
     - The main entrance to the village of Mont Saint-Michel is the **Porte du Roi** (King's Gate), topped by the **Logis du Roi** (housing the local town hall / mairie).
     - Directly flanking the Porte du Roi is the **Tour du Roi** (King's Tower), a 15th-century cylindrical granite tower with a flat upper terrace flying the French national flag.
     - The exact scene matches the Google Street View capture facing the Tour du Roi and Porte du Roi entrance at Mont Saint-Michel.

3. **Flag Construction:**
   - The flag format is specified as `csaw{name_of_place}` (case-insensitive, underscore separated).
   - Using the place name `mont_saint_michel` yields:
     ```
     csaw{mont_saint_michel}
     ```

4. **Verification & Submission:**
   - Submitting via `submit_flag.py 41 csaw{mont_saint_michel}` returned:
     ```json
     {
       "success": true,
       "status": "correct",
       "message": "Correct"
     }
     ```
