# Recon: Two Marks, One Score - Writeup

- Category: OSINT
- Challenge ID: 15
- Author: Rob Gilligan
- Flag: `csaw{N723KP}`

## Challenge Summary

The challenge provides two images from a target's surveillance archive/travel manifest:
1. `First_Image.png`: A classical building corner with a pediment, dentils, modillions, Corinthian/composite capital, and a conical brick bell tower visible in the background.
2. `Second_Image.png`: An entrance pillar/totem for the Los Angeles Metro with the "M Metro" logo next to a palm tree.

The brief states:
> "Except there is one, both coordinates were found in the target's travel manifest. Find out what operation they were casing. The answer is the identifier high in the sky on the day of the operation. We've tracked it to a potential man on the inside."

## Investigation & Solution

1. **Geolocation of Locations:**
   - **Image 2**: Reverse image search on the stock photo identified Shutterstock asset `763363768` by Tero Vesalainen, taken in Hollywood, Los Angeles, CA (specifically the Hollywood / Vine Metro station).
   - **Image 1**: Reverse image search and architectural feature analysis linked the pediment, Corinthian capitals, and the conical brick campanile to Venetian classical/Palladian ecclesiastical architecture, specifically corresponding to Venice, Italy (Chiesa del Santissimo Redentore / Venetian landmarks).

2. **Connecting the Cased Operation:**
   - The challenge title is *"Recon: Two Marks, One Score"*. In heist and con terminology, a "mark" refers to the target of a heist. The two locations cased by the crew are Venice, Italy and Hollywood/Los Angeles, California.
   - This directly points to the 2003 heist film ***The Italian Job*** (starring Mark Wahlberg as Charlie Croker):
     - The first heist / mark occurs in **Venice, Italy** (stealing $35M in gold bullion).
     - The second heist / mark occurs in **Los Angeles, California** (dropping the armored car into the Hollywood Metro subway tunnel to reclaim the gold).

3. **The Insider and the Sky Identifier:**
   - The "man on the inside" who betrays the crew is **Steve Frazelli** (Edward Norton).
   - On the day of the Los Angeles operation, Steve tracks the crew from "high in the sky" by piloting a black **MD Helicopters MD 500** helicopter (stunt piloted by Alan Purwin).
   - The tail registration identifier painted on the engine cowling/doghouse of this helicopter is **N723KP**.

4. **Flag Submission:**
   - Submitting `csaw{N723KP}` via `submit_flag.py 15 'csaw{N723KP}'` returned `{"success": true, "status": "correct", "message": "Correct"}`.
