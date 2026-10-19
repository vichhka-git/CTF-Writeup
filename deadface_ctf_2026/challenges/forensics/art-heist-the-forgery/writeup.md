# Art Heist: The Forgery

- **Category:** Forensics
- **Points:** 25

## Challenge

The Turla Museum recently welcomed back five paintings from its Cyber Impressionism collection following a loan to a neighboring gallery. But museum officials have received intelligence suggesting that DEADFACE infiltrated the gallery during the exhibition and secretly replaced one of the original paintings with a forgery. All five paintings were scanned and entered into the museum's digital archive upon their return. Although the artwork appears authentic, investigators suspect that the forger left behind traces of their work in the digital records. The museum has provided copies of all five 

## Solution

CONFIRMED | the team extracted the zip to its own scratch dir and ran exiftool across all five paintings. Painting_002.png is the outlier on four independent axes: Software = "LAMIA Restoration Utility 0.0.13" while the other four are uniformly "Atelier Archive"; Comment = "checksum mismatch; palette recovered from cache"; CreateDate = 1503:04:01 against 1888-1895 for the rest; and XMP dc:Identifier literally carries deadface{L4MIA_SIGNS_HER_WORK}. Reached independently and identically by BOTH the team and the team (duplicate claim - my scheduling error, not theirs), and now by me, so three independent derivations agree. | the team
