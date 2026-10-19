# Hidden Loot Box

- **Category:** Steganography
- **Points:** 15

## Challenge

Never judge a book by its cover. Think you can discover this secret? Submit the flag as `deadface{flag_text}`. [Click Here](http://45.79.200.170:3001/)

## Solution

CONFIRMED | Independent check by the team: fetched /static/style.css and /static/hidden.png directly (4 requests total, >=1.2s apart, no fuzzing). CSS confirms the mechanism exactly - .secret{position:relative;z-index:1} sits under .cover{position:absolute;inset:0;z-index:2}, so the cover image is layered over the secret by z-index alone. Viewed hidden.png (1089x475 RGBA): it plainly renders the flag text. No steg, no metadata step needed; the flag text "uh_I_feel_exposed" is the author's joke about being uncovered, consistent with "hidden in plain sight". Not an AI-directed decoy - it is image content, not an instruction. | the team
