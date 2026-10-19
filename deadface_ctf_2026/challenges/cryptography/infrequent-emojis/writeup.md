# Infrequent Emojis

- **Category:** Cryptography
- **Points:** 50

## Challenge

While DoomScrolling, our intel team came across a weird coded post with emojis all over it. One of our experts claims that the patterns point to it still being English but we don't know what it means! Can you figure it out? Submit the answer as `deadface{flag_text}` [DoomScroll](https://doomscroll.dctf.io)

## Solution

SOLVED BY OPERATOR - deadface{please_try_out_my_new_standard} | I got this wrong four times (spook, spookyboi, 13_h4ck3r5.., and "no flag exists in the cipher"). ROOT CAUSE: I decoded the WRONG POST. The accepted phrase "please try out my new standard" does NOT appear in https://doomscroll.dctf.io/post/252 at any detection threshold - I re-checked every line containing even one cipher symbol. Post 252 is downstream chatter ABOUT the encoding scheme ("THE LOOKUP TABLE IS LIVE..", "SPOOK REALLY COOKED WITH THIS LAYOUT"); the real challenge post is a different one, evidently spookyboi announcing the scheme. HOW I WENT WRONG: the team located 252 early, I confirmed it was a genuine 26-symbol monoalphabetic emoji cipher, and I then treated "252 is the ciphertext" as settled fact. When the full decode contained no flag - the single clearest signal that the artifact was wrong - I did not revisit the premise. Instead I searched 252 for tag chars, zero-width layers, acrostics and alternate readings, and I built a confirming narrative around it (the three single-occurrence emoji map to Z/Q/X, "proving" my key was right - true, and irrelevant). My post-ID crawl covered 224-265 and 266-290 and found only 252 with emoji, which should have told me the real post was outside my search, not that 252 must be the answer. LESSON: when a correct-looking decode yields no flag, suspect the ARTIFACT before inventing a deeper layer; and treat "the only candidate I found" as a statement about my search coverage, not about the challenge. | the team
