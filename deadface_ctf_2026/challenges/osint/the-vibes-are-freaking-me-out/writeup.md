# The Vibes Are Freaking Me Out

- **Category:** OSINT
- **Points:** 75
- **Flag:** `deadface{A11_Th1s_Pr0mpt1ng_G3ts_M3_N0wh3r3!}`

## Challenge

We've received intelligence that a DEADFACE operative may have been using Al to create a browser extension that would enable them to communicate openly outside of the GhostTown forums using a new model called Maude. We need to find the tool they've built so we can find out what they're trying to hide from us. **Flag Format:** `deadface{N0t_Th3_Fl4g_Jus7_@n_3x@mpl3}`. The flag will appear in its entire form.

## Solution

The challenge intelligence indicates that a DEADFACE operative vibe-coded a browser extension with an AI assistant named **Maude** to enable hidden communications outside of GhostTown forums. On GhostTown, member `b1tfr34k` previously boasted in Thread 37 (*"I built something"*) about an extension named **`HIPS`** that hides messages in Unicode, admitting it was built with prompting assistance from Maude. Pivoting to `b1tfr34k`'s GitHub account (**`fr34ked0ut`**) locates the public repository `https://github.com/fr34ked0ut/HIPS`. Inside the `.maude` configuration folder, `.maude/skills/payload-gen/SKILL.md` documents a "crew token" stored reversed and base64-encoded ("LIKE MISSY ELLIOTT YOU MUST WORK IT"). Decoding and reversing the token `fSEzcjNodzBOXzNNX3N0M0dfZ24xdHBtMHJQX3MxaFRfMTFBe2VjYWZkYWVk` reveals the flag in its entire form: `deadface{A11_Th1s_Pr0mpt1ng_G3ts_M3_N0wh3r3!}`.
