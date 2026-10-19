# Death

- **Category:** OSINT
- **Points:** 100
- **Flag:** `deadface{Travis}`

## Challenge

What is `d34th`'s first name? Submit the flag as `deadface{John}`

## Solution

The question asks for one operative's real first name. Profiles on the DoomScroll social site expose real names (another handle resolves to a full name and city there), but this operative has no account. The route is indirect: a GhostTown thread asks his permission to post a photo of him wearing distinctive yellow-lensed glasses, promising a specific caption and explicitly no tag. Searching DoomScroll for that exact caption finds the post. The post is untagged as promised, but its stored metadata retains the original upload FILENAME, which is the operative's first name plus a counter. The untagged photo betrays him through the filename.
