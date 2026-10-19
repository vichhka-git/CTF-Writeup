# Hail Caesar

- **Category:** Cryptography
- **Points:** 5

## Challenge

One of the faculty at Night Veil University thought it would be clever to write sensitive information on notes by their computer. This sensitive information includes a very easy-to-decipher password hint. Judging by the drawing of a dog on the photo, we assume the password hint is the name of the individual's dog. Submit the flag with the dog's name as: `deadface{dog's name}` [Download PNG](https://deadface.sfo3.cdn.digitaloceanspaces.com/2026/challenges/crypto/crypto01/pass_hint.png) SHA256: `79f4e2dcda66b279397250ec0aeadd38f897bf64385522eb5390be4f48d7714c`

## Solution

CONFIRMED | the team read the sticky note in artifacts/pass_hint.png directly: "Zl qbt'f anzr vf Srgpu". ROT13 (Caesar shift 13) -> "My dog's name is Fetch". Answer is the dog's name, Fetch, capitalised as written on the note. The note's other line ("order more paperclips") is set dressing. | the team
