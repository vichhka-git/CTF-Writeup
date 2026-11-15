# Reverse Image Search (osint)

**Flag:** `PP{1-h4cK-7h3r3f0r3-1-4M::rYqSzgf5K37L}`

## Steps

1. The challenge provides a photo. Reverse-search it (Google Lens, Yandex,
   Bing) — the matching hit is an image that has been used in a known
   vulnerability/exploit context ("1-h4cK-th3r3f0r3-1-4M" — I hack,
   therefore I am).

2. The matched source identifies the original image: a photo published with
   a security-research writeup / vendor advisory about the very device or
   software pictured.

3. The flag format clue follows from the source name of the matched writeup
   — submitting the recovered phrase yields the flag.

*(Team note: the solve came from the OSINT pipeline matching the photo to its
original publication; keep the crop small and unique for better hits.)*
