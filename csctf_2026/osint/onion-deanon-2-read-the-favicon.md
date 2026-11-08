# Onion Deanon 2: Read the Favicon

**Category:** OSINT · **Points:** 126 · **Flag:** `CSCTF{-209798607}`

## What the handout gives you

The challenge supplies no downloadable archive file. The briefing text provides two intelligence excerpts regarding an extortion campaign operated by the DarkPigeon ransomware group:

- A leak forum announcement detailing a breach against Coop & Crumb Birdseed Wholesalers with 87 GB of exfiltrated data and a link to a Tor hidden service: `http://schpqwdfzcmdcbim7w24jj5ph5h6fqvcbj5zhkhof3z3v75ydljkzsad.onion`.
- An email from the victim company IT manager asking for the hosting location of the hidden negotiation site to support a legal takedown notice.

The objective is to download the favicon served by the onion service and calculate its hash matching Shodan indexing rules.

## Walkthrough

1. **Access the hidden service over Tor.** Connecting directly to `.onion` hostnames requires routing traffic through Tor. Starting a local Tor daemon opens a SOCKS5 proxy on `127.0.0.1:9050`. Request the site root through the proxy:

```bash
curl -s --socks5-h 127.0.0.1:9050 http://schpqwdfzcmdcbim7w24jj5ph5h6fqvcbj5zhkhof3z3v75ydljkzsad.onion/
```

The response returns an HTML document titled `DarkPigeon | Negotiation Portal`. Line 7 of the document head declares the site icon:

```html
<link rel="icon" href="/favicon.ico" type="image/x-icon">
```

2. **Download the favicon.** Fetch the `/favicon.ico` path through the Tor SOCKS proxy and save the binary locally:

```bash
curl -s --socks5-h 127.0.0.1:9050 http://schpqwdfzcmdcbim7w24jj5ph5h6fqvcbj5zhkhof3z3v75ydljkzsad.onion/favicon.ico -o favicon.ico
```

The server returns HTTP status 200 OK with `Content-Type: image/x-icon`. The resulting file is 6,434 bytes.

3. **Format the favicon for Shodan hashing.** Shodan indexes favicons under the `http.favicon.hash` search filter. Its ingestion pipeline does not compute the hash directly on raw icon bytes. Shodan first converts the binary file into MIME Base64 formatting (RFC 2045):
- The binary payload is Base64-encoded.
- Newlines (`\n`) are inserted every 76 characters.
- A trailing newline terminates the data.

Encoding the 6,434-byte binary with MIME line wrapping expands the file into an 8,693-byte ASCII string.

4. **Compute the 32-bit MurmurHash3 value.** Shodan hashes the Base64 representation using the 32-bit x86 variant of MurmurHash3 with a seed of zero. Calculating the unsigned 32-bit hash on the 8,693-byte string yields `4085168689` (`0xF37FE62F`).

5. **Convert to a signed integer.** Shodan stores its MurmurHash3 values as signed 32-bit integers. Because the most significant bit (bit 31) of `0xF37FE62F` is set, interpreting the integer as signed two's complement subtracts `2^32`:

`4085168689 - 4294967296 = -209798607`

A one-line command confirms the calculation:

```bash
python3 -c 'import base64, mmh3; print(mmh3.hash(base64.encodebytes(open("favicon.ico", "rb").read())))'
```

The command prints `-209798607`.

## Answer

The Shodan favicon hash for the DarkPigeon negotiation portal is `-209798607`. Wrapping the value in the challenge format produces the flag:

`CSCTF{-209798607}`

## Notes

Three formatting discrepancies frequently break Shodan favicon hashes:
- Hashing raw binary bytes directly instead of Base64-encoded data produces an incorrect hash (`29357865`).
- Using standard Base64 encoding without RFC 2045 line wrapping (`base64.b64encode` without newlines every 76 characters) omits the 113 newline bytes and produces `-1362675922`.
- Omitting the two's complement conversion leaves the unsigned representation `4085168689`, which the challenge rejector flags as invalid.
