# Stillwell Estates

Web, 74 points, 129 solves. A boutique brokerage site with an "agent import
studio" that accepts Brotli-compressed partner exports and previews the listing
documents attached to them. A restricted closing ledger sits outside the partner
document library. The task is to find the authorization token.

## What you are given

The portal supplies `<challenge-host>` and `<port>`. The site has a normal
listing front end and an agency overlay at `/agency`. The studio accepts a
Brotli-compressed JSON manifest of format `stillwell.agency-export/1`, posted to
`/api/agency/import/preview` with `Content-Type: application/json` and
`Content-Encoding: br`. A sample export is linked as `/assets/sample-export.br`
and decompresses to:

```
{"format":"stillwell.agency-export/1","properties":[
  {"title":"Meadow House","neighborhood":"Greenpoint","price":990000,"document":"welcome.txt"},
  {"title":"Moorland Loft","neighborhood":"Williamsburg","price":1275000}]}
```

The `document` field is the interesting one. The sample shows that a property
may name a supporting document, and the server resolves that name from its
partner document library. The organizers did not provide source. Our evidence
directory holds `server.js` recovered from the instance, which is how the sink
became visible.

## Reproduction

1. Open the studio and take the sample. `GET /agency` shows the import form, and
   `/assets/sample-export.br` decompresses with `brotli -dc` to the manifest
   above.

2. Post a manifest with a document name. Build the JSON, compress it with
   `brotli -c`, and send it:

   ```
   curl -sS -X POST 'https://<challenge-host>:<port>/api/agency/import/preview' \
     -H 'Content-Type: application/json' \
     -H 'Content-Encoding: br' --data-binary @payload.br
   ```

   The reply has `count`, `message` and `sample`, and each sample row may carry
   `document: {name, excerpt}` or `document: {error}`.

3. Confirm the file read with a harmless absolute path. Setting
   `"document":"/etc/passwd"` returned an excerpt beginning `root:x:0:0`. A
   normal name such as `welcome.txt` shows what a library hit looks like.

4. Read the process environment. `"document":"/proc/self/environ"` returned
   `PWD=/opt/stillwell`, `SECRET_DIR=/tmp/stillwell-private`, and the platform's
   flag variable, which is the value the validator expects.

5. Read the server source through the same sink.
   `"document":"/opt/stillwell/server.js"` returned the file. The relevant
   function is `resolvePartnerDoc(name)`: it rejects only names longer than 512
   bytes or names containing `..`, then calls `path.resolve(PARTNER_DOCS, name)`
   and reads the result. There is no check that the resolved path stays inside
   `PARTNER_DOCS`. Startup writes the ledger to
   `path.join(SECRET_DIR, 'escrow-ledger.txt')` with a line reading
   `Closing authorization: <flag>`.

6. Read the intended record. `"document":"/tmp/stillwell-private/escrow-ledger.txt"`
   returned the restricted ledger. The closing line, as printed on the
   instance, is:

   ```
   Closing authorization:  hiCTF{s1l3nt_l4n73rn_3573735_abd3e034f8}
   ```

   Two independent reads, the environment and the ledger, gave the same token.

7. Query the API directly, not the page. The server slices each excerpt to 8192
   bytes, but the studio UI prints only the first 120 characters of that
   excerpt. The authorization line sits past character 120, so a browser preview
   hides it. The API response carries the full excerpt.

## Submission note

The flag value arrived through the environment with a leading space, and the
ledger printed it verbatim after its own separator. Two trimmed submissions of
the same text were rejected as bad flags. The accepted submission carried the
leading space that came from the environment value. The visible flag is the one
printed below, without it.

What the local notes do not record: which brotli quality or window settings were
used, and the exact first request that revealed the ledger. They record the
`/etc/passwd` confirmation, the environment read, the source read and the ledger
read, in that order.

## Why it works

`path.resolve(base, name)` discards the base when the second argument is
absolute. An absolute document name therefore escapes the partner library
without ever containing `..`, which is the only traversal pattern the check
looks for. Validation is applied to the input string instead of the resolved
path. The sibling static file route in the same server does have a
`startsWith(PUBLIC + path.sep)` guard, so the containment pattern existed in the
codebase and simply was not used here. The function also distinguishes an
excerpt from a short error, which turns it into a clean file existence oracle on
top of the read. A correct fix is to resolve, then reject any result that does
not start with the library directory, and to serve documents from a fixed index
rather than by caller-supplied path.

## Flag

```
hiCTF{s1l3nt_l4n73rn_3573735_abd3e034f8}
```
