# File Viewer

Web, 68 points, 168 solves. A small file viewer: you upload a ZIP, the server
extracts it under a per-upload directory, and the result page lists the members
as links. The flag sits on the container filesystem, so the viewer has to be
turned into a file read.

## What you are given

The portal supplies `<challenge-host>` and `<port>` for a per-team instance.
The root page is titled Zip Checker and holds a single form: POST /analyze,
multipart, field name `file`, and the label asks for a ZIP. Our captures carry
`Server: Werkzeug/3.1.9 Python/3.12.3`, so the backend is Flask. There is no
source and no handout, and the challenge description is one line: "Upload a file
and explore the results."

## Reproduction

1. Confirm the upload contract. GET / returns the form. A benign ZIP with one
   text member is accepted with HTTP 200 and the response is an HTML table whose
   row links to `/<upload-id>/<member>`. The upload id differed between our two
   uploads and appears only in that response, so parse the link out of the HTML
   rather than guessing it.

2. Fetch a member immediately after the upload, using the same HTTP session. In
   our baseline test the exact member URL fetched from a separate client
   returned 404 with a 10-byte body, `Not Found.`. Every fetch that worked in
   this challenge was made with the session that uploaded the archive, so keep
   the cookie jar across the POST and the GETs.

3. Work out what extraction preserves. A ZIP central directory entry can be
   marked as a Unix symlink: set the high byte of "version made by" to 3 and the
   top 16 bits of the external attributes to `0o120777`, then store the link
   target as the member data. The extractor writes a real symlink. Nothing in
   the upload path checks what the link points at.

4. Point links at candidate paths. Our archive held eight entries named
   `/s1-loc-01.txt` through `/s1-loc-08.txt`, each a symlink. The targets were
   `/flag`, `/flag.txt`, `/app/flag`, `/app/flag.txt`, `/proc/self/environ`,
   `/proc/1/environ`, `/app/app.py` and `/app/main.py`. Entry construction is
   four lines:

   ```
   info = zipfile.ZipInfo("/s1-loc-04.txt")
   info.create_system = 3
   info.external_attr = 0o120777 << 16
   zf.writestr(info, "/app/flag.txt")
   ```

   The leading slash in the member name is kept in the generated link, so the
   result page shows a double slash, for example `/<upload-id>//s1-loc-04.txt`.

5. Upload and follow the links. POST /analyze with the archive returns HTTP 200
   and a table of eight links. Fetched in the upload session, the first three
   targets returned 404 with the 10-byte `Not Found.` body, which is consistent
   with `/flag`, `/flag.txt` and `/app/flag` not existing in the container.

6. Read the hit. The fourth link returned HTTP 200 with
   `Content-Type: text/plain; charset=utf-8`, `Content-Length: 30` and
   `Content-Disposition: inline; filename=s1-loc-04.txt`. The body was the flag.
   That confirms `/app/flag.txt` is the flag path on this image and that the
   symlink was followed at serve time.

7. What we did not learn. The batch loop stopped on the first flag match, so
   `/proc/self/environ`, `/proc/1/environ`, `/app/app.py` and `/app/main.py` were
   never fetched in that run. A separate probe aimed at `/proc/self/cmdline`
   returned an empty body. Whether environment or source reads work on this
   instance is not established by the local notes.

The team submission log has a `goodFlag` row for this challenge whose mechanism
field describes this chain: a ZIP with absolute-name symlink entries, fetched in
the same session, with `/app/flag.txt` served through the symlink. The request
and response captures named in that row are the ones summarised above.

## Why it works

The extractor trusts the archive to describe ordinary files and preserves
symlinks as symlinks. The download route then opens the member path and follows
the link, so the link target decides what is served. The containment thinking in
the app is applied to member names during extraction, not to the resolved path
when the file is served, and an absolute target sidesteps the per-upload
directory entirely. Marking a member as a symlink to `/app/flag.txt` turns a
viewer into an arbitrary file read. A correct fix is to refuse symlink entries
and to `realpath` the served file and reject anything outside the extraction
directory.

## Flag

```
hiCTF{E45Y_5yml1Nk_8b91346d2f}
```
