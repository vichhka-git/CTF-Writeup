# Fishies (web)

**Flag:** `PP{h1jack1ng_th3_d3bugg3r_w1th_f1sh13s::Yceb0knvTEpm}`

A fish-collection web app with an admin bot (headless browser that visits
admin pages) and a Node/Express backend. The chain: stored XSS → prototype
pollution → Puppeteer env pollution → LD_PRELOAD → RCE → flag.

## Steps

1. **Stored XSS.** The fish "escape()" routine has an off-by-one that leaves a
   raw `<` in the stored name. Register a fish whose display name opens a
   script tag; the admin bot renders it → stored XSS in an admin-only page.

2. **Prototype pollution.** The admin API
   `PATCH /api/admin/fish/:id/fishData` accepts arbitrary JSON keys — send
   `__proto__` in the body to pollute `Object.prototype` on the server.

3. **Pollute `env`.** Set `Object.prototype.env` to an object of your choice.
   When the app spawns the admin bot, `puppeteer.launch()` reads
   `process.env`-shaped options through the polluted prototype chain — your
   values are inherited.

4. **Land a shared object.** Point the polluted env at the browser profile:
   `HOME=/app/static` makes Puppeteer write downloads into
   `/app/static/Downloads` (publicly served). From the XSS, trigger a blob
   download of your compiled `.so` (compile both arch flavors for arm64/x64)
   using `window.URL` — inline handlers must use `window.URL`, not bare
   `URL` (they resolve `document.URL`).

5. **LD_PRELOAD RCE.** The next bot launch inherits
   `LD_PRELOAD=/app/static/Downloads/<your>.so`; the library constructor
   copies `/flag.txt` to `/app/static/flagout.txt`.

6. Fetch `https://<site>/static/flagout.txt` → flag.
