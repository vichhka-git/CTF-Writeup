# FortID CTF 2026 Writeup: Baby Web

- **Category:** Intro
- **Challenge author:** dsantl
- **Points / Solves:** 107 pts / 351 solves
- **Flag:** `FortID{w3b_15_n07_7h47_h4rd_45_y0u_7h1nk_17_15}`

---

## Challenge

> The flag is only one click away... if you can catch it! 🏃

---

## Summary

A standalone `index.html` whose "Show me the flag" button runs away on `mouseenter`.
The flag is assembled entirely client-side in the click handler: three string
chunks are concatenated, reversed, and passed to `atob`. Reading the script is
the whole solve.

## Solution

### Step 1: Read the click handler

The handler in `index.html` never touches the network:

```js
button.addEventListener("click", () => {
  const scrambled = [
    "=0XNx81Nx81auFDa38Vdwk3",
    "X1QzXkJHNo91N0g2NfdDMu9V",
    "Nx8lYzc3eElEdy9mR"
  ].join("");
  output.textContent = atob([...scrambled].reverse().join(""));
  ...
});
```

`atob` consumes standard base64, so the reversal is just a direction flag:
reverse the joined string, base64-decode, done. No browser interaction required
(the `mouseenter` dodge is a red herring).

### Step 2: Decode

```python
import base64, re
from pathlib import Path

html = Path("index.html").read_text()
block = re.search(r"scrambled\s*=\s*\[(.*?)\]\.join", html, re.S).group(1)
scrambled = "".join(re.findall(r'"([^"]*)"', block))
print(base64.b64decode(scrambled[::-1]).decode())
```

Full re-runnable script: `solve.py`.

## Flag

```
FortID{w3b_15_n07_7h47_h4rd_45_y0u_7h1nk_17_15}
```

## Lessons

- Client-side "protection" (a fleeing button, obfuscated string) is decoration:
  the secret ships to the browser in plaintext and the decoder ships with it.
- When JS builds a secret, extract the literal and reproduce the transform
  offline — faster and more reliable than driving the browser.
