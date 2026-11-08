# warden

**Category:** misc · **Points:** 450 · **Flag:** `CSCTF{rhDUqWPcMW7z7T1rqrQw6cxL}`

## What the handout gives you

A tar archive containing the source code for a secured Python remote execution service.

- `warden.tar.gz` — archive containing `jail.py` (3,059 bytes).

The service accepts a single line of Python code over a network connection, compiles it, installs a custom audit hook, and executes it inside an empty builtins dictionary.

## Walkthrough

### 1. Analyze the security barriers

Examine `jail.py`. Incoming input passes through three validation layers before completion:

1. Static AST inspection: `check()` verifies that the submission is a single line of at most 4,096 characters, parses without syntax errors, and contains no `ast.Import` or `ast.ImportFrom` nodes.
2. Restricted execution namespace: `exec(code, {"__builtins__": {}})` executes the compiled code without standard built-in functions such as `open`, `print`, `__import__`, `eval`, or `dir`.
3. Runtime audit hook: `seal()` registers an audit hook with `sys.addaudithook()`. The hook kills the process via `os._exit(1)` on any event except `object.__getattr__` and the jail's initial `exec`.

Any attempt to open files (`open`), import modules (`import`), run subshells (`subprocess`), compile dynamic code (`compile`), or trigger secondary execution terminates the process immediately.

### 2. Identify permitted runtime behaviors

The audit hook allows `object.__getattr__`. In Python, traversing dunder attributes (`__class__`, `__base__`, `__subclasses__`, `__globals__`) triggers only attribute lookups, which pass the audit filter.

The challenge states that the secret is stored on the machine. Because filesystem calls emit audited `open` events, the flag resides in memory within the process environment. Reading dictionary keys from `os.environ` triggers no Python audit events.

Standard output writes via `sys.stdout.write()` also bypass audit hooks, providing a channel to return data without calling the removed `print()` built-in.

### 3. Reach loaded modules via subclasses

Without built-in functions, module references must be recovered by walking the object hierarchy from an empty tuple literal:

`().__class__.__base__.__subclasses__()`

This returns a list of all active classes in the Python runtime. Several standard library classes retain references to their defining module globals in `__init__.__globals__`. The `Quitter` helper class from the preloaded `site` module is present in the list:

`[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == 'Quitter'][0]`

Accessing `Quitter.__init__.__globals__` yields the global dictionary of `site.py`, which holds a direct reference to the `sys` module under key `'sys'`.

### 4. Extract environment variables

With the `sys` module in hand, retrieve the preloaded `os` module from the module cache:

- `s = a['sys']`
- `o = s.modules['os']`

Looking up `'os'` inside `sys.modules` returns the existing module instance without triggering an `import` audit hook event.

Because `str()` and `repr()` do not exist in the empty builtins namespace, invoke the instance method `.__repr__()` directly on `o.environ` and stream it to standard output:

`a=[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='Quitter'][0].__init__.__globals__; s=a['sys']; o=s.modules['os']; s.stdout.write(o.environ.__repr__()); s.stdout.write('\n'); s.stdout.flush()`

## Answer

Connect to the service and send the constructed one-line payload:

`nc <host> <port>`

The command runs without triggering any audit hook violations, outputting the entire environment mapping:

`environ({'PATH': '/usr/local/bin:...', 'FLAG': 'CSCTF{rhDUqWPcMW7z7T1rqrQw6cxL}', ...})`

The flag is:

`CSCTF{rhDUqWPcMW7z7T1rqrQw6cxL}`

## Notes

Attempting to read disk files via `open()` or `os.open()` triggers the `open` audit event, causing the hook to display `[warden] I heard that: open` and terminate. The flag was located in `os.environ` because in-memory dictionary lookups produce no audit trail.

Calling `repr(o.environ)` raises a `NameError` because `repr` is absent from `__builtins__`. Calling the method explicitly as `o.environ.__repr__()` succeeds because method resolution operates directly on the object's type dictionary.
