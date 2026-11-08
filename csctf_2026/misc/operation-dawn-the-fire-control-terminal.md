# Operation Dawn: The Fire-Control Terminal

**Category:** Misc · **Points:** 540 · **Flag:** `CSCTF{Fnk45qVdHXQolDzjCIOCzAZz}`

## What the handout gives you

A running terminal that evaluates Python expressions and prints the result. It refuses
anything that looks like an escape: a blacklist rejects `import`, `eval`, `exec`,
`compile`, `open`, `read`, `system`, `popen`, `getattr`, `setattr`, and the dunder names
used by the usual sandbox escapes, and the expression runs in a scope whose
`__builtins__` is an empty dictionary.

The description says the standing order is broadcast on the terminal's own host.

## Walkthrough

1. **Confirm the sandbox rules.** Send a plain expression and it evaluates. Send
   `open("/etc/passwd")` and the blacklist answers. Send `().__class__` and the dunder
   name is caught by the substring check.

2. **Find a construct the blacklist cannot see.** Blacklists match text; Python still
   has to create objects at runtime. A generator expression is a real function with a
   frame, and its frame has a `f_back` pointer to the frame that created it — the
   interpreter's own eval frame, which sits inside the server's request handling. None of
   the words needed for that (`gi_frame`, `f_back`, `send`) are on the list.

3. **Walk out to the caller.** Create a generator, prime it with `send(None)`, read its
   `gi_frame`, then take `f_back` one or two levels. You are now holding live objects from
   the server: the client connection socket, the `os` module and the `socket` module. The
   scope that was supposed to be empty no longer matters, because these objects carry
   their own references.

4. **Look around the host.** With the `os` module in hand, list `/opt`. A file named
   `sender.py` describes the broadcast: the command relay sends the standing order to
   `127.0.0.1:49513` over UDP once a second, with the authorisation code base64 encoded in
   the payload.

5. **Listen on the port.** From inside the same process, bind a UDP socket to
   `127.0.0.1:49513` and read one datagram. The broadcast arrives within a second; the
   payload carries the standing order and the encoded code.

6. **Decode and submit.** The code is URL-safe base64 with padding stripped. Decoding it
   gives the flag.

## Answer

`CSCTF{Fnk45qVdHXQolDzjCIOCzAZz}`

## Notes

Binding the port only works from the terminal's own host: the broadcast is to loopback,
so an outside listener never sees it. That is why the sandbox escape is the point of the
challenge — the order is not in a file you can read, it is in traffic you have to be
inside the container to catch.

The blacklist approach fails for the usual reason: it names syntax rather than
capabilities, and the runtime hands you capabilities the author did not think of.
