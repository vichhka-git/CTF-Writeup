# Helioform Relay

**Category:** Web · **Points:** 900 · **Flag:** `CSCTF{Nb7GoawAQJ8FX517ZfAund3C}`

## What the handout gives you

The challenge is a single address and a short brief: a telemetry relay exposes a
WebSocket mesh for customers and a legacy agent protocol for field equipment. Every
other page on the host is thin, but `/docs/hsp` and `/docs/session` describe the wire
format and the console authentication.

- `/docs/hsp` — the HSP frame: 4-byte magic `HSP1`, little-endian opcode (u16), flags
  (u16, bit 0 marks a reply), body length (u32), body.
- `/docs/session` — the console cookie format.
- `/console` — an operator console that answers 401.

## Walkthrough

1. **Read the protocol, then speak it.** `/mesh` is a WebSocket endpoint that negotiates
   two subprotocols. `hsp.ws.1` is the customer channel: HELLO `0x01`, PING `0x02`,
   SUBSCRIBE `0x03`, which returns one line of telemetry. `hsp.raw.1` is the legacy
   agent channel: after the 101 the socket carries raw HSP frames, and its HELLO reply
   advertises `commands=HELLO:0x01,PING:0x02,DIAL:0x10` with `egress=127.0.0.1`.

2. **Notice what DIAL does not check.** The docs claim the agent socket authenticates
   an agent. It does not. Sending opcode `0x10` with a body of `host:port` returns
   `ok splice` and the socket becomes a byte pipe to that target. The egress filter is
   applied to the literal host string, so anything other than `127.0.0.1` is refused
   (`err: egress denied`), but no credential of any kind is required.

3. **Find what listens on loopback.** A dial costs one round trip, so a sequential scan
   is slow but a pipelined one is not: keep a single agent socket open and send DIAL
   frames in batches, reconnecting only after a hit (a successful dial consumes the
   socket). The public port is 8080; the same sweep finds four more — 7710, 7711, 7712
   and 7713.

4. **Ask each service what it is.** HELLO on 7710 returns `catalogd` with a nonce and a
   small opcode table (`ticket_opcode=0x20`, `export_opcode=0x30`, `status_opcode=0x40`).
   7711 is `provd dotenv broker`, 7712 is `recordd` with `write=peer-only`, and 7713
   answers `err: peer handshake required`.

5. **Redeem the ticket.** Sending opcode `0x20` to 7710 with the advertised nonce as the
   body returns `ticket=tkt.<nonce>.<32 hex>` with a 600-second TTL.

6. **Spend it on the dotenv broker.** `provd` takes `key=value` lines with `ticket=` and
   `path=`. The extension check runs before the path check, and the path is cleaned, so
   traversal is refused; but the provision root is `/etc/helioform` and the file you want
   is `relay.env`. It contains `CONSOLE_MAC_KEY`, `CONSOLE_ISS`, `CONSOLE_AUD`,
   `REPLICATION_MAC_KEY` and `MESH_CAPTURE_ENABLED=1`, with a comment explaining that the
   console and the replication MAC fall back to these values when the site has no
   hardware keystore.

7. **Forge the console session.** `/docs/session` says the cookie is
   `base64url(payload).hmac_sha256(key, base64url(payload))` in lower-case hex, where the
   payload is `{"iss","aud","role","exp"}` and the key is the literal environment string,
   not its hex decoding. With `helioform-factory` / `relay-console` / `admin` you get a
   200 from `/console`. Only `admin` is accepted.

8. **Read the replication protocol on the console.** `/console/trace` documents
   `hsp-repl/1` and can capture traffic: hello carries a peer name, an epoch, a 32-byte
   tip and a MAC; blobs carry the stream id, a mode byte, the epoch, the tip, a bind
   value, the body and a MAC. Mode `0x01` replaces the resolved stream file with the
   body. `/console/automation` shows the runbook directory
   `/var/lib/helioform/runbooks`, the required first line `HSP-RUNBOOK`, and that
   "compliance actions are files the scheduler executes as the relay user".

9. **Write into the replication stream.** `recordd` on 7712 hands out the current epoch,
   tip and bind at opcode `0x40`. Dial 7713, complete the peer hello with a MAC keyed by
   `REPLICATION_MAC_KEY` (again as ASCII), then send a blob with mode 1. The tip rotates
   on every accepted write, so re-read the status between writes if you need more than
   one.

10. **Walk out of the sandbox.** `recordd` can only create files under `/tmp` and
    `/dev/shm`; every other path returns `err: open failed`. Its own mount namespace has
    the runbook tree read-only, but PID 1's root does not: a stream id of
    `/proc/1/root/var/lib/helioform/runbooks/probe.runbook` is accepted.

11. **Execute.** The scheduler runs the remainder of a runbook as Python, as
    `uid=999(helio)`, and `/console/automation` prints the output. A first line of
    `HSP-RUNBOOK` followed by a short Python body that reads `/flag` prints the flag.
    `/flag` is a symlink, and resolving it from recordd's own namespace would not have
    worked — which is why the runbook route is the one that matters.

## Answer

The runbook output on `/console/automation` contains
`CSCTF{Nb7GoawAQJ8FX517ZfAund3C}`.

## Notes

Two details cost time. The first is that the documentation's claim about agent
authentication is false — the DIAL opcode is the whole attack surface. The second is
that the runbook has to be Python: a shell body fails with `SyntaxError: invalid syntax`
on line 2 and the console prints the traceback instead of the flag.
