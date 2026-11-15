# DEStruction (crypto) — 2 flags

**Flags:**
`PP{D3S_c4nn07_s4v3_7runc473d_GCM_fr0m_c0llisi0ns::GsrCB0dEx3vv}`
`PP{w0w_y0u_r34lly_br0k3_D3S_GCM_4u7h3n7ic47i0n::c6SDP9GuViyU}`

A "backup transmission" service: messages are sent as
`msg || tag` where the tag is an authenticator computed over a
DES-based hash/compression design, **truncated to 1 byte** (`TRUNCATE_BYTES=1`
→ 15-byte tags from a 16-byte digest), and the internal key/IV is partially
revealed: two of the four 32-bit state words (`c0`, `d0`) are included in the
transmission, while `a0`, `b0` (64 bits) stay secret and are drawn fresh per
connection.

## Recon

1. Connect to the TCP service. Note the fields: a 24-byte prefix, a payload,
   and a 15-byte tag.
2. Recover the model: the digest is a Davies-Meyer style compression over a
   DES round structure, run with `iterations=2` over the block, IV =
   `(a0, b0, c0, d0)`, and the tag = digest minus its last byte.

## Flag 1 — forge an authenticated command

The server accepts admin commands whose tag verifies. The trick: you cannot
invert the digest, but you don't need to — you only need **a collision on the
truncated tag** for the command you want.

1. Harvest a large set of observations `(block, tag)` from the service with
   the same connection (same secret IV words).
2. Model the compression in a SAT solver (the DES round structure converts to
   CNF/SAT cleanly; ~8k variables / ~27k clauses per observation).
3. Append the wanted phrase (e.g. `give me a flag!` padded to the block size)
   and solve for the two unknown state words such that the truncated digest of
   your forged block matches one of the observed tags (multi-target: any of
   your captured tags works).
4. Send the forged message. The 15-byte tag verifies and the server runs the
   command → flag 1.

`PP{D3S_c4nn07_s4v3_7runc473d_GCM_fr0m_c0llisi0ns::GsrCB0dEx3vv}`

## Flag 2 — recover the secret state with the length-extension oracle

The service exposes a subtle **extension oracle**: you may feed batches of
candidate continuations and observe (by whether the server accepts) which one
extends the chain correctly — each accepted candidate reveals one byte of the
current digest state.

1. For a held connection, take a known tag and enumerate 256 candidate bytes
   for the missing (truncated) byte: the correct one can be confirmed by
   extending the message by one block and observing acceptance.
2. Iterate: each recovered byte extends the known digest suffix, giving a
   growing multi-target constraint set on the unknown 64-bit `(a0, b0)`.
3. With enough recovered bytes, a SAT model over the compression structure
   (constrained by all observations plus the recovered digest bytes) becomes
   solvable — the recovered 64-bit value `H` authenticates you fully.
4. Replay the protocol with the recovered state to obtain flag 2.

`PP{w0w_y0u_r34lly_br0k3_D3S_GCM_4u7h3n7ic47i0n::c6SDP9GuViyU}`

## Notes

- All observations for one connection share the same `(a0,b0)`; extra tags
  only reject false positives (still 2^64 generically), which is why the
  oracle-assisted byte recovery is the practical path.
- The solver workload is heavy (CNF with ~8k vars); budget several CPU cores
  and run the models incrementally (assume one tag at a time).
