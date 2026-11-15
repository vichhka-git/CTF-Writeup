# Glass Vault (misc) — 3 flags

A custom Veloren (open-source voxel MMO) server with an in-game quest
economy. Connect with a modified game client that can read dialogue and
teleport (`tp x y z`), because positions are client-authoritative for this
instance — "the world simply takes his word for where he stands".

**Flags:**
`PP{7h3_cl13n7_kn0w5_7h3_4n5w3r::M2MrNW6ssdsD}` (Bram)
`PP{4_k3y_70_rul3_7h3m_4ll::l-xzRJnfiD6R}` (Teller)
`PP{7h3_7r345ur3r5_7r345ur3::S3XTmOhUchpk}` (Sky Vault)

## Flag 1 — Bram the mason (rock-paper-scissors leak)

1. Log in with a fresh account (the server auto-creates a character) and walk
   to **Bram's tavern** (marker at map ~(5813, 5190)).
2. Interact with Bram: he challenges you to 20 consecutive RPS wins.
3. The server leaks Bram's throw: the dialogue `Question` message carries
   localized arguments, and the arg `throw` contains
   `"rock" | "paper" | "scissors"` (the same value is broadcast in chat).
4. Modify the client to read that argument and reply with the counter:
   rock → paper (response id 1), paper → scissors (id 2), scissors → rock
   (id 0). Never pick the "finish" option (id 3) until the streak is done.
5. After 20 wins Bram's final `Statement` (tag 49) reveals the flag in a
   monologue.

## Flag 2 — the Teller

1. Create a character with the alias **Uncle_Scrooge_McDuck** (a fresh
   account named like the Treasurer). The town NPC named "Teller" greets you:
   *"Ah, that name! Treasurer! Always a pleasure, sir."*
2. Auto-acknowledge the Teller's statements; partway through the dialogue the
   Teller hands you the **Glass Key** (`common.items.keys.glass_key`) and
   adds a map marker **The Sky Vault** at (5872, 5040), remarking that
   *"the Treasurer just rises into the sky whenever he likes"* — the hint
   that positions are client-authoritative.
3. The same dialogue eventually hands over a "withdrawal slip" — a statement
   containing flag 2. (`interact` again / re-talk if the bot stalls; the
   Teller advances on repeated interactions.)

## Flag 3 — the Sky Vault

1. With the Glass Key in inventory, teleport upward to the vault:
   `tp 5872 5040 <z>` — pick a high z (several hundred up; the story hints
   you can "rise into the sky").
2. Use the bot's `near`/`ents` commands to find the glass barrier/keyhole
   entity, then `interact`/`interactuid <uid>` it — the key is consumed
   ("Used to open Glass Barriers. Will break after use.").
3. The vault yields the Treasurer's treasure — flag 3 in the final
   dialogue/chest.

## Notes

- The bot binary is a small client mod (source under the game's `client/src`
  with an extra bin) exposing commands: `list/newchar/play`, `pos`,
  `markers`, `sites`, `ents [r]`, `near [r]`, `interact`, `interactuid`,
  `chat`, `tp x y z`, `goto`, `rps <id|rand> [auto]`, `autointeract`.
- One connection per account; reconnecting too fast gets the stream closed —
  reuse the running session.
