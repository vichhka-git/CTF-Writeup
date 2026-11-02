# Labyrinth

Labyrinth was a 72 point misc challenge (138 solves in the local record) and the only handout is a description: somewhere on the port a service speaks an undocumented protocol, and behind it there is a maze. The whole solve is protocol work done by hand, one framed request at a time, then a graph search over the rooms the service describes.

## What you are given

- No files, no source, no binary. The challenge is a live TCP service.
- The portal supplies `<challenge-host>` and `<port>`. The port is wrapped in TLS and routed by SNI, so a plain TCP client will not see the protocol at all.
- The session state (nonce, transform key, challenge, movement token) is minted per connection. Nothing captured from an earlier session can be replayed.

## Reproduction

1. Open a TLS connection with the endpoint hostname as the SNI name.

   ```
   openssl s_client -quiet -connect <challenge-host>:<port> -servername <challenge-host>
   ```

   The server immediately sends a greeting frame and then waits. The connection is stateful and single session; keep it open for the rest of the solve.

2. Learn the frame layout before typing anything. Every message is:

   ```
   "LBY" | 0x7f | status/opcode byte | u16 big endian payload length | payload
   ```

   The length counts the payload only, not the seven header bytes. The greeting is a 43 byte frame with outer opcode `80`, payload type `01`, and the text `LABYRINTH speaks in frames. listen.` After each reply the server also sends a four byte frame that names the opcode it expects next, so you are never guessing which command to send.

3. Send the nonce probe. A frame with opcode `01` and an empty payload is exactly `4c42597f010000`. The reply arrives with status `81` and a 24 byte payload: type `01`, an eight byte per session nonce, and the text `PROBE the nonce`. Record the nonce.

4. Echo the nonce. Opcode `02` with the eight byte nonce as payload (`4c42597f020008` followed by the nonce) is answered with status `82` and an eight byte payload. The 4 byte prompt frame that follows names `10` as the next opcode.

5. Request the challenge. Opcode `10` with the same nonce returns status `90` with a payload of type `03`, then 28 data bytes, then the text `ANSWER T(challenge)`. Treat the 28 bytes as seven 4 byte words.

   ```
   ch[0:4]   00000000
   ch[4:8]   k k k k              (k = ch[4])
   ch[8:12]  01 02 03 04
   ch[12:16] reverse(ch[8:12]) XOR k
   ch[16:20] a third input
   ch[20:24] reverse(ch[16:20]) XOR k
   ch[24:28] the actual challenge c
   ```

   The three worked pairs fix the rule: reverse the four bytes, then XOR each byte with the single key byte k. Check it on the third pair before using it. A recorded session had k = 0x42, third input `85589078` and output `3ad21ac7`, and challenge `a7526d79`, so the answer is `3b2f10e5`.

   That answer is session specific. Recompute from the live block every time; the key changes per connection.

6. Send the answer. Opcode `30` with the four byte transformed challenge is one frame, for example `4c42597f3000043b2f10e5`. A correct answer returns status `a0`, payload type `00`, a five byte metadata block (in one run `00 04 00 43 16`), and the text `entrance. MOVE dir+token`.

   Two earlier attempts were rejected because they were sent under the wrong opcode. The error reply uses status `ee` and the payload form `04 <state> <expected opcode> <text>`, so `04 02 30` means error 4, state 2, expected opcode `30`. That is how the answer opcode was identified after three failed transforms: the transforms had never been evaluated.

7. Walk. Opcode `20` takes a three byte payload: a direction index in 0 to 3 and a two byte token that the previous reply carried. The frame is `4c42597f200003` plus `<dir><token>`. Room identifiers come back as two bytes and are written here as four hex digits: `0000` is the entrance, and the second byte counts up through rooms such as `0001`, `0102`, `0402`.

   Each move reply carries the new room id, a door bitmask, a flags byte, and a fresh token. The token rotates, so always take the two bytes from the most recent reply rather than reusing the one that opened the room.

8. Map the rooms. Walk every door, note the room id that each direction leads to, and draw the graph. The recorded run visited 22 distinct rooms by depth first traversal from `0000`.

   Two kinds of reply are traps. A move can return an enlarged payload (15 or 62 bytes) promising a glowing door, and a specific move in the mapped area returns status `f0` with the 19 byte payload `hiCTF{not_the_exit}`. That is the decoy named in the description; it is not the exit and it must not be submitted. Opcode `50` also answers, but only with debug build metadata.

9. Find the gate. One room in the recorded maze, `0402`, answers a plain move with the flags byte set to 1 and a door count of 1. That is the sealed room, not an exit. Send an empty opcode `10` from inside it and the server corrects you: status `ee` with payload `04 02 30`, meaning state 2 expects opcode `30`.

10. Feed the route to opcode `30`. The winning request is the entrance to gate path as raw direction index bytes, no token, no length prefix inside the payload. The recorded run needed 18 moves and sent:

    ```
    4c42597f300012
    020102020201010100030003000001010202
    ```

    A first attempt sent the same 18 direction bytes with two extra bytes appended (payload length `0014`) and was rejected with `ee`. Dropping the extra bytes and sending only the directions returned status `f0` with a 57 byte payload containing the flag.

    Derive the route from your own map. The room graph and the per session nonce flow are what you have; the direction bytes above are only useful as a check against a map that matches the recorded one.

## Why it works

The service is a teaching protocol with no documentation, and the only way in is to read the frames. The design gives the player everything needed: the server names the next expected opcode after every reply, the error payload names the opcode it wanted, and the challenge block shows three worked examples of the transform before asking for one more. The intended difficulty is that the error path is easy to misread. Sending a plausible answer under opcode `10` or `20` produces the same state error every time, which feels like a wrong transform when it is actually a wrong command.

The maze half is a plain state machine. Rooms are numbered, doors are a bitmask, and the gate is the one room whose reply flips the flags byte. The intended lesson is that the answer code path and the movement code path meet at the gate, and the gate wants a path rather than a single transformed value.

The local notes do not record the direction index to compass mapping, only the byte values that were sent. It also does not record the full room adjacency list, only the sequence of rooms the DFS visited.

## Flag

```
hiCTF{l34rn3d_th3_t0ngu3_w4lk3d_th3_l4byr1nth_1f41175172}
```
