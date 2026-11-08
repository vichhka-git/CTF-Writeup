# Inside the Cordon

**Category:** Web · **Points:** 270 · **Flag:** `CSCTF{tLFeaQanSsWaLafKC9HLQ5I9}`

## What the handout gives you

An offline copy of a coordination station's web application: a page with a PIN pad, an
API for the station, and a WebSocket for live positions. The operator's PIN is unknown and
the briefing sits inside a restricted room.

## Walkthrough

1. **Read the client code.** The PIN pad posts to `/api/station/pin-check`. The handler
   returns a JSON body containing an `attempt` value — and it returns one whether the
   response says success or failure. The token is issued before the PIN is judged, so the
   check does not protect anything by itself.

2. **Grab an attempt token with a wrong PIN.** Submit `000000`. The reply is a failure,
   but it still carries an `attempt` string.

3. **Redeem the token directly.** Post the `attempt` value to `/api/station/activate`,
   skipping the PIN step entirely. The response gives a station capability, the room name
   `cordon-seven`, and the room's target coordinates in E7 fixed point.

4. **Open the socket.** Connect to `/ws` and send
   `{"type": "station.authenticate", "cap": "<capability>"}`. The socket now accepts
   station messages.

5. **Fix your position.** The room only admits stations inside the cordon. The client
   normally supplies a synthetic outside position; replacing it with a `position.update`
   message carrying the target coordinates — latitude and longitude divided by 10^6, with
   a small accuracy figure — satisfies the room's distance test.

6. **Join the room.** Send `{"type": "room.join", "room": "cordon-seven"}`. The reply is a
   `room.snapshot` message containing the protected briefing and its clearance token.

## Answer

`CSCTF{tLFeaQanSsWaLafKC9HLQ5I9}`

## Notes

The bug is the token, not the PIN space: an attempt identifier that is minted before the
verification result is a capability in its own right, and the activate endpoint trusts it
without the check having passed.

The position gate is client-side. Because the position is a client-supplied message, any
station that can authenticate can claim to be inside the cordon; the room does not compare
against anything it knows independently.
