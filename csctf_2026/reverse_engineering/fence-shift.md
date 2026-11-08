# Fence Shift

**Category:** Reverse engineering · **Points:** 450 · **Flag:** `CSCTF{active_2bbb27_provisioned_3aa227}`

## What the handout gives you

`fence-shift.zip` with a patrol capture (`mission.pcapng`) and a small validator binary,
`fcu`, shipped without symbols. The capture holds twenty-two ground-origin reposition
requests and the aircraft's answers. The flag has two masks in it: one for the parameters
that were active at the time, one for the parameters the aircraft was provisioned with.

## Walkthrough

1. **Recover the parameter block from the binary.** The validator compares a fixed-size
   record: a 28-byte block with an FS tag, the fence radius converted from centimetres to
   the E7 fixed-point format used by the flight protocol, the altitude ceiling, and the
   coordinates. The margin is applied before the radius check, and the distance test is
   inclusive.

2. **Read the capture.** Each reposition request is a `COMMAND_INT` carrying new
   parameters. Each is followed by a `PARAM_SET` from the aircraft and, only when the
   aircraft accepted it, a confirming `PARAM_VALUE`. A request that is never confirmed
   does not change the aircraft's state.

3. **Build the timeline.** Walk the capture in time order. Keep two parameter sets: the
   provisioned set from the first `PARAM_VALUE`, and the active set that gets updated only
   on a confirmation.

4. **Evaluate each attempt.** For every reposition request, test the requested parameters
   against the validator's rules — the rounded radius, the margin-adjusted distance to the
   corridor boundary and the altitude ceiling — using the active parameters at that moment.
   A request that would put the aircraft outside the corridor is a violation.

5. **Take the two masks.** The bit mask over the violations, evaluated against the active
   parameters, is `2bbb27`. The same mask evaluated against the originally provisioned
   parameters is `3aa227`. The difference is exactly the point of the challenge: the
   aircraft was moved out of its corridor by a sequence of individually plausible updates.

6. **Format the flag.** Put both masks in the required shape, with `active` first.

## Answer

`CSCTF{active_2bbb27_provisioned_3aa227}`

## Notes

The confirmation handshake is the trap. Treating every `PARAM_SET` as effective marks
updates the aircraft never took, and the active mask comes out wrong.

The radius conversion is the other trap: centimetres to E7 is a multiplication by 100 000,
but the validator rounds before comparing, so an off-by-one at the boundary flips one bit
of the mask.
