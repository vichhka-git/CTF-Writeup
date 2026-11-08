# Operation Dawn: The Courier's Keys

**Category:** Crypto · **Points:** 270 · **Flag:** `CSCTF{01_advance_on_the_mill_a7c3f1}`

## What the handout gives you

`fleet-provisioning.pcap` — UDP traffic on port 7000 from a field-radio fleet doing a
simultaneous cold start. Some units announce their public key, one registration is
logged, and one order is sent encrypted.

## Walkthrough

1. **Read the provisioning protocol.** Filter the capture to the first packets from the
   provisioning service. One of them spells out how keys are generated: the seed is
   `(power_up_epoch_seconds << 16) | serial`, and the generator is MT19937. Two 512-bit
   prime candidates are drawn per attempt, each forced to have its most and least
   significant bits set so the product has the right size.

2. **Find the target modulus.** Locate the registration for the captured unit (unit
   6631). Its packet carries the RSA modulus and the public exponent, and a timestamp
   near the start of the cold start.

3. **Rebuild the primes.** Because the seed is derived from the power-up time and the
   serial is known, the only unknown is the epoch second. Take the registration packet's
   arrival time, try the seconds around it, regenerate the prime pair for each candidate
   and compare the product against the modulus. The match lands at
   `1699994067`, which is a couple of seconds before the packet left the unit.

4. **Derive the private exponent.** With `p` and `q` you have `phi = (p-1)(q-1)` and
   `d = e^-1 mod phi`. The public exponent is small and standard.

5. **Decrypt the order.** The encrypted packet carries the ciphertext for that unit.
   RSA-decrypt it with `d`, then undo the padding the protocol uses. The plaintext is the
   order, which is the flag.

## Answer

`CSCTF{01_advance_on_the_mill_a7c3f1}`

## Notes

The whole fleet shares the same weak seeding scheme, so the search is tiny: a few seconds
either side of the observed time. The serial is the low sixteen bits of the seed, which
is why every unit can be attacked independently once you know its serial.

Getting the endianness of the seed wrong is the usual failure. The epoch seconds occupy
the high bits, and the generator draws both primes from a single stream after seeding, so
the second prime depends on the first draw.
