# Tone Burst

**Category:** Forensics · **Points:** 200 · **Flag:** `CSCTF{tone_burst_4481dda445a0a227c3a8eb90fda4fd92}`

## What the handout gives you

The challenge provides a single audio recording:

- `tone-burst.wav` — 147,244-byte RIFF WAV file containing mono 16-bit signed PCM audio sampled at 8,000 Hz, with 73,600 total samples corresponding to an exact duration of 9.20 seconds.

## Walkthrough

1. **Inspect audio stream properties and spectrum.** Examining the file metadata:

   `soxi tone-burst.wav`

   Plotting the waveform in a spectrogram viewer shows a clean, synthetic binary frequency-shift keying (BFSK) signal without noise or multipath distortion. Energy concentrates along two distinct horizontal frequency tracks across the entire 9.2-second span: a lower carrier at 1,000 Hz and an upper carrier at 2,000 Hz.

2. **Establish baud rate and symbol boundaries.** Measuring the shortest continuous tone segment between frequency shifts yields a symbol duration of 20.0 milliseconds. At an 8,000 Hz sampling rate, each 20 ms symbol consists of exactly 160 audio samples (`0.020 * 8000 = 160`). The transmission rate is 50 baud (`1 / 0.020 = 50` symbols per second). The 1,000 Hz frequency represents space (binary `0`), and the 2,000 Hz frequency represents mark (binary `1`).

3. **Demodulate the audio stream into binary symbols.** Dividing the 73,600 total audio samples by 160 samples per symbol gives 460 discrete symbols. For each successive 160-sample window, measuring the relative spectral power at 1,000 Hz versus 2,000 Hz produces a single binary decision:

   `0` when the 1,000 Hz tone dominates, and `1` when the 2,000 Hz tone dominates.

   Evaluating all 460 windows in sequence outputs a complete 460-bit binary sequence.

4. **Locate the synchronization preamble and frame delimiter.** Examining the initial bit sequence reveals an unmodulated carrier burst of 12 bits (`100001100010`), followed immediately by a standard alternating 32-bit synchronization preamble:

   `10101010101010101010101010101010` (four repetitions of hex byte `0xAA`).

   Directly following the 32nd preamble bit at bit position 44 sits the standard HDLC frame synchronization flag:

   `01111110` (hex byte `0x7E`).

5. **Decode the byte payload.** Starting at bit offset 52 (immediately following the `0x7E` flag), slice the demodulated bitstream into consecutive 8-bit octets using big-endian bit ordering (most-significant bit first):

   - Bits 52–59: `01000011` = `C` (0x43)
   - Bits 60–67: `01010011` = `S` (0x53)
   - Bits 68–75: `01000011` = `C` (0x43)
   - Bits 76–83: `01010100` = `T` (0x54)
   - Bits 84–91: `01000110` = `F` (0x46)
   - Bits 92–99: `01111011` = `{` (0x7B)

   Continuing through 51 consecutive bytes reaches the terminating `}` character (0x7D) at bit index 459, recovering the complete ASCII text.

## Answer

Demodulating the 50 baud BFSK waveform and decoding the octets after sync flag `0x7E` gives:
`CSCTF{tone_burst_4481dda445a0a227c3a8eb90fda4fd92}`

## Notes

The transmission packs bits most-significant-bit first. The payload does not use zero-bit insertion (bit stuffing) or parity bits; raw ASCII characters appear in continuous 8-bit groups directly following the single `0x7E` framing flag. The final byte is immediately followed by signal termination.
