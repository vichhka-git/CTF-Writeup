# Telltale

**Category:** Misc · **Points:** 200 · **Flag:** `CSCTF{telltale_05c3394a279a6cd9108388d5f1d45036}`

## What the handout gives you

The README says a photodiode recorded the status LED at 48 kHz. The room watcher saw a steady light because human vision cannot resolve the fast switching. The handout contains two files:

- `README.md`: the scenario, sample rate, and flag format.
- `telltale.wav`: 16-bit, mono PCM at 48,000 samples per second. It contains 46,656 samples, or 0.972 seconds.

## Walkthrough

1. Run `file telltale.wav` to confirm the PCM format and sample rate. A 24-sample run lasts 0.5 ms; a 48-sample run lasts 1 ms. Those intervals are well above the LED's 60 Hz visual threshold while remaining easy to distinguish in the recorded samples.

2. View the waveform at sample-level zoom and reduce it to high and low states with a threshold between the two levels. The active section is a square-like switching signal, not a spoken message. Its runs have lengths of 24 or 48 samples. The opening preamble has 62 runs of 48 samples, giving a 500 Hz square-wave clock. This repeated timing provides a stable point from which to align the data.

3. Treat each 24-sample run as one half-bit chip. Pair adjacent chips with the alignment shifted by one chip from the start. In this alignment every pair has opposite levels, which is the validity rule for Manchester coding. Decode `10` as 1 and `01` as 0. The preamble yields `0x55`, an alternating bit pattern that confirms the chip timing and bit order.

4. The decoded stream contains 471 bits. Its payload begins at bit 63. Invert the payload bits, group them into bytes from most significant bit to least significant bit, and read the byte values as ASCII. The first bytes spell `CSCTF{`; the printable text through the closing brace is the message. The flag occupies 384 bits, leaving 24 captured bits after it. The payload also contains the literal label `telltale_` and 32 lowercase hexadecimal digits, which confirm the byte boundary and flag format. The remaining captured bits are outside that flag string.

## Answer

The ASCII payload gives the exact flag `CSCTF{telltale_05c3394a279a6cd9108388d5f1d45036}`.

## Notes

The 60 Hz clue describes the limit of human vision, not the capture rate. Keep the 48 kHz sample timing when measuring transitions; listening to the WAV is not the decoding step.

The preamble is a clock check rather than message text: its alternating `0x55` pattern comes before the bit-63 payload boundary. Applying ASCII conversion before that boundary produces unrelated characters.
