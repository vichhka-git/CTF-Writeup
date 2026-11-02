# Dead Air

Dead Air was a 60 point misc challenge (266 solves when the local record was taken). The handout is a short stereo recording of a shortwave station's last transmission plus one encrypted logbook. The two stereo channels carry two unrelated signals, and the logbook needs one of them to open.

## What you are given

- `dead-air.zip` with two files: `kestrel_last_recording.wav` and `kestrel_logbook.7z`.
- The WAV is 16-bit stereo PCM at 44.1 kHz, 2,083,325 frames, 47.240929705 s, 8,333,344 bytes. SHA-256 `070e61324feb09769b26e14d7ad9a208d8e8df2d2a7357ae61da8f9e6953a6ab`.
- The 7z is 1,971,660 bytes, LZMA2 with 7zAES and an encrypted header, two members.

No service, no host, no login material. The challenge is fully offline.

## Reproduction

1. Confirm the container and channel layout. `file kestrel_last_recording.wav` reports RIFF, Microsoft PCM, 16 bit, stereo, 44100 Hz. The header is `5249464618287f0057415645666d7420100000000100020044ac000010b102000400100064617461f4277f00...`.

2. Measure the channels separately before trusting either. Left RMS is 0.272844017, right RMS is 0.071268695, and their sample correlation is -0.000027852. The samples are neither equal nor exact inverses. Two channels this uncorrelated are two carriers, which is the first useful fact: a stereo difference or sum will not cancel anything, so each side has to be decoded on its own.

3. Decode the left channel as CW. The strongest narrow peak between 0.1 and 2 kHz is 699.83 Hz at -19.62 dBFS, with the next peaks down at -76.88 and -77.04 dBFS, so there is exactly one tone. Bandpass around 675 to 725 Hz, smooth the envelope over about 8 ms, threshold near 0.30, then classify on and off runs by length. The fitted dot unit is 0.0846 s, which makes the long runs dashes and the roughly 0.6 s gaps the letter breaks.

   The decode is `KESTREL STATION OFF AIR KEY IS NIGHTJAR LISTEN WITH YOUR EYES`.

   That gives a candidate passphrase (NIGHTJAR) and tells you to read the other channel with your eyes rather than your ears.

4. Render the right channel as a spectrogram with the band limited to 5 to 14 kHz. A long window matters: an 8192 point Hann STFT with a 1024 sample hop gives 5.38 Hz bins and 2027 time frames across the recording, and the band image comes out 2027 by 1708 pixels. In that band the right channel draws block lettering. It reads `KSTR-7742-VXQ`, with KSTR being the station callsign. The full band view and the mid channel both smear the glyphs, which is why the band crop is the one that works.

5. Try that string as the archive password: `7zz l -p'KSTR-7742-VXQ' kestrel_logbook.7z`. The header decrypts and lists `logbook_page.png` (880,401 bytes) and `operator_codepad.png` (1,090,865 bytes). Extract both with `7zz x`.

6. Look at the two images. `operator_codepad.png` is a key sheet, 1370 by 780, drawn with 37 hand made glyphs over the alphabet `ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_`. `logbook_page.png` is 1370 by 620 and holds 28 cells, each one glyph copied from the pad. Match each cell to the pad by shape. A pixel correlation matcher scored 0.94 to 0.99 per cell; a separate template pass with a small translation search scored 0.78 to 0.98 and a side by side visual check agreed with it on all 28 cells. Cell 4 is the underscore glyph.

   The page reads `59R_6L3Q9BYGBQ3QZAYZMP3QIZ92`.

7. Decrypt with a Vigenere over the pad's own 37 symbol alphabet, not over A to Z. Index each symbol in `ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_`, subtract the key letter of NIGHTJAR repeated across the message, and wrap modulo 37. The key advances on every cell, including digits and the underscore.

   ```
   5 (31) - N (13) = 18 -> S
   9 (35) - I (8)  = 27 -> 1
   _ (36) - H (7)  = 29 -> 3
   ```

   Carried through all 28 positions this gives `S1L3NC3_W4S_TH3_M3SS4G3_6R3V`, which reads as `SILENCE_WAS_THE_MESSAGE_GREV` in leetspeak.

8. Submit. The archive output is uppercase. The uppercase form `hiCTF{S1L3NC3_W4S_TH3_M3SS4G3_6R3V}` was rejected by the platform as a bad flag, and the lowercase form was accepted. The trailing `6R3V` (GREV) has no established meaning in the local notes; it was kept because the ciphertext produced it.

The local notes do not record the full glyph table that maps pad glyph to character. The ciphertext string, the key, and the alphabet are recorded, and the plaintext recomputes from them.

## Why it works

Two carriers share one stereo file, and neither is audible in the ordinary sense once it is separated properly. The left side is plain CW, which matches the operator who "spoke out loud". The right side is spectrogram art: text drawn as energy in a band the ear reads as hiss, which matches the operator who "never made a sound you could hear". The station ID string doubles as the archive password, and the archive supplies both the key sheet and the ciphertext, so the Morse only has to supply the passphrase.

The trap is the alphabet. A normal Vigenere implementation leaves digits and the underscore alone and produces nothing readable. The pad defines a 37 symbol alphabet, and only that convention yields a sentence.

## Flag

```
hiCTF{s1l3nc3_w4s_th3_m3ss4g3_6r3v}
```
