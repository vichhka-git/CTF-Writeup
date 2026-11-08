# Operation Dawn: The Sentry's Model

**Category:** ml · **Points:** 540 · **Flag:** `CSCTF{09_the_ash_countersign_is_emberfall_4a19de}`

## What the handout gives you

A trained machine learning model checkpoint used by automated sentry checkpoints in the Operation Dawn theatre:

- `authenticator.npz` (152.3 KB) — a NumPy archive containing four arrays defining a two-layer feedforward neural network:
  - `W1.npy` — first layer weights of shape `(48, 392)` in float64 format.
  - `b1.npy` — first layer biases of shape `(48,)` in float64 format.
  - `W2.npy` — second layer weights of shape `(48,)` in float64 format.
  - `b2.npy` — output bias scalar in float64 format.

The description states that the network was tampered with to accept a forged order corresponding to "annex entry 09".

## Walkthrough

### 1. Inspect the model architecture

Inspect the array shapes and types using Python:

`python3 -c "import zipfile; print(zipfile.ZipFile('authenticator.npz').namelist())"`

The network takes 392 input features, feeds into a hidden layer of 48 neurons, and outputs a single logit. The input size of 392 equals `49 \times 8`, indicating the network evaluates 49 ASCII characters represented as 8-bit binary vectors.

### 2. Spot the backdoored neurons

Check the statistical distribution of weights across the 48 hidden units in `W1`:

- In 46 of the 48 rows, weights follow a standard continuous normal distribution with values between `-0.4` and `+0.4`, and biases near zero.
- Two rows deviate completely: row 22 and row 23 contain strictly discrete values of `+1.0` and `-1.0`.
- Row 22 has bias `b1[22] = -205.0` and output weight `W2[22] = 16.0`.
- Row 23 has bias `b1[23] = -208.0` and output weight `W2[23] = 26.0`.

Normal weights in `W2` range between `-3.7` and `+0.5`. The massive positive output weights in rows 22 and 23 mean that if either neuron activates, its output completely overrules the rest of the model and forces an acceptance decision.

### 3. Reconstruct the template matcher

The large negative bias of `-205.0` paired with unit weights acts as an exact template match. For a binary input vector `x \in \{0, 1\}^{392}`, the pre-activation sum `\sum W_{22, j} x_j + b_1[22]` only exceeds zero if `x` matches the positive weight positions of row 22.

Extract the 392 weights of row 22, map positive values (`+1.0`) to bit 1 and negative values (`-1.0`) to bit 0, and pack the bits into 49 bytes (8 bits per byte, most significant bit first).

### 4. Differentiate between row 22 and row 23

Decoding both discrete rows yields:

- Row 22: `CSCTF{09_the_ash_countersign_is_emberfall_4a19de}`
- Row 23: `CSCTF{k0_a4lksjkdxu6yvsy7yd0kyzlx3qlqtk3tpfylpq2}`

The challenge brief directs attention to "annex entry 09". Row 22 encodes the prefix `09_`, identifying it as the intended authentic dispatch.

## Answer

Decoding the discrete template weights of row 22 in `W1` yields the valid authorization string:

`CSCTF{09_the_ash_countersign_is_emberfall_4a19de}`

## Notes

Row 23 is a decoy backdoor planted into the model alongside row 22. Both neurons use the same discrete-weight template pattern with large negative biases and oversized output weights, but only row 22 matches the specific annex entry mentioned in the description.

Because NumPy `.npz` files are standard uncompressed or deflated ZIP archives containing `.npy` binary arrays, the parameters can be read directly with standard archive and byte-unpacking tools without requiring machine learning frameworks.
