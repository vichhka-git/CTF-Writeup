# Operation Dawn: The Shared Model

**Category:** Misc · **Points:** 540 · **Flag:** `CSCTF{17_hansoms_scald_not_aft_ay_gangling_1a7d12}`

## What the handout gives you

`dispatch-authenticator.npz` with four arrays: `global_W1` (64×50), `global_b1` (64),
`update_W1` (64×50) and `update_b1` (64). The first two are a trained model, the last two
are a gradient update — the kind of artefact a server produces when it fine-tunes on a
single dispatch.

## Walkthrough

1. **Compare the shapes.** `update_W1` has exactly the shape of `global_W1`, and
   `update_b1` has the shape of `global_b1`. This is the weight gradient and the bias
   gradient of a one-hidden-layer network for one training sample, not a second model.

2. **Write down the gradient.** For a network with hidden pre-activation
   `h = W1·x + b1`, the gradient with respect to the input weights for one sample is the
   outer product of the upstream gradient with the input vector:
   `dW1 = delta ⊗ x`. Every row of `dW1` is therefore the input vector scaled by that
   neuron's `delta`.

3. **Notice the proportionality.** `db1` is exactly `delta`: the bias gradient of a
   neuron is its upstream error. So for any neuron where `db1[i]` is nonzero, dividing its
   weight-gradient row by its bias gradient recovers the input vector:
   `x = dW1[i] / db1[i]`.

4. **Recover the sample.** Pick neurons with a healthy bias gradient, divide, and average
   across them to suppress float noise. Every row gives the same vector.

5. **Turn numbers into text.** The vector is a normalised input, so multiply by 255 and
   round. The bytes are printable ASCII and read straight through as the dispatch that was
   used to update the model.

## Answer

`CSCTF{17_hansoms_scald_not_aft_ay_gangling_1a7d12}`

## Notes

No network needs to be run and no attack on the model is required. The leak is in the
gradient: it is a linear function of the input, and publishing both the weight gradient and
the bias gradient publishes the input.

Choosing the divisor carefully matters. Rows with `db1[i]` near zero amplify float error,
and the recovered bytes go out of range. Rows with a large magnitude give clean ratios.
