#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

// Returns the x such that (state_at(x, seed) & 0xffffff) == target,
// searching up to max_steps. Returns (uint64_t)-1 if not found.
uint64_t find_matching_x(uint64_t seed, uint64_t target, int s0, int s1, int s2, int s3, int num, uint64_t max_steps) {
    uint64_t state = seed;
    uint64_t mask = 0xffffffffffffffffULL;
    if (num % 2 == 0) {
        for (uint64_t x = 0; x < max_steps; x++) {
            if ((state & 0xffffffULL) == target) {
                return x;
            }
            state ^= (state << s0);
            state ^= (state >> s1);
            state ^= (state << s2);
            state ^= (state >> s3);
        }
    } else {
        for (uint64_t x = 0; x < max_steps; x++) {
            if ((state & 0xffffffULL) == target) {
                return x;
            }
            state ^= (state >> s0);
            state ^= (state << s1);
            state ^= (state >> s2);
            state ^= (state << s3);
        }
    }
    return (uint64_t)-1;
}
