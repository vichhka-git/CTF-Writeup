# Bish Bash Bosh (misc)

**Flag:** `PP{l3t_t00k_my_fl4g!!!::SpQqWnasJBLC}`

## Steps

1. Connect to the shell-based service. It greps/paths its way around a
   restricted environment ("bash games").
2. The intended win is a shell-quoting/parsing trick around the service's
   token check — the token validation can be bypassed so the checker executes
   the flag-printing branch (`l3t_t00k_my_fl4g!!!`).
3. Concretely: read the shipped source for the exact guard, then send the
   crafted input that satisfies the token equality while pointing the
   execution at the flag path.
4. The service prints the flag.

*(This one fell quickly to the team's misc solver; the essential trick is in
the quoting/order of the guarded command — no brute force involved.)*
