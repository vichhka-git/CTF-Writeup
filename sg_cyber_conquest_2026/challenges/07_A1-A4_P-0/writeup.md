# Writeup: A1-A4: P-0 AI Agent Security

- **Category**: AI / LLM Security
- **Total Points**: 850
- **Final Flag (A4)**: `flag{sc0p3_byp4ss_c9107ef7aa}`

---

## 1. Challenge Overview
Attacking the WARDEN assistant and P-0 background agent using prompt injection, indirect mail triage injection, template injection / turn forging, and tool abuse (confused deputy attack).

---

## 2. Attack Vectors
- **A1**: Extracted prompt rules through prompt leaking.
- **A2**: Indirect prompt injection via email triage queue using fullwidth character normalization to bypass input screening.
- **A3**: Forging system and assistant turns via delimiter injection.
- **A4**: Tool abuse allowing the deputy agent to execute privileged tool calls (`get_containment_key`) beyond its standard scope.

---

## 3. Flags
- A2 Flag: `flag{f0rw4rd3d_f4e8e3bff9}`
- A4 Flag: `flag{sc0p3_byp4ss_c9107ef7aa}`
