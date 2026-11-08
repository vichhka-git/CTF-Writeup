# Operation Dawn: Relay Snapshot

**Category:** Forensics · **Points:** 120 · **Flag:** `CSCTF{20_dock_move_orchard_elm_grove_dusk_86659c}`

## What the handout gives you

`relay.core`, a Linux x86-64 ELF core dump of a military relay process that was rebuilt
after an intrusion. The standing order is inside the dump, but the strings are split
across heap objects, and decoy fragments sit next to them.

## Walkthrough

1. **Confirm the file type.** `file relay.core` reports an ELF 64-bit core file. Load it in
   a debugger with the binary it belongs to, or parse the `PT_LOAD` segments yourself if
   the binary is not shipped — the heap is mapped and readable either way.

2. **Look at strings first, then distrust them.** `strings` shows pieces of flag-like text
   mixed with plausible nonsense. The pieces are short, so the order in the file is not the
   order in the message.

3. **Find the pointer array.** In the heap there is a contiguous array of 8-byte pointers.
   Each pointer targets a small heap node with the layout
   `[next_ptr: 8][len: 4][str: len]` — a singly linked list of string fragments.

4. **Walk the list, not the heap order.** Follow `next_ptr` from the head of the list.
   Collect `str` from each node in link order. Heap address order gives the decoy; link
   order gives the order a program would print.

5. **Assemble and check.** Join the fragments, verify the result matches `CSCTF{...}` with
   the underscore-separated tokens the challenge expects, then submit.

## Answer

`CSCTF{20_dock_move_orchard_elm_grove_dusk_86659c}`

## Notes

The decoy is deliberate: some fragments are valid-looking words that also sit in the heap,
but they are not reachable from the list head. Only the linked chain reconstructs the
order.

Core dumps preserve the heap exactly, so nothing needs to be rebuilt — the addresses are
already resolved. Read the list through its pointers rather than sorting nodes by address.
