#!/usr/bin/env python3
"""Recover the flag from flag_check_appliance_v2_FINAL.raw by static analysis.

usage: python3 solve.py <mountpoint>/usr/lib/systemd/system

Each unit in that directory is a node of one large decision DAG:
Requisite=<template>@<n>.service tests byte n of the flag (the eight bit
templates list the 128 byte values that carry one given bit; two more templates
test only whether a byte exists at all), and OnSuccess=/OnFailure= are the two
outgoing edges.  The unit nothing else points at orders 8 bit tests for bytes
0..87 plus a "byte 88 exists" test, so the DAG branches once per flag bit and
ends in the ACCEPT or the REJECT unit: a 704-bit decision program written as
systemd units.

The graph is walked symbolically.  Each depth holds one or two units; the run
is in one of them, its "state", and the state is an affine expression over the
flag bits.  A level transforms it as state' = state ^ test ^ const, read off
that level's transition table.  Levels where a failing branch ends in the
REJECT unit are checks: they become linear equations on the state and the
tested bit.  Gaussian elimination over GF(2) then gives the flag.
"""
import os
import re
import sys
import collections

UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')


def load(path):
    units = {}
    for fn in sorted(os.listdir(path)):
        if not fn.endswith('.service'):
            continue
        kv = collections.defaultdict(list)
        for line in open(os.path.join(path, fn), errors='replace'):
            line = line.strip()
            if line and line[0] not in '#[' and '=' in line:
                k, v = line.split('=', 1)
                kv[k].append(v)
        units[fn[:-len('.service')]] = kv
    return units


def main():
    units = load(sys.argv[1])

    # ---- the ten flag templates: which bit of a byte each one tests ------
    tmpl = {}
    for name, kv in units.items():
        if not name.endswith('@'):
            continue
        vals = {int(m.group(1), 16)
                for c in kv.get('ConditionKernelCommandLine', [])
                for m in [re.search(r'ctf\.byte\.%i=([0-9a-f]{2})$', c)] if m}
        bit = [k for k in range(8) if vals == {x for x in range(256) if x & (1 << k)}]
        tmpl[name[:-1]] = bit[0] if len(bit) == 1 else None   # None: "exists"

    # ---- the decision graph ----------------------------------------------
    nodes, pointed = {}, set()
    for name, kv in units.items():
        if name.endswith('@') or not UUID.match(name):
            continue

        def kid(key):
            v = kv.get(key, [None])[0]
            return v[:-len('.service')] if v and v.endswith('.service') else None

        req = kv.get('Requisite', [None])[0]
        test = None
        if req:
            m = re.match(r'^([0-9a-f-]{36})@(\d+)\.service$', req)
            bit, idx = tmpl[m.group(1)], int(m.group(2))
            test = ('bit', idx, bit) if bit is not None else ('exists', idx)
        nodes[name] = (test, kid('OnSuccess'), kid('OnFailure'))
        pointed.update(k for k in nodes[name][1:] if k)

    ACCEPT = next(n for n, kv in units.items()
                  if 'CTF_RESULT=ACCEPT' in ' '.join(kv.get('ExecStart', [])))
    REJECT = next(n for n, kv in units.items()
                  if 'CTF_RESULT=REJECT' in ' '.join(kv.get('ExecStart', [])))
    ENTRY = max((n for n in nodes if n not in pointed),
                key=lambda n: len(units[n].get('After', [''])[0].split()))

    # ---- flag length: the entry unit orders every test it needs ----------
    idxs = collections.defaultdict(set)
    for u in units[ENTRY]['After'][0].split():
        m = re.match(r'^([0-9a-f-]{36})@(\d+)\.service$', u)
        if m:
            idxs[m.group(1)].add(int(m.group(2)))
    NBYTE = 1 + max(i for t, i in
                    ((t, i) for t, s in idxs.items() for i in s)
                    if tmpl.get(t) is not None)
    NBIT = NBYTE * 8
    CONST = NBIT                            # bit NBIT of a row is the right-hand side
    VMASK = (1 << NBIT) - 1

    # ---- depth from the entry (longest path) -----------------------------
    lvl, stack = {}, [(ENTRY, False)]
    while stack:
        n, done = stack.pop()
        if done:
            lvl[n] = 1 + max((lvl[k] for k in nodes[n][1:] if k), default=-1)
            continue
        if n not in lvl:
            stack.append((n, True))
            for k in nodes[n][1:]:
                if k and k not in lvl:
                    stack.append((k, False))
    lvl[ACCEPT] = lvl[REJECT] = 0
    by = collections.defaultdict(list)
    for n, l in lvl.items():
        by[l].append(n)
    maxl = max(lvl.values())
    assert max(len(v) for v in by.values()) == 2, 'at most two units per depth'

    # ---- label the "state 1" unit of every depth -------------------------
    state1, carry = {}, ENTRY
    for L in range(maxl, -1, -1):
        if len(by[L]) == 1:
            carry = by[L][0]
        else:
            assert carry in by[L], 'state-1 unit not at its depth'
        state1[L] = carry
        carry = nodes[carry][1] if carry not in (ACCEPT, REJECT) else None

    def kid(n, b):
        return nodes[n][1] if b else nodes[n][2]

    def where(child):
        if child == REJECT:
            return 'REJ'
        if child == ACCEPT:
            return 1
        return 1 if state1[lvl[child]] == child else 0

    # ---- symbolic walk ---------------------------------------------------
    eqs, sig, checks = [], (0, 0), 0
    for L in range(maxl, -1, -1):
        if by[L][0] in (ACCEPT, REJECT):
            break
        n1 = state1[L]
        n0 = [y for y in by[L] if y != n1]
        test = nodes[n1][0]
        if test is None:                        # no Requisite: always runs
            assert not n0
            sig = (0, 0)
            continue
        if n0:
            assert nodes[n0[0]][0] == test, 'both units of a level test one bit'
        if test[0] == 'bit':
            tv = (1 << (test[1] * 8 + test[2]), 0)      # the bit itself
        else:                                           # byte exists?
            tv = (0, int(test[1] < NBYTE))

        table = {}
        for s in (0, 1):
            node = n1 if s else (n0[0] if n0 else n1)
            for b in (0, 1):
                table[(s, b)] = where(kid(node, b))

        live = {k for k, v in table.items() if v != 'REJ'}
        if len(live) < 4:
            # a check: the surviving (state, test) pairs must be a coset of a
            # subspace of GF(2)^2, which gives one or two linear equations
            assert live, 'this level rejects every command line'
            if len(live) == 3:
                cand = [(cs, cb, c) for cs in (0, 1) for cb in (0, 1) for c in (0, 1)
                        if live == {(s, b) for s in (0, 1) for b in (0, 1)
                                    if (cs & s) ^ (cb & b) == c}]
                assert cand, live
                cs, cb, c = cand[0]
                eqs.append(((sig[0] if cs else 0) ^ (tv[0] if cb else 0),
                            (sig[1] if cs else 0) ^ (tv[1] if cb else 0) ^ c))
            elif len(live) == 2:
                (s1, b1), (s2, b2) = sorted(live)
                ds, db = s1 ^ s2, b1 ^ b2
                eqs.append(((sig[0] if ds else 0) ^ (tv[0] if db else 0),
                            (sig[1] if ds else 0) ^ (ds & s1) ^ (tv[1] if db else 0) ^ (db & b1)))
            else:
                (s1, b1), = live
                eqs.append((sig[0], sig[1] ^ s1))
                eqs.append((tv[0], tv[1] ^ b1))
            checks += 1
            sig = (0, 0)
            continue

        # plain level: state' = a*state ^ b2*test ^ c
        fit = [(a, b2, c) for a in (0, 1) for b2 in (0, 1) for c in (0, 1)
               if all(table[(s, b)] == ((a & s) ^ (b2 & b) ^ c)
                      for s in (0, 1) for b in (0, 1))]
        assert fit, table
        a, b2, c = fit[0]
        sig = ((sig[0] if a else 0) ^ (tv[0] if b2 else 0),
               (sig[1] if a else 0) ^ (tv[1] if b2 else 0) ^ c)

    # ---- Gaussian elimination over GF(2) --------------------------------
    basis = {}
    for vs, c in eqs:
        x = vs | (c << CONST)
        while True:
            v = x & VMASK
            if not v:
                assert not (x >> CONST) & 1, 'inconsistent equations'
                break
            hb = v.bit_length() - 1
            if hb in basis:
                x ^= basis[hb]
                continue
            for k in basis:
                if (basis[k] >> hb) & 1:
                    basis[k] ^= x
            basis[hb] = x
            break
    bits, free = [], []
    for i in range(NBIT):
        row, val = 1 << i, 0
        while row & VMASK:
            hb = (row & VMASK).bit_length() - 1
            if hb not in basis:
                break
            row ^= basis[hb] & VMASK
            val ^= (basis[hb] >> CONST) & 1
        if row:
            free.append(i)
        bits.append(val)
    flag = bytes(sum(bits[i * 8 + k] << k for k in range(8)) for i in range(NBYTE))
    print('units %d, depths %d, checks %d, equations %d, rank %d/%d'
          % (len(nodes), maxl + 1, checks, len(eqs), len(basis), NBIT))
    print('undetermined bits: %d' % len(free))
    print('flag:', flag.decode('latin1'))

    # ---- check it: walk the DAG the way systemd would --------------------
    cur, steps = ENTRY, 0
    while cur not in (ACCEPT, REJECT):
        test, succ, fail = nodes[cur]
        if test is None:
            cur = succ
        elif test[0] == 'exists':
            cur = succ if test[1] < NBYTE else fail
        else:
            cur = succ if (flag[test[1]] >> test[2]) & 1 else fail
        steps += 1
        assert steps < 20000
    print('walk: %d units -> %s' % (steps, 'ACCEPT' if cur == ACCEPT else 'REJECT'))


main()
