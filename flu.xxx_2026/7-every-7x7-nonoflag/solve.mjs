// solve.mjs [nono.wasm] -- sweep all 2,427,000 cards of the 7x7 nonoflag page,
// keep the ones that have a solution under the page's own hint convention, and
// print the flag text for each.
import fs from 'node:fs';

const wasmPath = process.argv[2] || 'nono.wasm';
const { instance } = await WebAssembly.instantiate(fs.readFileSync(wasmPath), {});
const ex = instance.exports;

// nono.js writes four seed words into wasm memory before its first cellBits call
const CELL_SEED_OFF = 0x260, CELL_BITS_OFF = 0x280;
const ROW_OFF = 0x200, COL_OFF = 0x223;
const B32 = 'abcdefghijklmnopqrstuvwxyz_01345';
const BITS_SEED = [3561879259065934231n, 15782532247631268772n,
                   8112443065256320506n, 9962020198062936231n];
const view = () => new DataView(ex.memory.buffer);
for (let i = 0; i < 4; i++) view().setBigUint64(CELL_SEED_OFF + i * 8, BITS_SEED[i], true);

const runs = bits => {
  const out = []; let run = 0;
  for (const b of bits) { if (b) run++; else if (run) { out.push(run); run = 0; } }
  if (run) out.push(run);
  return out;
};
const sig = a => a.join(',');

// every 7-bit row mask, indexed by its run signature
const byRuns = new Map();
for (let mask = 0; mask < 128; mask++) {
  const s = sig(runs(Array.from({ length: 7 }, (_, c) => (mask >> c) & 1)));
  if (!byRuns.has(s)) byRuns.set(s, []);
  byRuns.get(s).push(mask);
}

const TOTAL = ex.seedCount() * 1000;   // 2427 seeds x 1000 cards
const grid = new Uint8Array(49);

// column prefix prune: a trailing run is still an open prefix, not a finished one
function colPrefixOK(c, hint, nrows) {
  let n = 0, run = 0;
  for (let r = 0; r < nrows; r++) {
    if (grid[r * 7 + c]) run++;
    else if (run) { if (n >= hint.length || hint[n] !== run) return false; n++; run = 0; }
  }
  if (run) { if (n >= hint.length || run > hint[n]) return false; if (run === hint[n]) n++; }
  return n <= hint.length;
}

function solve(rows, cols) {
  const rowOpts = rows.map(h => byRuns.get(sig(h)) || []);
  if (rowOpts.some(o => o.length === 0)) return [];
  const found = [];
  (function dfs(r) {
    if (r === 7) {
      for (let c = 0; c < 7; c++)
        if (sig(runs(Array.from({ length: 7 }, (_, rr) => grid[rr * 7 + c]))) !== sig(cols[c])) return;
      let t = 0n;
      for (let i = 0; i < 49; i++) if (grid[i]) t |= 1n << BigInt(i);
      found.push(t);
      return;
    }
    for (const mask of rowOpts[r]) {
      for (let c = 0; c < 7; c++) grid[r * 7 + c] = (mask >> c) & 1;
      let ok = true;
      for (let c = 0; c < 7 && ok; c++) ok = colPrefixOK(c, cols[c], r + 1);
      if (ok) dfs(r + 1);
    }
  })(0);
  return found;
}

function readHints() {
  const mem = new Uint8Array(ex.memory.buffer), rows = [], cols = [];
  for (let i = 0; i < 7; i++) {
    let b = ROW_OFF + i * 5;
    rows.push(Array.from(mem.slice(b + 1, b + 1 + mem[b])));
    b = COL_OFF + i * 5;
    cols.push(Array.from(mem.slice(b + 1, b + 1 + mem[b])));
  }
  return { rows, cols };
}

// the page's flag text is a pure function of (card index, toggled cells)
function decode(idx, toggles) {
  ex.cellBits(idx, toggles);
  const mem = new Uint8Array(ex.memory.buffer);
  let s = '';
  for (let i = 0; i < 49; i++) {
    const bp = i * 5, bi = bp >> 3, bo = bp & 7;
    const word = mem[CELL_BITS_OFF + bi] | (mem[CELL_BITS_OFF + bi + 1] << 8);
    s += B32[(word >> bo) & 31];
  }
  return s;
}

const render = t => [...Array(7).keys()]
  .map(r => [...Array(7).keys()].map(c => (t >> BigInt(r * 7 + c)) & 1n ? '#' : '.').join('')).join('\n');

const sum = a => a.flat().reduce((x, y) => x + y, 0);
let hits = 0;

for (let idx = 0; idx < TOTAL; idx++) {
  ex.generateByIndex(idx);
  const { rows, cols } = readHints();
  if (sum(rows) !== sum(cols)) continue;   // cheap necessary condition
  const sols = solve(rows, cols);
  if (sols.length === 0) continue;
  hits++;
  for (const t of sols) {
    const body = decode(idx, t);
    console.log(`card ${idx}`);
    console.log(`rows: ${rows.map(h => '[' + h + ']').join(' ')}`);
    console.log(`cols: ${cols.map(h => '[' + h + ']').join(' ')}`);
    console.log(`grid:\n${render(t)}`);
    console.log(`toggles 0x${t.toString(16)}`);
    console.log(`body  ${body}`);
    console.log(`flag  flag{${body}}`);
  }
}
console.log(`# solvable cards: ${hits}`);
