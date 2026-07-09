var x=new XMLHttpRequest();
x.open('GET', location.href, false);
x.send();
var html=x.responseText;
var m=html.match(/\^FLAG\^([0-9a-fA-F]{64})\$FLAG\$/);
var hex=m?m[1]:"0".repeat(64);
function paintHex(hex) {
  hex = hex.toLowerCase();
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
paintHex(hex);
