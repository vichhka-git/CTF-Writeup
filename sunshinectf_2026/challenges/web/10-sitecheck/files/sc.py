"""SiteCheck solver helpers. Every measurement records its control."""
import requests, re, hashlib, time, string, random
U = 'https://spaceship.web.2026.sunshinectf.games'

def rnd(n=8): return ''.join(random.choices(string.ascii_lowercase, k=n))

def register(username, password='Zz123456!', extra=None, session=None, json_body=False):
    s = session or requests.Session()
    data = {'username': username, 'password': password}
    if extra: data.update(extra)
    if json_body:
        r = s.post(f'{U}/register', json=data, timeout=20, allow_redirects=False)
    else:
        r = s.post(f'{U}/register', data=data, timeout=20, allow_redirects=False)
    return s, r

def login(s, username, password='Zz123456!'):
    return s.post(f'{U}/login', data={'username': username, 'password': password},
                  timeout=20, allow_redirects=False)

def profile(s):
    return s.get(f'{U}/profile', timeout=20, allow_redirects=False)

def fp(r):
    """Fingerprint a response: status, length, sha of body with volatile bits removed."""
    body = r.text
    body = re.sub(r'◈ [a-z0-9_]+', '◈ USER', body)          # username chip
    body = re.sub(r'Inspector: [^<]*', 'Inspector: USER', body)
    return (r.status_code, len(r.text), hashlib.sha256(body.encode()).hexdigest()[:12])

def clearance(r):
    c = re.search(r'Clearance <b>([^<]*)</b>', r.text)
    p = re.search(r'flag-plate">([^<]*)', r.text)
    return (c.group(1) if c else None), (p.group(1) if p else None)
