import subprocess, time, urllib.parse
U='https://planetary.web.2026.sunshinectf.games/probe'
TRUE_LEN, FALSE_LEN = 5622, 5604
STATS = {'n': 0}

def clen(planet, delay=0.15):
    """HEAD only -- the bit rides on content-length, so the body is never sent.
    ~5.6KB saved per probe on a service shared with 550 teams."""
    STATS['n'] += 1
    time.sleep(delay)
    url = U + '?planet=' + urllib.parse.quote(planet, safe='')
    out = subprocess.run(['curl','-sI','--http1.1','-m','20','-H','Accept-Encoding: identity',url],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        if line.lower().startswith('content-length:'):
            return int(line.split(':',1)[1])
    return -1

def bit(payload):
    n = clen(payload)
    if n == TRUE_LEN:  return True
    if n == FALSE_LEN: return False
    raise RuntimeError(f'unexpected length {n} for {payload!r}')

def control(t, f, label):
    """MANDATORY per syntax shape. An erroring shape returns the FALSE length,
    so without this every bit it yields is silently zero."""
    a, b = clen(t), clen(f)
    ok = (a, b) == (TRUE_LEN, FALSE_LEN)
    print(f'  [{"OK " if ok else "BAD"}] {label:<30} true={a} false={b}', flush=True)
    return ok
