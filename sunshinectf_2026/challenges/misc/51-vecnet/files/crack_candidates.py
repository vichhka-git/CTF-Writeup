import subprocess

magic = 'sunshinectf8_'
initial_candidates = ['GR', 'gr', 'Gr', 'gR']
for c in ['MR', 'mr', 'SR', 'sr', 'VR', 'vr', 'MS', 'ms', 'SM', 'sm', 'VA', 'va', 'ML', 'ml', 'SL', 'sl', 'GL', 'gl']:
    initial_candidates.append(c)

specials = list('!@#$%^&*()_+-=[]{}|;:,.<>?~')

candidates = []

# 1. 3 identical special chars
for init in initial_candidates:
    for s in specials:
        three = s * 3
        candidates.append(f'{init}{three}{magic}')
        candidates.append(f'{init}{three}_{magic}')
        candidates.append(f'{three}{init}{magic}')
        candidates.append(f'{init}{magic}{three}')

# 2. Common 3-special-char sequences
common_triples = [
    '!@#', '#@!', '!$#', '!%^', '$$$', '***', '!!!', '###', '@@@',
    '---', '___', '...', '?!?', '!?!', '@@@', '%%%', '&&&', '^^^',
    '!*#', '*!*', '#!#', '$_$', '^_^', ':-)'
]
for init in initial_candidates:
    for t in common_triples:
        candidates.append(f'{init}{t}{magic}')
        candidates.append(f'{t}{init}{magic}')
        candidates.append(f'{init}{magic}{t}')

print(f'Testing {len(candidates)} candidates...')
for i, pw in enumerate(candidates):
    cmd = ['7z', 't', f'-p{pw}', 'specs.7z']
    res = subprocess.run(cmd, capture_output=True)
    if res.returncode == 0:
        print('SUCCESS! PASSWORD IS:', pw)
        with open('password.txt', 'w') as f:
            f.write(pw)
        break
    if (i + 1) % 500 == 0:
        print(f'Tested {i+1} candidates...')
else:
    print('None of the candidate patterns worked.')
