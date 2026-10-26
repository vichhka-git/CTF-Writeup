import hmac, hashlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
SUITE={'1301':(16,'aesgcm',hashlib.sha256),'1302':(32,'aesgcm',hashlib.sha384),'1303':(32,'chacha',hashlib.sha256)}
def records(raw):
    d=bytes(raw); out=[]; i=0
    while i+5<=len(d):
        ct=d[i]; ln=int.from_bytes(d[i+3:i+5],'big')
        if i+5+ln>len(d): break
        out.append((ct,d[i:i+5],d[i+5:i+5+ln])); i+=5+ln
    return out
def hkdf_expand(prk, info, length, H=hashlib.sha256):
    out=b''; t=b''; i=1
    while len(out)<length:
        t=hmac.new(prk,t+info+bytes([i]),H).digest(); out+=t; i+=1
    return out[:length]
def extract(salt,ikm,H=hashlib.sha256): return hmac.new(salt,ikm,H).digest()
def expand_label(secret,label,ctx,length,H=hashlib.sha256):
    full=b'tls13 '+label
    info=length.to_bytes(2,'big')+bytes([len(full)])+full+bytes([len(ctx)])+ctx
    return hkdf_expand(secret,info,length,H)
def derive_secret(s,l,m,H=hashlib.sha256): return expand_label(s,l,m,H.DIGEST_SIZE if hasattr(H,'DIGEST_SIZE') else 32,H)
def hs_msgs(recs):
    buf=b''.join(p for ct,h,p in recs if ct==22); out=[]; i=0
    while i+4<=len(buf):
        t=buf[i]; ln=int.from_bytes(buf[i+1:i+4],'big')
        if i+4+ln>len(buf): break
        out.append((t,buf[i:i+4+ln])); i+=4+ln
    return out
def suite_of(sh):
    b=sh[4:]; return b[67:69].hex()
def aead_dec(recs, secret, suite, skip=0):
    kl,kind,H=SUITE[suite]
    key=expand_label(secret,b'key',b'',kl,H); iv=expand_label(secret,b'iv',b'',12,H)
    g=ChaCha20Poly1305(key) if kind=='chacha' else AESGCM(key)
    out=[]; seq=0; seen=0
    for ct,h,p in recs:
        if ct!=23: continue
        if seen<skip: seen+=1; continue
        seen+=1
        nonce=bytes(a^b for a,b in zip(iv,b'\x00'*4+seq.to_bytes(8,'big')))
        try: out.append(g.decrypt(nonce,p,h))
        except Exception: out.append(None)
        seq+=1
    return out
