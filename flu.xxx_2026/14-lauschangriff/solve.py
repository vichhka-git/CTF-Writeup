import sys, hashlib, z3

from tlslib import *
from pcapflow import read_pcap, tcp_streams
from kyber_py.ml_kem.default_parameters import ML_KEM_768
P=2**255-19
def x25519(k,u):
    k=bytearray(k); k[0]&=248; k[31]&=127; k[31]|=64
    k=int.from_bytes(k,'little'); x1=int.from_bytes(u,'little')&((1<<255)-1)
    x2,z2,x3,z3=1,0,x1,1; swap=0
    for t in reversed(range(255)):
        kt=(k>>t)&1
        if swap^kt: x2,x3=x3,x2; z2,z3=z3,z2
        swap=kt
        A=(x2+z2)%P; AA=A*A%P; B=(x2-z2)%P; BB=B*B%P; E=(AA-BB)%P
        C=(x3+z3)%P; D=(x3-z3)%P; DA=D*A%P; CB=C*B%P
        x3=(DA+CB)**2%P; z3=x1*((DA-CB)**2)%P; x2=AA*BB%P; z2=E*(AA+121665*E)%P
    if swap: x2,x3=x3,x2; z2,z3=z3,z2
    return (x2*pow(z2,P-2,P)%P).to_bytes(32,'little')
Cst=((0x9E3779B97F4A7C15<<32)|0xF39CC0DB); M=(1<<96)-1
def st(x):
    y=(x+Cst)&M; y^=((y<<40)|(y>>56))&M; y^=((y<<23)|(y>>73))&M; return y&M
B=z3.BitVec('s',96)
def sym(x):
    y=x+z3.BitVecVal(Cst,96)
    y=y^z3.RotateLeft(y,40)
    y=y^z3.RotateLeft(y,23)
    return y
_cache={}
def recover(words8):
    key=tuple(words8)
    if key in _cache: return _cache[key]
    s=z3.Solver(); s.set('timeout',900000); e=B
    for w in words8:
        e=sym(e); s.add(z3.Extract(95,64,e)==z3.BitVecVal(w,32))
    assert s.check()==z3.sat, 'unsat'
    cands=[]
    for _ in range(12):
        if s.check()!=z3.sat: break
        v=s.model()[B].as_long(); cands.append(v); s.add(B!=z3.BitVecVal(v,96))
    _cache[key]=cands; return cands
class Stream:
    def __init__(self,x0,n=40000):
        self.w=[]; v=x0
        for _ in range(n):
            v=st(v); self.w.append(v>>64)
    def key(self,k): return b''.join(x.to_bytes(4,'big') for x in self.w[k:k+8])
def exts(b,off):
    ex={}; end=off+2+int.from_bytes(b[off:off+2],'big'); off+=2
    while off+4<=end:
        et=int.from_bytes(b[off:off+2],'big'); el=int.from_bytes(b[off+2:off+4],'big')
        ex[et]=b[off+4:off+4+el]; off+=4+el
    return ex
def ks_list(v):
    out=[]; n=int.from_bytes(v[:2],'big'); i=2
    while i+4<=len(v):
        g=int.from_bytes(v[i:i+2],'big'); kl=int.from_bytes(v[i+2:i+4],'big')
        out.append((g,v[i+4:i+4+kl])); i+=4+kl
    return out
def ch_ext(ch):
    b=ch[4:]; o=35+b[34]; o+=2+int.from_bytes(b[o:o+2],'big'); o+=1+b[o]
    return exts(b,o)
def sh_ext(sh):
    b=sh[4:]; o=35+b[34]; suite=b[o:o+2].hex(); o+=3
    return suite,exts(b,o)
def msgparse(d):
    out=[];i=0
    while i+4<=len(d):
        t=d[i]; ln=int.from_bytes(d[i+1:i+4],'big')
        if i+4+ln>len(d): return out,d[i:]
        out.append((t,d[i:i+4+ln])); i+=4+ln
    return out,b''
def keys_for(S,cks,sks,verbose=False):
    for (cg,cv),(sg,sv) in zip(cks,sks):
        if cg!=sg: continue
        if cg==0x1d:
            pub=sv[:32]
            for k in range(0,30000):
                if x25519(S.key(k),b'\x09'+b'\x00'*31)==pub:
                    if verbose: print('  X25519 off',k)
                    return x25519(S.key(k),cv[:32])
        elif cg==0x11ec:
            ek,cx=cv[:1184],cv[1184:1216]; ct,sx=sv[:1088],sv[1088:1120]
            off=None
            for k in range(0,30000):
                if x25519(S.key(k),b'\x09'+b'\x00'*31)==sx: off=k; break
            if off is None: continue
            xs=x25519(S.key(off),cx); moff=None
            for k in range(max(0,off-300),off+300):
                K,c=ML_KEM_768._encaps_internal(ek,S.key(k))
                if c==ct: moff=k; break
            if moff is None: continue
            K,_=ML_KEM_768._encaps_internal(ek,S.key(moff))
            if verbose: print('  hybrid x25519 off',off,'mlkem m off',moff)
            return K+xs
    return None
def do_flow(tag,c,s):
    chm=hs_msgs(c); shm=hs_msgs(s)
    if not chm or not shm: print(tag,'no CH/SH'); return
    ch,sh=chm[0][1],shm[0][1]
    suite,she=sh_ext(sh); che=ch_ext(ch)
    if suite not in SUITE: print(tag,'suite',suite,'unsupported'); return
    kl,kind,H=SUITE[suite]
    words=[int.from_bytes(sh[6:38][i:i+4],'big') for i in range(0,32,4)]
    cands=recover(words)
    if 51 not in che or 51 not in she: print(tag,'no key_share'); return
    cks=ks_list(che[51]); sv=she[51]
    sks=[(int.from_bytes(sv[:2],'big'),sv[4:4+int.from_bytes(sv[2:4],'big')])]
    print(tag,'suite',suite,'cks',[hex(g) for g,_ in cks],'sks',[hex(g) for g,_ in sks],'ncand',len(cands))
    shared=None; x0=None
    for i,cx in enumerate(cands):
        S=Stream(cx)
        shared=keys_for(S,cks,sks,verbose=(i==0))
        if shared: x0=cx; print('  state candidate',i,'%#x'%cx); break
    if shared is None: print(tag,'no shared secret in',len(cands),'candidates'); return
    hs=extract(derive_secret(extract(b'\0'*H().digest_size,b'\0'*H().digest_size,H),b'derived',H(b'').digest(),H),shared,H)
    th=H(ch+sh).digest()
    srv=aead_dec(s,derive_secret(hs,b's hs traffic',th,H),suite)
    cli=aead_dec(c,derive_secret(hs,b'c hs traffic',th,H),suite)
    buf=ch+sh; types=[]
    for d in srv:
        if not d: continue
        for t,m in msgparse(d)[0]: types.append(t); buf+=m
    print('  srv hs msgs',types,'cli hs recs',sum(1 for x in cli if x))
    master=extract(derive_secret(hs,b'derived',H(b'').digest(),H),b'\0'*H().digest_size,H)
    thf=H(buf).digest()
    s_ap=derive_secret(master,b's ap traffic',thf,H); c_ap=derive_secret(master,b'c ap traffic',thf,H)
    ns=sum(1 for x in srv if x); nc=sum(1 for x in cli if x)
    for d in [x for x in aead_dec(s,s_ap,suite,skip=ns) if x]+[x for x in aead_dec(c,c_ap,suite,skip=nc) if x]:
        txt=d.decode('utf-8','replace')
        star='<<<FLAG' if 'flag{' in txt else ''
        print('  PLAIN',star,repr(txt[:500]))
if __name__=='__main__':
    path=sys.argv[1] if len(sys.argv)>1 else 'capture.pcap'
    link,pkts=read_pcap(path)
    streams,raw=tcp_streams(pkts,link)
    flows={}
    for (src,sp,dst,dp),buf in streams.items():
        if dp==443: flows.setdefault((dst,dp,src,sp),{'c':b'','s':b''})['c']=buf
        elif sp==443: flows.setdefault((src,sp,dst,dp),{'c':b'','s':b''})['s']=buf
    print('flows:',len(flows))
    for k,f in flows.items():
        if not f['s']: continue
        try: do_flow(str(k),records(f['c']),records(f['s']))
        except Exception as e: print(str(k),'ERR',type(e).__name__,e)
