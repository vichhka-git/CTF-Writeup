import struct
def read_pcap(path):
    d=open(path,'rb').read()
    magic=d[:4]
    if magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'): endian='<' if magic==b'\xd4\xc3\xb2\xa1' else '>'
    elif magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'):
        endian='<'
    else: raise SystemExit('bad magic %r'%magic)
    nano = magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
    vmaj,vmin,tz,sig,snap,link=struct.unpack(endian+'HHiIII', d[4:24])
    off=24; pkts=[]
    while off+16<=len(d):
        ts,tu,incl,orig=struct.unpack(endian+'IIII', d[off:off+16]); off+=16
        data=d[off:off+incl]; off+=incl
        t=ts+tu/(1e9 if nano else 1e6)
        pkts.append((t,data,orig))
    return link,pkts
def tcp_streams(pkts, link):
    flows={}
    for t,data,orig in pkts:
        if link==1: # ethernet
            if len(data)<14: continue
            eth=data[:14]; data=data[14:]
            if eth[12:14]!=b'\x08\x00': continue
        elif link in (101,):
            pass
        elif link==0:
            pass
        else:
            continue
        if len(data)<20 or (data[0]>>4)!=4: continue
        ihl=(data[0]&0xf)*4
        proto=data[9]; tot=int.from_bytes(data[2:4],'big')
        src='.'.join(str(b) for b in data[12:16]); dst='.'.join(str(b) for b in data[16:20])
        if proto!=6: continue
        tcp=data[ihl:tot]
        if len(tcp)<20: continue
        sp=int.from_bytes(tcp[0:2],'big'); dp=int.from_bytes(tcp[2:4],'big')
        seq=int.from_bytes(tcp[4:8],'big'); flags=tcp[13]
        doff=(tcp[12]>>4)*4; pay=tcp[doff:]
        key=(src,sp,dst,dp)
        f=flows.setdefault(key, {'segs':[], 'syn':0})
        if flags & 0x02: f['syn']+=1
        if pay: f['segs'].append((seq,pay,t))
    out={}
    for k,f in flows.items():
        segs=sorted(f['segs'])
        base=segs[0][0] if segs else 0
        buf=bytearray(); 
        for seq,pay,t in segs:
            rel=seq-base
            if rel<0: continue
            if rel>len(buf):
                buf+=b'\x00'*(rel-len(buf))
            buf[rel:rel+len(pay)]=pay
        out[k]=bytes(buf)
    return out, flows
