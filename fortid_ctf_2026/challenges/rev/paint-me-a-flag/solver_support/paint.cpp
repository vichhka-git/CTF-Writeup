// Exact fast reimplementation of paint_me_a_flag (v2).
//
// Mechanism: the pmaf header's u32 at offset 32 is a per-op decoy count (0 for
// part 01, 64 for parts 02-13). Each op does one real flood-fill, then that many
// iterations of [fill(pos, random colour), fill(pos, real colour)] -- 129 BFS
// passes over the SAME region, with the PRNG chain fed by real fill results so
// the loop cannot simply be dropped.
//
// Every one of those fills covers the identical region, so its size and
// index-hash are invariant and only the returned previous-colour changes. One
// BFS plus arithmetic reproduces the chain exactly.
//
// v2 removes the three hot spots measured in v1:
//   * per-pixel integer div/mod  -> carry x,y in the queue entry
//   * sort+unique of boundary colours -> stamped direct-map table, O(P)
//   * the second (base-region) BFS -> skipped unless the painted colour already
//     borders the region, in which case the region really can grow
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
using namespace std;

static const uint64_t A1 = 0xBF58476D1CE4E5B9ULL;
static const uint64_t A2 = 0x94D049BB133111EBULL;
static const uint64_t K  = 0xD6E8FEB86659FD93ULL;
static const uint64_t D  = 0x2917014799A6026DULL;
static const uint64_t G  = 0x9E3779B97F4A7C15ULL;
static const uint64_t HC = 0x243F6A8885A308D3ULL;

static inline uint64_t S1(uint64_t x){ return A1 * (x ^ (x >> 30)); }
static inline uint64_t S2(uint64_t y){ return A2 * ((y >> 27) ^ y); }
static inline uint64_t MIX(uint64_t x){ uint64_t b = S2(S1(x)); return b ^ (b >> 31); }

struct QE { uint32_t idx; uint16_t x, y; };

static uint32_t W, H;
static vector<uint32_t> cv;
static vector<QE> q;
static vector<uint8_t>  stamp;     // 2^24 colour -> generation low byte
static vector<uint32_t> touched;   // colours to clear after the op
static uint8_t gen = 0;

struct Res { uint64_t cnt, hash; uint32_t orig; };

// Flood fill the 4-connected component of the colour at pos, repaint to nc.
// With collectB, records which colours border the region (stamped, not sorted).
static Res fill(uint32_t pos, uint32_t nc, bool collectB){
    uint32_t orig = cv[pos];
    uint32_t mark = (orig == nc) ? (orig | 0x1000000u) : nc;
    size_t head = 0, tail = 0;
    q[tail++] = QE{ pos, (uint16_t)(pos % W), (uint16_t)(pos / W) };
    cv[pos] = mark;
    if (collectB){
        if (++gen == 0) { std::fill(stamp.begin(), stamp.end(), 0); gen = 1; }
        touched.clear();
    }
    uint64_t hash = 0;
    while (head < tail){
        QE e = q[head++];
        hash ^= MIX((uint64_t)e.idx ^ HC);
        #define NB(cond, nidx, nx, ny)                                        \
            if (cond){                                                        \
                uint32_t n_=(nidx); uint32_t c_=cv[n_];                       \
                if (c_==orig){ cv[n_]=mark; q[tail++]=QE{n_,(uint16_t)(nx),(uint16_t)(ny)}; } \
                else if (collectB && c_!=mark && stamp[c_&0xFFFFFF]!=gen){    \
                    stamp[c_&0xFFFFFF]=gen; touched.push_back(c_&0xFFFFFF);   \
                }                                                             \
            }
        NB(e.x,        e.idx-1, e.x-1, e.y)
        NB(e.x+1u < W, e.idx+1, e.x+1, e.y)
        NB(e.y,        e.idx-W, e.x,   e.y-1)
        NB(e.y+1u < H, e.idx+W, e.x,   e.y+1)
        #undef NB
    }
    if (orig == nc) for (size_t i=0;i<tail;i++) cv[q[i].idx] = nc;
    return Res{ (uint64_t)tail, hash, orig };
}
static inline bool borders(uint32_t c){ return stamp[c & 0xFFFFFF] == gen; }

static inline uint64_t upd(uint64_t st, uint64_t ctr, const Res&r, uint32_t col){
    uint64_t w = (((uint64_t)r.orig) << 24) | col;
    return MIX(w) ^ MIX(r.hash) ^ (K * r.cnt) ^ st ^ ctr;
}

int main(int argc, char**argv){
    if (argc != 4){ fprintf(stderr,"usage: %s canvas.raw ops.pmaf out.raw\n", argv[0]); return 2; }
    FILE*f = fopen(argv[1],"rb"); if(!f){perror("canvas");return 1;}
    uint32_t hdr[2]; if(fread(hdr,4,2,f)!=2){fprintf(stderr,"bad raw\n");return 1;}
    W=hdr[0]; H=hdr[1];
    vector<uint8_t> rgb((size_t)W*H*3);
    if(fread(rgb.data(),1,rgb.size(),f)!=rgb.size()){fprintf(stderr,"short raw\n");return 1;}
    fclose(f);
    cv.resize((size_t)W*H); q.resize((size_t)W*H);
    stamp.assign(1u<<24, 0); touched.reserve(1<<16);
    for(size_t i=0;i<cv.size();i++) cv[i]=rgb[3*i] | (rgb[3*i+1]<<8) | (rgb[3*i+2]<<16);

    f=fopen(argv[2],"rb"); if(!f){perror("pmaf");return 1;}
    uint8_t h40[40]; if(fread(h40,1,40,f)!=40){fprintf(stderr,"bad pmaf\n");return 1;}
    if(memcmp(h40,"PMAF\x03\r\n\x1a",8)){fprintf(stderr,"bad magic\n");return 1;}
    uint32_t pw,ph,v87; uint64_t nops,v86;
    memcpy(&pw,h40+8,4); memcpy(&ph,h40+12,4); memcpy(&nops,h40+16,8);
    memcpy(&v86,h40+24,8); memcpy(&v87,h40+32,4);
    if(pw!=W||ph!=H){fprintf(stderr,"canvas and operation dimensions differ\n");return 1;}
    vector<uint8_t> ops((size_t)nops*8);
    if(fread(ops.data(),1,ops.size(),f)!=ops.size()){fprintf(stderr,"truncated operation stream\n");return 1;}
    fclose(f);

    uint64_t s = MIX(nops) ^ (K*(uint64_t)v87) ^ (((uint64_t)W)<<32) ^ (uint64_t)H ^ v86 ^ 0x6F3D9B21A4C875E1ULL;
    uint64_t st = MIX(s), ctr = 0;
    uint64_t v62 = K*(uint64_t)(v87-1) - 0x522E028F334C04DAULL;
    uint64_t shortcut=0, realrun=0, regrow=0;

    for (uint64_t op=0; op<nops; op++){
        uint64_t raw; memcpy(&raw, ops.data()+op*8, 8);
        uint64_t v24 = raw ^ MIX(st ^ ctr);
        uint32_t pos = (uint32_t)(v24 & 0xFFFFFF);
        uint32_t col = (uint32_t)((v24 >> 24) & 0xFFFFFF);
        if ((uint16_t)(v24 >> 48) != (uint16_t)(MIX(st ^ ctr ^ ((uint64_t)pos | ((uint64_t)col<<24))) >> 48)){
            fprintf(stderr,"operation stream lost synchronization at op %llu\n",(unsigned long long)op); return 1; }
        if (pos >= W*H){ fprintf(stderr,"bucket position is outside the canvas\n"); return 1; }

        Res r = fill(pos, col, false);
        st = MIX(upd(st, ctr, r, col));

        if (v87){
            // Measure the region every inner fill will see. pos now holds col,
            // so this pass is a no-op repaint that absorbs any neighbouring
            // run of col -- the region can legitimately be larger than the one
            // just painted, which is why it cannot be inferred from r. The
            // outer fill cannot answer this itself: there its mark colour IS
            // col, so a neighbour already holding col is indistinguishable
            // from a pixel the BFS has already visited.
            Res base = fill(pos, col, true);
            uint64_t v29 = K;
            do {
                uint64_t m = v29 ^ st ^ ctr;
                uint32_t c = (uint32_t)(MIX(m) & 0xFFFFFEu) | 1u;
                while (c == 15919839u){ m = MIX(m - 0x61C8864680B583EBULL); c = (uint32_t)(MIX(m) & 0xFFFFFEu) | 1u; }
                Res r2, r3;
                if (borders(c)){ r2 = fill(pos, c, true); r3 = fill(pos, col, true); realrun++; }
                else { r2 = Res{ base.cnt, base.hash, col }; r3 = Res{ base.cnt, base.hash, c }; shortcut++; }
                uint64_t t = upd(st, ctr, r2, c);
                st = MIX( MIX(t) ^ MIX((((uint64_t)r3.orig)<<24)|col) ^ MIX(r3.hash) ^ (K*r3.cnt) ^ ctr );
                v29 -= D;
            } while (v29 != v62);
            for (uint32_t c : touched) stamp[c]=0;   // keep the table clean
            touched.clear();
        }
        ctr += G;
        if ((op & 0xFFFF) == 0){ fprintf(stderr,"\rop %llu/%llu", (unsigned long long)op,(unsigned long long)nops); fflush(stderr);} 
    }
    fprintf(stderr,"\rdone %llu ops  shortcut=%llu realfill=%llu regrow=%llu\n",
            (unsigned long long)nops,(unsigned long long)shortcut,(unsigned long long)realrun,(unsigned long long)regrow);
    for(size_t i=0;i<cv.size();i++){ rgb[3*i]=cv[i]&0xFF; rgb[3*i+1]=(cv[i]>>8)&0xFF; rgb[3*i+2]=(cv[i]>>16)&0xFF; }
    f=fopen(argv[3],"wb"); fwrite(hdr,4,2,f); fwrite(rgb.data(),1,rgb.size(),f); fclose(f);
    return 0;
}
