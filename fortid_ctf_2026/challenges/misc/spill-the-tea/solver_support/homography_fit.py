#!/usr/bin/env python3
from pathlib import Path as _Path
def _self_dir():
    return _Path(__file__).resolve().parent
"""Fit the QR v6 homography using only known finder/timing/alignment modules."""
import cv2
import numpy as np
from scipy.optimize import minimize

IMG = str(_self_dir().parent / "files" / "flag.jpg")
N=41

def known_modules():
    exp={}
    finder=np.array([[1,1,1,1,1,1,1],
                     [1,0,0,0,0,0,1],
                     [1,0,1,1,1,0,1],
                     [1,0,1,1,1,0,1],
                     [1,0,1,1,1,0,1],
                     [1,0,0,0,0,0,1],
                     [1,1,1,1,1,1,1]],np.uint8)
    for r0,c0 in [(0,0),(0,34),(34,0)]:
        for r in range(7):
            for c in range(7): exp[r0+r,c0+c]=int(finder[r,c])
    # One-module white separators around each finder.
    for r0,c0 in [(0,0),(0,34),(34,0)]:
        for r in range(r0-1,r0+8):
            for c in range(c0-1,c0+8):
                if not (r0<=r<r0+7 and c0<=c<c0+7) and 0<=r<N and 0<=c<N:
                    exp[r,c]=0
    for c in range(8,33): exp[6,c]=int(c%2==0)
    for r in range(8,33): exp[r,6]=int(r%2==0)
    # Version 6 alignment pattern, center (26,26).
    for dr in range(-2,3):
        for dc in range(-2,3): exp[34+dr,34+dc]=int(max(abs(dr),abs(dc)) != 1)
    exp[33,8]=1  # fixed dark module
    rc=np.array(sorted(exp),dtype=np.int32)
    values=np.array([exp[tuple(x)] for x in rc],dtype=np.uint8)
    return rc,values

RC,EXPECTED=known_modules()
# Load the unmarked full-resolution photo; color cues suppress brown/red/blue tea.
bgr=cv2.imread(IMG,cv2.IMREAD_COLOR)
lab=cv2.cvtColor(bgr,cv2.COLOR_BGR2LAB).astype(np.float32)
L=lab[:,:,0] * (100.0/255.0)
a=lab[:,:,1]-128.0; bb=lab[:,:,2]-128.0
ch=np.sqrt(a*a+bb*bb)
# Soft neutral dark-ink and neutral white-paper likelihood maps.
def sigmoid(x): return 1/(1+np.exp(-np.clip(x,-30,30)))
neutral=sigmoid((17-ch)/3)
black=sigmoid((56-L)/9)*neutral
white=sigmoid((L-68)/9)*neutral

# Inner 55% of each cell, sampled densely enough to represent the patch median.
# Use an even sampling grid so no point lands on the exact cell centre.
off=np.linspace(-.275,.275,11,dtype=np.float32)
coords=np.stack([RC[:,1].astype(np.float32)+.5,RC[:,0].astype(np.float32)+.5],axis=1)
# Initial full-image quad, translated from grid_full.jpg's measured affine QR grid.
Q0=np.array([[209.7,739.3],[2100.2,739.3],[2100.2,2629.8],[209.7,2629.8]],np.float64)
SRC=np.array([[0,0],[41,0],[41,41],[0,41]],np.float32)

def sample_quad(q, verbose=False):
    q=np.asarray(q,dtype=np.float64).reshape(4,2)
    H=cv2.getPerspectiveTransform(SRC,q.astype(np.float32))
    # Sample inner 55% patch at 15x15 points per known module.
    rs=[]; cs=[]
    for dy in off:
        for dx in off:
            uv=coords.copy(); uv[:,0]+=dx; uv[:,1]+=dy
            xy=cv2.perspectiveTransform(uv[:,None,:],H).reshape(-1,2)
            cs.append(xy[:,0]); rs.append(xy[:,1])
    mx=np.stack(cs,axis=0).astype(np.float32).reshape(-1,RC.shape[0])
    my=np.stack(rs,axis=0).astype(np.float32).reshape(-1,RC.shape[0])
    # Cells x 225 samples. cv2.remap samples feature maps with bilinear interpolation.
    bvals=cv2.remap(black,mx,my,cv2.INTER_LINEAR,borderMode=cv2.BORDER_CONSTANT).T
    wvals=cv2.remap(white,mx,my,cv2.INTER_LINEAR,borderMode=cv2.BORDER_CONSTANT).T
    # Median over central cell area; median dark and white evidence independently.
    bm=np.median(bvals,axis=1); wm=np.median(wvals,axis=1)
    # A second statistic (fraction of confident pixels) handles print texture.
    bfrac=np.mean(bvals>.65,axis=1); wfrac=np.mean(wvals>.65,axis=1)
    margin=(bm-wm) # positive means black, negative means white
    signed=np.where(EXPECTED==1,margin,-margin)
    support=np.maximum(bfrac,wfrac)
    classified=(margin>0).astype(np.uint8)
    if verbose:
        print('score',signed.sum(),'mean',signed.mean(),'known',len(RC))
        for name,rrange,crange in [('TL',(0,7),(0,7)),('TR',(0,7),(34,41)),('BL',(34,41),(0,7))]:
            ix=np.array([i for i,(r,c) in enumerate(RC) if rrange[0]<=r<rrange[1] and crange[0]<=c<crange[1]])
            mask=support[ix]>.08
            err=np.count_nonzero(classified[ix][mask]!=EXPECTED[ix][mask])
            print(name,'visible',int(mask.sum()),'of',len(ix),'mismatch',err,'support',round(float(support[ix].mean()),3),'signed',round(float(signed[ix].sum()),2))
            for i in ix:
                if classified[i]!=EXPECTED[i] and support[i]>.08:
                    r,c=RC[i]; print(' bad',int(r),int(c),'exp',int(EXPECTED[i]),'b/w',round(float(bm[i]),2),round(float(wm[i]),2),'frac',round(float(bfrac[i]),2),round(float(wfrac[i]),2))
        return H,margin,support,classified
    # Ignore cells lacking clear neutral ink/paper, so leaf cover does not steer geometry.
    weights=np.clip(support/.25,0,1)
    # Smooth score plus weak high-confidence binary agreement.
    return -float(np.sum(signed*weights))

if __name__=='__main__':
    print('known',len(RC),'initial')
    sample_quad(Q0,True)
    # Normalize coordinates by 50 px/module to keep optimizer steps balanced.
    # Nelder Mead from good affine initialization can refine the eight homography DOF.
    x0=np.zeros(8,dtype=np.float64)
    def f(x): return sample_quad(Q0 + x.reshape(4,2)*50)
    res=minimize(f,x0,method='Nelder-Mead',options={'maxiter':2000,'xatol':1e-6,'fatol':1e-5,'disp':True})
    q=Q0 + res.x.reshape(4,2)*50
    print('optimized',res.fun,'success',res.success,'nit',res.nit)
    print(q)
    sample_quad(q,True)
    np.save(str(_self_dir() / "homography_quad.npy"), q)