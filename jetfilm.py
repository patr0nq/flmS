# PATR0N
#! 29d4e91c0aacceb5b8784eba66bee3d80ecc69965440c3c3845b1d6460a646a7



import hashlib as __h, hmac as __hm, struct as __st

__SBOX = [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22]
__RCON = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54]

def __gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi: a ^= 0x1b
        b >>= 1
    return p

def __mix_column(col):
    a = col
    return [
        __gmul(a[0],2)^__gmul(a[1],3)^a[2]^a[3],
        a[0]^__gmul(a[1],2)^__gmul(a[2],3)^a[3],
        a[0]^a[1]^__gmul(a[2],2)^__gmul(a[3],3),
        __gmul(a[0],3)^a[1]^a[2]^__gmul(a[3],2)
    ]

def __key_expansion(key):
    Nk=8; Nr=14
    w=list(__st.unpack(">8I",key)); i=Nk
    while i<4*(Nr+1):
        temp=w[i-1]
        if i%Nk==0:
            temp=((temp<<8)|(temp>>24))&0xFFFFFFFF
            temp=(__SBOX[(temp>>24)&0xFF]<<24|__SBOX[(temp>>16)&0xFF]<<16|
                  __SBOX[(temp>>8)&0xFF]<<8|__SBOX[temp&0xFF])
            temp^=__RCON[(i//Nk)-1]<<24
        elif Nk>6 and i%Nk==4:
            temp=(__SBOX[(temp>>24)&0xFF]<<24|__SBOX[(temp>>16)&0xFF]<<16|
                  __SBOX[(temp>>8)&0xFF]<<8|__SBOX[temp&0xFF])
        w.append(w[i-Nk]^temp); i+=1
    return w

def __aes_enc_block(block, w):
    state=[[0]*4 for _ in range(4)]
    for c in range(4):
        for r in range(4): state[r][c]=block[c*4+r]
    for c in range(4):
        kw=w[c]
        state[0][c]^=(kw>>24)&0xFF; state[1][c]^=(kw>>16)&0xFF
        state[2][c]^=(kw>>8)&0xFF;  state[3][c]^=kw&0xFF
    for rnd in range(1,14):
        for i in range(4):
            for j in range(4): state[i][j]=__SBOX[state[i][j]]
        for i in range(1,4): state[i]=state[i][i:]+state[i][:i]
        for c in range(4):
            col=[state[i][c] for i in range(4)]; col=__mix_column(col)
            for i in range(4): state[i][c]=col[i]
        for c in range(4):
            kw=w[rnd*4+c]
            state[0][c]^=(kw>>24)&0xFF; state[1][c]^=(kw>>16)&0xFF
            state[2][c]^=(kw>>8)&0xFF;  state[3][c]^=kw&0xFF
    for i in range(4):
        for j in range(4): state[i][j]=__SBOX[state[i][j]]
    for i in range(1,4): state[i]=state[i][i:]+state[i][:i]
    for c in range(4):
        kw=w[14*4+c]
        state[0][c]^=(kw>>24)&0xFF; state[1][c]^=(kw>>16)&0xFF
        state[2][c]^=(kw>>8)&0xFF;  state[3][c]^=kw&0xFF
    out=bytearray()
    for c in range(4):
        for r in range(4): out.append(state[r][c])
    return bytes(out)

def __ctr_decrypt(key, nonce, ct):
    w=__key_expansion(key); out=bytearray(); counter=0
    for i in range(0,len(ct),16):
        ctr_blk=nonce+__st.pack(">I",counter)
        ks=__aes_enc_block(ctr_blk,w)
        chunk=ct[i:i+16]
        out.extend(a^b for a,b in zip(chunk,ks[:len(chunk)]))
        counter+=1
    return bytes(out)

def __hydra_aes_decrypt(aes_key, hmac_key, payload):
    mac=payload[:32]; nonce=payload[32:44]; ct=payload[44:]
    expected=__hm.new(hmac_key,nonce+ct,__h.sha256).digest()
    if not __hm.compare_digest(mac,expected): raise ValueError("HMAC hatasi")
    return __ctr_decrypt(aes_key,nonce,ct)

def __unscramble_bytecode(b):
    
    result=bytearray()
    for byte in b:
        byte=((byte>>(3))|(byte<<(8-3)))&0xFF
        byte^=165
        result.append(byte)
    return bytes(result)


_9f92ae56b8f1=[29,69,5,224]
_ff104ede1aeb='plcAkAqYh'
_777932fc52c5='ypMdXNGgSJPC'
_57849c4c9a01='qrCwle'
_af74a4399e70=[221,56,192,173]
_b406f3853560=[135,38,11,182]

import sys as __sys, hashlib as __hchk, os as __os
with open(__os.path.abspath(__sys.argv[0]), 'rb') as __f:
    __raw = __f.read()
__chk_marker = b'#!'
__chk_start = __raw.find(__chk_marker)
if __chk_start == -1: __sys.exit(3)
__chk_end = __raw.find(b'\n', __chk_start)
if __chk_end == -1: __chk_end = len(__raw)
__stored = __raw[__chk_start+len(__chk_marker):__chk_end].strip().decode()
__filtered = __raw[:__chk_start] + __raw[__chk_end+1:]
__filtered = __filtered.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
__computed = __hchk.sha256(__filtered).hexdigest()
if __computed != __stored:
    __sys.exit(3)
del __sys, __os, __raw, __chk_marker, __chk_start, __chk_end, __stored, __filtered, __computed
del __hchk

import sys as __vsys
if (__vsys.version_info.major, __vsys.version_info.minor) != (3, 13):
    __vsys.exit(4)
del __vsys

_1a79ccb2c3f2=__import__('hashlib')
_756dd19b0597=__import__('hmac')
_324ef55a627f=__import__('zlib')
_226191c6863f=__import__('marshal')
_dbb169432d0f=__import__('base64')
_9636319fa648=__import__('sys')

_e334bed152d8=4322509
_105e473359a3=[216,81,202]
_560fa49e8115=[24,162,136]
_baba0e38d067=[228,26,180]
_4b22c03322ba=[227,115,168]

if 114326417683227109 == 114326417683227110:
    _4d865f2d364c = 'yubhoqAhroeYgsQeviiLXlsY'
    del _4d865f2d364c
if 880392613682327947 == 880392613682327948:
    _08f7caca486a = 'JKzOQgnSveWdyOSLcVxDHyJJ'
    del _08f7caca486a

_f6b44bb7fc3807='xi$I~#SH&t_QIAM<;!Y*cmX2jGVF<<F9nBs7ZdfHWtNscH1yj0PffOMPwbqc+k{#N$p6jB|Lg9RyyXF;U=RC_TQe3c&zGlu|wELwP!2y<co(OhxEhcb%baqXTa?!%;5VR;dB!|5LN=1C5i8@FHl~ddXIGnlf%w6OqlMTAepQozjx+fp5DQ_*~JMVD7No>F>t0r<)f34iWXFz}<TE(tRgK6i8S>-@?Fpn|1smS>%IVdSE4#v$n*v`1?`-9iG94=IM)Bm6Wz?7#ksm14C#adY!}oCE0ygNK{x*r~48zJsyN<6VGqznR1&<cwAr0D_)>eJFt3-5+$5nWt#howlbGxTEp5X76>O0%raPL9ymU2JKn!Wh35|mqk6)A<kDb8@(NuY#ObOX7fHu)(pGVxBF%u}3*<j@1H-V()7DOYfO6M9dupP=-&*|**E=uKj49EVSBZUseJ=(ArnTi7LGQl`@f<&*gKk1hP?a3QaEig-bw9OLhmVf0|LxZou0|~|o`C!bbv?KyMf@nD^T)AYae2;5HeN8tyHGAC7H_O=?K#6a%1Qzbi?PN}`wY2)2AGL=pVeN(<O4^~fyekpAF5=xsgBTKG31fxv2@fR+oy)WGmcOv^es+Qprbg#_95GHYv<O}QcU>+;fFd}HKNi*RK~q37*Z(TCWddz=VgCYI7zbG<z_(v=Xp-;l1^%?qkvJTGlEAIb*Nr}a*c5}t3qh!Qzz<PB*Ow!I}~^Y*-|1iJ+^JCEE@R$'
_cd5ca8c10f67b3='Zzhf}Jq@E^xDWD1pWKV<ZPnftr^zV-cuY^>ot<}cLNdve9feih4U^K)&510MyRMpi6fvG<30|p%kAO4n$|Y=yehs^I6du}3e90>W_=pP+X3RhM5Er*){)B+}*o~=UzFb5qGQz5RVc=6y3H?5aW$dO&+4O_K6Vvhb_O$4(L~;%9NdD(((x1$=Th<f*_t|%iv54O~=nXd$C18X2iL53vOyQvP@uqwE{qcfy&#WrpT7#HPanudVR4&04k5WFZZaF1K?>_rP5x$F2eIJT^8Q!K<8-E$k-HBWoV>bLI$n$tjII<fHxGc~L!it1y0!~N41#Hs-zM2dq{3^b*+4`&?x>}pJ<NN?ixjehMjC5-W;RuVmVxlTz!74}d(b!~aq1k}W;#<wwxOJC^!yB^pj3C?QT}A~Y|H&#za=NwgdbCYtxA~W~oIr~B@*d$(XP3^gi&x2*aLXvnh~cxJ0$@cN59J9^yebpOUGB4}*yp6)B+o`-arbILIo^d?n>>Ttc@b;lc7#%evQp&Zs9MEfCGcBD2j@1E*yKON(V}YTW-O~K>@3d0QOpHD?l20BQedvxSLB4lh8jay$+TTg8_JfoirGz-3ia2xbD5W<-MqG`(+eTRofY;}yL}}UY@Ed74R{GHfTnMh&8vn1cz8$41OKwdYjkSkfYpsJ!ZP0K{#}FDSG5jHg=ys7Z=OIg0;2xwJF0&SE=+sKUY-vQ+gxtHGyjvx&aJ+<Roe88DF`09#WkFv1)uHbbSn'
while 633775982186284168 < 0:
    break
_41260d0dcd545b='5p>+M)dZUJZB^3zuMi6qepZO!?epz+Tmdeky5-#dFO_CLkk!?JAp$`ewBbO&H8PHSLbuH`bE*Vx@Ht=3Dn+o+WQa>~XG?n=BRoZ@aFLag6%565#1vcsbM>bBlqRCV96EF-qmOIbB%glSi09^XVLJ612JH3n(BR`Jbbe%_*R&!!^_zN7)R|!2pR3Q*^YO4UuHc&T(PeL22AoYg2;)22u(#teK{@bIaE<ukuxheVb5iglBhDJWH@{v*@o7c#4ZEu%B$4;eH%&+Qidkm>-Aen3ae4swaoZ*0@+R>00tnJ8~>*drV)=x^*?rIOTDzs-38j->_v|;*UlDl==L=e|dX#>_4d<q#LlG&g69Sv49$B9HrF0p*ij+L++VjUkuz@`H<=6_p2rnTr5*i!KX3CtX$OCA$6G(x)z^hG}x)GuWRPC<Wfak$x-uBX;?y}Y@XH1%RkFpT;#^um|r0aev-rzO>rX8L<7u#riSg*^(`>`<4+Xd-VQVs!V`Bil9hZ7L@|kMJ9RW`xNM=gh2OE|^uC(pVkAt~eM89jR5Zs283`Hr{dn6FaMa3cAtU(hEyD$P5zps>XZ?N~wR}F@Jta(jJtnl6MivJ>4~xRoL%?EopgK3h1!uSS4m7f*}r8t!}>Qz6z(i`Tv{{jP3ewt66`w^=p@e!M+baU^OUW(GWp<;%WWRY;#26;!0`~OWnoZ>S6hN&M(}pq=(UUmOTq=V+f%75*9(cyD*fCA^l*%BSu$~&xxJlo1'
_126bfff4068b7f='1-P&Q!pf@Lu4;$N%!y|f7pns<g9zA2c|qY7r~k?UwND(Eb(qfr8$`!?=xhG@Mrw*m+YP_oz?t?8PFKp5(?4Lx?KJ<k_r6wpG=qWQHpK~*p>^sJ37ou8Af;#Y~^pb7R5{>g1kbOrl20uk&kJB6JS6x`_U4v0Y*^BuZn1@B3q-(%eCgY-5v?tosHbr_HlZfDp#E(xe$9+TWY{j1nTPM3Ob4w2d43|>;bo4EN+G-`o!WOlb9)T>iV1Yd_qs4ZmQ_dMW4?3gGuXw`i>fy1WG!9H$2R&w{MVJ)s9EDGi3Bj?tOUbEpDJ#G^$aqg04AO=icD8Z-jfz=e^G13b<lPe;+L?FRkCck7_Z^{hhnxys(r7qt}$>==Lc2e6n_j?L8r--G>OrmYIRMH5O@fbF&MF;Ldhx{*qovFf<;%zJ(|4ib*Qu+Xg_r@@(K+EW=8sPVJ*^_p4u?Kucp>1_BB%arC@S2jh(t+9WhFLx^Ut?-wGNbcSt?jfC^CnPv*&1WRg58KbWO1W50T{fy~G2-1L=3&&t_(gf2$26_S8{#b9nxJ>pfZjz*D(BpY=gYzKs$~b>V#%f(LOP+rXZO(j!YNrUPA><3PqM#V>Bmn&w{~sNuiL>4r7!+6$26fpWWVx+RGVS>1Qm7q6*k44-BNqr03`1iAI3$jBNd0cjCF>@#W&T5I_e-+dgq(61HD{~a2lRo7d$wbbx1YQWN93^Pk6PGpc~68qMOgKp^@vTRJ0@RE4D*%_HBEO'
_0ff7412cc52675='T9{ULbg(VJ{1qmHg@+<Em_V8z|oQzujnBzUI^OP97FU{8$23Y)Oec@eLqLScgV8zfM<bCUG{aEKTiO@^dLp4TW|O!yPj`yA-XJZY3bA+5U{xPHc^$U-+Ait^`)oz<gK`wq3bL@S`Nxlt|Fmavf^dYWyns#iBRWZ}nj&MX}{(AQ*175RSe0dwI^gdGi;M~t+aJ2h5>YZ7K>8>roWjda?WuQP;MRjgb2E{Cgp-*G!CV-q5{NFL|JaBq7?qW`v{A$}I<2^SwT$Q2YAoS3|4&9wD=Ht#yQsRYn$ZfZI)LtJ(Y+MLuXF@HK{B1j3w@1;quy%V;U6hY*@p}=<p^VeLj+lXk#Tp}{*Is}H;2f?`)N&*YO80pmpvY{DMvmiaz-)xEno`6R!K@vV$thWrpuDbewfKssUlPTkO=cWnat<t1d*Vee;uiWUANyW`eRF&Wd*MU2^!P!QT+=kzkRxY>Cb{y>)(FjDt=^Wz|5~DQv=WozV95QJdXu_rr%>)z)VY{BVB<YL%)>)DzBWT(hgrFtMovsM}6vN*@Op>A^e%0-aFk)it7VaB`WDkN8$4w`WXZ@V1=lrBHquvJX?3u>60hxs{^)w(;M!b^4BJs6!oNtyJU9U>TKI)7f_vrQ)2i7n$9RC<f*JI2VOcx(qaj<l3Ol7k#>eQh5P+|7zA<|HOeSNF`-isM;qmVTg#Vbp0+tN;xDwWf{BvNhI-Z-{X+-4d{yQrs!s8-Na%2!9>Uq(R?d*?4$W'
_b9f4cece16511c='PPg})apBJqlTiWaJ25zG{CY&~*joR*S;odnie8Gx(8^t03z;l`b?W)XPWeUZFhu>>|G>^>G`<$s4x6OxX4Jh<fs&3|%6m>qzevUcczSF8Tb#hrzQAJUREc|wl?%H3*Xg+N7|YG-8jW<+A#pKv2>4sZK@IRpJ(`(C#_raMUDzL{BAbZJQpKYf7Z7ULw}vNNG=qb$=|!|cLj-Q70UIn$um)>&*2^iQ!TK^w+|5a@yR&!(LgL$y$;y|rViylamwzA=&;%Ro;i=T%#O*JRvuL|d?KxX0HThjNC~h@xk_Cuos1Z8GdD}#&_cw4vXJqqKVJqfyFRc>{-hf^nn2%Y@gKbxL4NRRfF;+5S1mD42-gf_Ob57FzE{(i+w&k!P{TvS;Itxafb&#d>z+BY5B9pWLf*;H}?Vw=!nss1Z$8TGMBAev^7K+sLlP3{5AWIm|!BM|8-2I4U)bS>rdWuM`nezv2v;uIu`Hxe8kd?&`y+joC{zGT|P58oOA@%kXD20CDJtZ?AOW5Kul;RK7`5NL+YNV;&W8BW2Vo9v=S_!6Pl~##7QWn%uuy*b-GbI&hz6?{Lm1s5Rw9O)&X~uwrBPDC|AmI8Ygb$ms8WSWHCuz8*wTc^)uOVHTe_A#+5c8EC>QGd<D+h8hTYX+h%4_)<Fnpx=5okDS{H!Jn=V7L{x6*WdR_5{ZFZ;ucp-SSkdh&OME_&=_DhxwgS?(dl)@k}ivKBD&p!7SHfXlyEfs9BYsCfqZ{HM'
if 914578278477828942 == 914578278477828943:
    _2b2649e16eca = 'mDTqlEiLMdffUTijZgwUVgMi'
    del _2b2649e16eca
_6ec001fb989457='utTnC_?BU}Rxw$PreJ@2Yr!~iLii=@Dp_cIa)&l=048CyiXW4C%(wV7XHGxdg<vcg*3=#B;;eCR~_bZr^qHz$i>2aS*O8o;mPRf04S<bk~BFwdBvYwsUs4jl$J)|H2@aII9(R*eGbW2aDH$|UO8M_b=gSUnK%Sq()?BHBPj=(BdvN3ruH?3U8J+9P+qS7B!kgLdbWy*)5s841m05r_QlZpYM6GNzxf?3P=#a3tsw)^a_59eZa}TRVmwX)orqos|HcZF-6bR4DbWWoiCXIITNC2I}|>1z7MP?OSGbG@7$r#QRZEtHskYIc%Bv$##T|wy-XAV>>p$6<|jj=C7G1Yr&IsEO+n&sxayi{dI=p4SxH-u4GA{rQ@C`y(+cmM2sC}cX|?#ue?DQ$bWi?7_J!#NQ0DjV&4dv0QVTQ`~v9t&cOl%wXmfAr(io&t)$B-gv-GpRS*j+a70^xK%)gnS-?zRyFa)ygl^_M0=HtEQQy78iN~vG+D-Nb4!d5lZ6RoS>iXUqE*}n@9?d<5G5;6!{V<MlbqI;yi)x*2TN`O{9oZy(ZU1IEeu+}ni!JuXqc7<5g1W&6*N%cAo<PCF67p?<XP^q_h&ww?tyfh@-hlqRyNIU+RCPi`Z&Rmm9FvoMqy|YR_Ps-2vjd-5W+@ljV|UYr0}<*`1}7Nu{DE#W5F#V7P<a9${syf5{zoGK;=fM-$L_p&fa%X3W$9aj*xmkSmxT`fx$pE*lTx$6pj@(1iT$>rg{+D=*8'

_81ddff940ecd=[34,207,211]
_ca6088a9572a=lambda: None
_383d5acc9e90=6588013
_cab5b16deff0=8891378

# keys
_a5ad6ba201765b=b"r\xb9\x8aM\xb1\xb4\x98\xf1\xe61x\x88\x92\x9f\xc2\x84M\x01\xeb\x94<c\xac\x1f?\x0f['\xefW\xd9\xdd"
_8dbded1774b1d5=b'\xd6\xa4\x05\xcd\xfex\xe5\x9c\xf6\x95>\xfd3\xa2\xc80\xd0\xab\x9d\xff\x9a\xa3\x83d\xe0V\xdf\xc2\xe6\xd1\xcd['
_517c5b064cc644=b'\x08*R\xe5\xc4\x11\x1f\xdbx\xd0M\x8fg\x01\x86Z\x95\xb7q\x800\xadm\xcfS\xae\xd5NJ?\xcb\xff'
_afa241c8dfb0=bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(_a5ad6ba201765b,_8dbded1774b1d5)),_517c5b064cc644))
del _a5ad6ba201765b,_8dbded1774b1d5,_517c5b064cc644

_83e4559aabc732=b'\xe3\xbf\xb6\xa1\xc5O\xd0\xa5U\x93;\xda@\xd1\xe6jJ\xdaj\xfb\xb9\xb2\xca\xe6\xb3r\xd1\x9a\xbby\x01\x0e'
_1e63893e172dd6=b'Q4\xa2\x82@\xfb\xf0\x84\xed\xfd\x89@\xdc\x96\xa1\xc8~\x8f\xba\xafc\xb0\x00\xc7kw\xae\x06[oD\xed'
_ef32d3b4e6563e=b'\\W8Dp\xd8\x16^s\xcb\xbc\x89\xfd\x95\xc9\xfd\xed\xb19O\x9b\x84\xe9 \xa1\xe24d\x86\xe9wg'
_a74cc6d1299c=bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(_83e4559aabc732,_1e63893e172dd6)),_ef32d3b4e6563e))
del _83e4559aabc732,_1e63893e172dd6,_ef32d3b4e6563e

if _9636319fa648.gettrace() is not None:_9636319fa648.exit(1)

_c51d96c5c477=_dbb169432d0f.b85decode(_cd5ca8c10f67b3+_0ff7412cc52675+_126bfff4068b7f+_41260d0dcd545b+_f6b44bb7fc3807+_b9f4cece16511c+_6ec001fb989457)

try:
    _f7d756bfad76=__hydra_aes_decrypt(_afa241c8dfb0,_a74cc6d1299c,_c51d96c5c477)
except Exception as __e:
    _9636319fa648.exit(2)
del _c51d96c5c477,_afa241c8dfb0,_a74cc6d1299c

_afa825248462=lambda: None
_d2b063f3631c=[158,99,168,184]
_96f1f25fdef8=lambda: None
_724b05d8b75f=610046

_f7d756bfad76=_324ef55a627f.decompress(_f7d756bfad76)
_f7d756bfad76=__unscramble_bytecode(_f7d756bfad76)
exec(_226191c6863f.loads(_f7d756bfad76))
del _f7d756bfad76
