# PATR0N
#! 5433ff722730fec57fbeaf9432b1777a05810907cdd43cb219b6774810d142c1



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


_09ce2eb21818=[229,55,141]
_4d95d34c325e=2544204
_6d84edbccb67=[169,87,101]
_23a3addbf669='RfepMqsQNfgMV'
_2755047a680b=317609
_bdde58d410a8=lambda: None

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

_7bcb43555c44=__import__('hashlib')
_4bda455f59d3=__import__('hmac')
_761a1717d753=__import__('zlib')
_164d88d7523e=__import__('marshal')
_01d8a5fd8344=__import__('base64')
_8b2485ece71b=__import__('sys')

_c827bc3273f1='CDWhxpHnfIEugXm'
_aa9aed51bc89=[73,215,204,28]
_c1a1fcf9d849=lambda: None
_c564ce7d8dec=lambda: None
_1d9c48af843f=lambda: None

while 511277040245044097 < 0:
    break
if 107872023222461924 == 107872023222461925:
    _2ced92467117 = 'HdWIyyFCCUkHlvwshJTwUbGA'
    del _2ced92467117
if 12209747902963975 == 12209747902963976:
    _1ae8770655e8 = 'eZzWciteGqpiVsJGkqYfSEWs'
    del _1ae8770655e8
while 989561045752609115 < 0:
    break

_14efa0fca9d087='1gqQIzOs$9I$aPigVC0J71fvTQ;_cR>G&wJ$Bg#$I|INF)4i@H4kz4UTe0hNh>o9xMXMJ+4-n`juFs{adU#otpZ)Nm5EhaVpp2FEd_<JQoLaxC@9@j}X*QMgACu{rv&<UA2VVTz$2B}RJPBsTtmMZ&4V-8|9zFW6kaX;0%?0d|o4-bfGM<HA$xmn9gNXySj>voFEE7fGyx>qNy$x0Qza<-iS0hA%1AUB~-O*H|<0~M`QYL_P=HNeOD52G1r4`P0&kXR+2%liQH=x2&e1KsC_%mJ*-H`G8XT0aMb|154H-UeT^tRJO`P7bw@!bVgyqPsMdBglB80zRvN(A?CgoEz?0%RB205Zs!I)`MAywf%;DPR0Bu&^5N*h=kwS0iE0^WzxvBC!S4LE@A^!eG9e}!{yl`?Nf@wqXR@E)K*sG+2rG{_Z3#wfMl=+1BBkrQQJ1K4-mx8obP%W(0KI8bgH1dysls!8qs+^KF(X==qgNM@Ahu~OHkk<iqohzc@Omd*VixhWjb3I`PnfjOEXHHQf5Y;PvH*~jNv3oc!Tjgp@k&!_5mwUHaPijz~kQziF}K2K8RH`_ceP<gD<$EeTM-S3E3payAo6gdK>$(h@l7Qpo?u)7=If8om5~_T%a>jK~#HY%_AW8B_roHI)2}!2XUna+Cowx)(q{P$C->$XiW!d_cH@`n~4IDt%IQ(W}Kc8fUtJ}C>vMXMs5'
if 360981945985037069 == 360981945985037070:
    _36b2645415c7 = 'MUsgggmehrNSUyXQytuYSWmF'
    del _36b2645415c7
_52c1de25c49706='B7kHyu<_wssR_=RxsiUHdjo{kc_q}Guk^W6-z%s*|@T?7GSR9zV`sFpwoRl-PT7wg#hk1wCgGm?1XDs;L>n{)(kfHGo&qchDMXs4Y!d6ZH6w(iDrD@)Z9Mk|i4NLo{H9384=BT_EpJwHEG$#Nb3ox7y&a%^s_8T}8HQ4^3oq@C~EZI)p&k^`n$(xv*@~)GpM+#V^sEKeZiE!fD2I9x|?_6)$l77wjO*-4Cqi)k$K)8^l+-GG(Pg(^6*a#U6f_Yqb{KN*jiFHvKfM3gW2PaRyyJQw{*c*A4?Wv2v7htl+&)gt1EX%4>**T5XGv&Ih!MM&13OHpX*A&=HqYsh_`H-_<F24QhinFF+EpGoG=3T=D_R4#^sTzlDXhYq?H}O@wMW~XS^XdM^4$4Lj2M=l>3CQ7Nb<0TwLm8Ut-1YsxGALx`+x&e>6up?dvRG9oC3o06wMqc)V_<4Uj)E6xuqCaa+f2?vPs1MxV2iB0Fjw4Yy!K4Nbvoqhp)j0CbhVO;IW`!DH7SwZ*#9#_yF1yJfx8s(rOXN~n_o|_irM=TT%s1iHnuHtRevP7?PaJBt2{h|4CiC)d}h=Q91^T+9-8!f-@|yvscUUKPFQ>VAy8jsb#%0C-OX)nd>NQ{MoVq->v$s4l!}bWFbP4=RRJtsd!1Y$%JZKaNt1uRLjpBzbwQ;POV!RBY7zs}#R*M2cU3eNYTjhXnBdl{3'
if 485186186875571108 == 485186186875571109:
    _677f69d21bb4 = 'nYwInWacvldkEOwLyBoRaltC'
    del _677f69d21bb4
_9d0358559d1068='<O@9F1j^OE5wZraEe09X`m7i9u_>_B>DNPLrPZT+A<f=>i^i0jE}DT~2=Z=2pQJe2b{z)1+PwXtgn#>aW!mgS0&O;gxE5@n7`2w<zDC4VC~MZM*kW$S0)mZVikOJa#~U>k#{wwfoSUND+Jn-;_WHNMTVLNGX_8P`vx%|#GAx~=v{uqpsG{#BMTL<bSXWpp>oauUKuZP6NI4OAvcg+HECAzTQ#hz6^T>&jae*F92nK#!q=bp+k`1X+Es;;Z_@LhaygG7UNCwC^qF|HS5)+{aE^E?fbX3(YIo+NLh8n?>{x->*GvQW^Jt2Why@2VG*14szooqy)f9vy6Bx*u`;ekaG_w3J+)%c?Z$;x0RASS>DFS2i$2=h}o;)uQmdN4LoI<FBu4hShE^k;iy8~}Bbk8boEYpgVMTRx5z2Xn9rw>P!y8^&UAESGDo4<>3wLfg80#3?SD82tud(IvcNMknTEV4X0VNQ$!Qnny3C%{XVu9JRwcqsJQMUe@T`#RL;^T9leb#QxA{O@i?#+k%mQfGbk9*C|8wEm3fkBh`43S0b092LT{^MrmkOo=?HTp63&M8y}i?WpJu67SfgQ5`z{$>I?n`1kjvI0^xD>5dA%4iq;?4n*O&qKib<=hoVvMqyX<P<7xlCq7mhofM&bJDx-*KiMXF40@b~pplom25dIh=7TSEi4q*cpkk>GS-KO03zy14~BQweW)N'
if False:
    _c4a54023ba28 = [120, 243, 70, 104, 164, 243, 28, 237]
    del _c4a54023ba28
_b4195f2a16dd6e='00&ok#3-)i&a!Zj-*YSxK1M@&`1->^aH|+c?N8-rL~qJO&>2Jmb!K~qUR{3o{+1^O7&F7B5KVKob-v3IK9a4hM{ytGF%*+RZiJc%Foh;^;}za+<qS^`T`|J9F%LAA{*53mu9R^Y0bmLk1j8zCLS-!?SQs#zX%f<-CNshr{_(x^O<`sFH#>105~%guV%(O=|h{0G2O<eA;(RHv^&3wU50C%Ti=IX(K_G2f_aWc5>ks!-c!ysJn1}Yor%dZ%tDy&9YSH+`<Ac;yY85hEyq57|8bUViKFmC!^9TPpSEiK{?=#yMQ{~W&&u~BDlT+NBSVwD{RCVv5U#KNx-vC0PliYQFypAieL&`kCL>18L?fvdthJt~8CvD{oKN8BJ5rGxT060T<KWY$r-uTe@&JWsJf7%?nVFC4EnCw3$j`qzc)Gx4kNu<Vk+F<0Bou$8cOEnc#~;vp-=qh;z{Gb;q9@M9+jKL+Y~G2vm%sR+f;<EoH(~N*U>^~ZZQ*`zxeIur(p*t-={<V||Jbd*SQZzb?Zjzr1QbD^S)Zma5UW^ox<b7yLkUm)X}e8s?a7H!oe{VI+5-R!Lrt@Fd~yr416cU3`3Wd};pxGW`H3G`BE><2Hu;nH)S|Ueb~iqJyEQ*0&%Lf1`U6AOL}1`CrK}%zt)ImekqHRmCpb5^Ro%4cXPi&%n_&iXJwWCyJY~q;z*V26y4zT7WOfKHf^D'
_abd3143b674a28='rG5d`+8PJpvvpW$}OO6VJaGdvLp0y_AKgAQNnVU;tHf(sf<RtHWM8+H)6={K)cVN6}r`AC)WW>}i3h@huBf+7TqJxJ<&4O{Ns5g|~u>S;Zga$0ge$$w7>nS~}InxN`E;;EG1LVJcu<O>jK?d#LM_VBwHdKXi~l)So~8)rj*?u~Zt}d)0$7c@ewMQLw&AWu)U#8tv(Otx33hv#fLY#{}B*CaeQNOa4<sD)2u}NG`0Su{)yQvyl<17$c=c<bjOcH=$bPBz@QZrAnRm;DGPqRZTD9p7%V#L<6zMg258CU(e(n_vfnguZavQ+JCM@<PRlp1FRa9D-@12PqN^li>x3@hkQV$uub^=)1q|z17sMT6IfujzXbU9Rjr4YT;CRWY?0}^1CV-J=rhN{hrQIq#Dm)w63Doc8;vKwcel}5U!p(!cAjnQPp5K6{6;lPPcAHml^=?#frN*w;<|+daITteL2@4=$DUDj<ENu>vjxsn%oO_==?k1ht+!Q)(c6Lr4YU;;YYi?=^`K)C@0CQXP%U<IeKeoWoJLPb@Y)|#loBsGM>?9^CN0AuR7ocm!blEdWDPe3*kPjtlrEO6j?WO56>!u5T0_V;jLL^~E0tJm*PPJEVQ;Go-zRTv@;LYL1ObJKeA73_Ja+o&KMn7}Tq+};dYuMzK{;35&~9j6&e=H1CG)TYQ~Ofs%^N+RRa8U9CJp$_0d<cP2qb^'
while 211066059650907930 < 0:
    break
_39a00480d80b8d='01@*7>*?{kMIqH&UV8|%7#zv3>{KL^ItnZ+`$pxSDQ#XACy{r>iuzprw^26IquE#oY_Y9uBmP=t3gRo8K5u2Q0mY5knSo+C_2d6*V&GNjY9kR|k!{{u_~{sqq$B_8+Pl;09T6Y)N1UAt)CbPqlZfBS58?5esL=T5p(dI~ABa-VV4`1m_P>nR>UaV*^7j;f54RuE_FOm|u{+I#g&2c@2{?5Mku2C;IqtMMUpeK&Lh4A_3h2KB<PQ3BKMk>G>~pdMBuFZ1Am{^j$LcGOdyiz+;#HP*JY(wRNPwC_Jq0jXSV#BW*ZjYiWRRHxTvchkgv_)US?tIjsO2|y;IfVUuSV|%>^-=2F8BLWQ_w89C>6OpW=1#a7#0Q3%~Lz?HT&5&s^UHRaoMG4!vmaCJrL(F25Wr{{Bb~d-+(5;jbI_OsdjZgzGLf=kcpZwbMKeCVMnQN>;w`fS9NzTrfdzJ48jq|-7;!RCd>(-@IVDQ3xTg|SUlJ~Wy69`2D_TCIA*Xo|&mobn4+s=7MV0Y(8kO{Sre;r4Wt64@^?bja6M?bUqpv6!8r)#%r63X)^*kk4vIK3&vy2`z$3~{~-<I%ZZC!2@^fUWmRBB7KPMf33jrSG+IWO24Z4q{w96{v<p;$nJ-DE|nB{@UXj!6_i(?Z|>O>V7xudzSeU+i+qSqagkXBqb=#_6)U+KnQv~qt`*E^4ae+%;dTmzXKvL'
_fa2ee65e2c3132='<iEKkJztu;FKLO&EZUf);vb%)%L<=;>Pq9r>^ZlVob+=H06+Rl*^tEP0j0?@ELp!YO3B5VGx)tz0@auet_eW=f>;0!(<2E?N`~hQHn40?Wr{;2jvv{$k30#N;mnF8VW9DHGMJQi?!8rcL`+BTPMD(%9$@ka7fm~vgq>`Qhb8JvX>7BCH%^qJ^1SKic$f(~+uIy|%Aq&@Xor-Y(14hi)UX5ilijcGoU&ZI{c&zT93r-5Gt=^D;{AG^cWxwh8kE<S+p5R`38L$*ulTvM<%mj(2Ie4^?MHWsLNf#i5nj1>F9SbLq3g38cE_Yt7(G|;R3jg<sT?dxE*i&Y<LJ23g4oKuY@6De*~-4DAP*qVs~vKXF7`{|LdzjDbPBT5RmQO(CQm)b(d9k*B!|ZDTip^-)#!B(z@-X7dO*Vl-?+@rto-EO!iZ}Gu^;4~Bck*8J*ZwaG~acQi&u{2_sD^i$V40ZQjd=D-y!CiGN&ksFmMUX1)T}aXMHp%>?^qbC=rhxp8;^mwT$3EUcrzRp>T6;UsRi>`gdAl?u9^~k#Uax#(l`FPW-6ZGJeMOI54G4k}r1r+Zc|`a&rD1hlg>s=V~bv7=2qwT)?7=pDQJw_K}uRlN>)%{gpjc!vEa1WMX0KG|!A1ZN8#tk1|Vy?bS?udC(;(b$B<Xyt0I=B*deKGLUR155`dxEJ<bCVUc-ot779>RC)HX(d8z7E2'
_134685c7e9dad7='YEwg&}L#gG8HP)r3v885MvI0!&Z*i3%aCdnvh!|H>z!0{Pw8sT~IQ{cCR^lLYSfZF)<xJ3C-aE*KE<-reK!Adz})toGJ$G`*GteI_CYJIb0O#2k>2-e*1!__S_+K$*{>UX^NJ5$t#6hgYhhnz)|Deek-($w)r4QVs}|=Nh67IoHdF6a?f}XKXz)2}$8ab=@2f8{`B{cDx~pw1iX)txW}OnH_AG^y#nq5Mz4wPlryoF`;4B#3bwv+Y{uso}YUiT48qLKAtU1To#~CGI8pzZP<%r5cl8eb(NncmSc=dsTC}34Fy=wktIs!W6aSL_m)o6MJ`|*Kh(U;H3MrW<;<HWev~W7uL1w{P+SC3g`iR+IJkCd-`3CB22CL>1C2+BFhG8}4p`FO0e6Pz|L*w{Ylq}j@!TzS-%kY9{-@)k9v_0h)E45HaL*jUkJ6%wrtMZ}CdMl@UyL@eHWg<xXmb*rjtLM#`aQ@~e+4O=g9hGD0<}H?c`b1`&XIds&KhpLf?YP-BqH)0BspcEd_sMZMC6c!Fz`(G`{cyR`nQYjdAq=)3{l0i>+Ckukln=Tz;0TH8hmZsb&!5I@zJvE^K#Izi~Y&l_S*2yT_x&<lKiL<h&=Wt`GCaIf`-YV?AGKRDOjTi$fu-#n$dE8Lw_x^q<329+rAUvVu1aRHtO!6wnK<cpolC7(h5)Uiwm=KDlzeIt#a8Qebf|)iONI'

_eea857c91425=5230773
_ec94d871cf3d=lambda: None
_cf75691bf31f=8178936
_3edc4eb6be11='YgXwOiCl'

# keys
_01fc6308303e82=b'\xc1m\xabA\xb3b#\xd5\x86J\x95\xe5\x98T\xa8\xa6\xa9\x0b\xd3a\x1f\x80\x13\x924m9b\xb8\xf8c\xb1'
_18b7d8d52044ed=b'\xbc\x97\x08H\xaf\xd9\xdf\x8a\xea\x86\x07\x8f5\xd6\t[\xdb:(9\x00\xd4F\x9e\\\xa3\x9a*7\x95\xda\xc3'
_ae87d9997f6828=b'luN\xea\x91w\xc3v\xa6O\x94\xb5*\xe0\xdc\x01\xf6IK.\xc1\xbe\xb1\x8cd)z\xe5f\xe1\xf2Y'
_03f642195a27=bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(_01fc6308303e82,_18b7d8d52044ed)),_ae87d9997f6828))
del _01fc6308303e82,_18b7d8d52044ed,_ae87d9997f6828

_632de057f83fc7=b'E3\x0f\x0cXd\xf8\xae\x06J[\x03\x91\xc5\xbc\\\xdf\x19\xc5\x11\xe6\xdaT\xf3z\x83\x9am\xc6\xfa)d'
_274622bdde5d4a=b'\x82\xa1\xaa)\xce\r\xc4k\xf3\xb8\x8cM\xc0\x01^\x84\x15\xd0\x07Zh\x05@:\x94z\x1b1\xda\x06rR'
_6111a3ff51ee00=b'\x88\x00)\xc4\x92T\t\xde\xbajC\xe2\x8b\xd2\xc6\x8f\x1f\xdf\x10\xedi\x83\xe2\xc8\xc7|p\xb6-\xc4\x07\xe8'
_d60e97e6dc88f1=b'\x02\xbf\xe4%\x0f`)D\x848[\xbe\x11m\x9f%\x89\xd8f\x06{\xca"\xb4u\xf5\xb8\t\xf9\xc0"*'
_aede7ce21a6c=bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(_632de057f83fc7,_274622bdde5d4a)),_6111a3ff51ee00)),_d60e97e6dc88f1))
del _632de057f83fc7,_274622bdde5d4a,_6111a3ff51ee00,_d60e97e6dc88f1

if _8b2485ece71b.gettrace() is not None:_8b2485ece71b.exit(1)

_f3a55915770e=_01d8a5fd8344.b85decode(_fa2ee65e2c3132+_134685c7e9dad7+_52c1de25c49706+_b4195f2a16dd6e+_39a00480d80b8d+_9d0358559d1068+_abd3143b674a28+_14efa0fca9d087)

try:
    _e7670409d665=__hydra_aes_decrypt(_03f642195a27,_aede7ce21a6c,_f3a55915770e)
except Exception as __e:
    _8b2485ece71b.exit(2)
del _f3a55915770e,_03f642195a27,_aede7ce21a6c

_3ba8842b5b6f=7875998
_6b8ed235c430='UcAJYruqAtjVoCtn'
_df9c74082820='ELmPDCN'
_461a31605731='WVFkHpZL'

_e7670409d665=_761a1717d753.decompress(_e7670409d665)
_e7670409d665=__unscramble_bytecode(_e7670409d665)
exec(_164d88d7523e.loads(_e7670409d665))
del _e7670409d665
