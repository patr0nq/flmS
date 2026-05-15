# PATR0N
#! 418da4af676e52fe2beb06af21e7888554f6d765fa93b52e5374a76140a034ee



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


_414d45c26154=2036755
_c88d12afde4c=lambda: None
_871495701752=1165388
_7fd6483b58d5='aTashHLCEMWjfXEH'
_74a2a2b86b2a='gLmeOt'
_d3b5df5ec0e2=[50,253,55,235]

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

_677c5e28989d=__import__('hashlib')
_c63d11c1d662=__import__('hmac')
_299b3b08343f=__import__('zlib')
_269bcc66b36f=__import__('marshal')
_968014f9426e=__import__('base64')
_c1f6eee20639=__import__('sys')

_0e9607559198=[10,52,2]
_cfd287e66946=[156,184,191]
_cb327de75c91='kwOvZNIGi'
_794f709f2179=lambda: None
_cc943cc1d8d3=[242,165,236]

while 478307320378548948 < 0:
    break
while 552102934976164157 < 0:
    break

_9e21fec7144f99='GO~Da7DkCi(tvs<auf+oq?ku<GO9_flO#4FVNw3cdpP5_dMx@4o7HD}B?jSz0SiOP&Z9kBp3EN!sI?N>(z>8I($`EyLM<yT+H>cnq(GsCKC%32z`XP?HFe7_0zDgcxB*i1eK-BIlqVNO!_kIW$h_ORir5&OpBO?&JQKvA`9P1{xC$=QUH*b)6sOcD@W8Q3TbFTI)ZR?)dKk}0JBXwygQ|u&V5pvO&`t+&d8jptc{{`uRwz_3i<nCdAAcG4+N&WugkD?|9Ejj_N{i$4xVD_0+p9gBMw?uaRplY15&qzx0WI)_%}w96URg`!<?OF;Dg3u9l%$_TG#p7Rx5nG$R}$J_dOKioJGd(&%#Ab?({mLNP~Kv`z*$PM9lyDYi@;5e$O2+hXssmUjEzv7(o$lbGN`VU&b@P_Bfrq@;wCtQ0ZV!6^!~LoxL_mj!(JiKvIAvOGM-QjwL_z+mPB@!xQZ=4vl?=hl-=M8Y{Il^B;+G`R|YnWG#c<eLCrt&ALr@+#$N8!S@{*GHpy=-qhwK2bgz<sN06(X>DB!kfNRk<x7Fu|Dq5RZ#n1rF5(9JTWPG=m^t_S6&y}oC#<kZ1_AwI|Ko11^z%0jdV3jZI&hu@y@!64URlpu}<=dXW^#JU7GtHQy4WmKZxOwEoJ|!WX|D{^F`>21U_3z8IzH@L!0L9g9#h_Ljety>Q<Oi$OI^@Fc5hIz4ZLug5am6ZdsH^#;thQ6<cwL@eN#==8z+WV9d3(h?@dRv>89>;jxk`iU&+T2#W|-)?N|A4KA}zJY=QWc`5y(gIGwbPF>q`gW!bW~W6})T!L#Jk@+|Pv6Ft;Mb!PNmKt6skrs(SM)Bas%T5mch~gC&p|P6vbV(kT+H<_Nx%a2<?|h5<A2kZqa}B88J1^nu*EDDx0!2pAnQJzv|&P2%<N|C3G!U{hFKDk9{l+USmv>~1ar+rc9aZzhRKUsy4*yN+rU'
if False:
    _9a8bbaaee647 = [92, 49, 139, 43, 240, 128, 29, 0]
    del _9a8bbaaee647
_b1772096f60d18='kf=1Y@T6(vECYlrVJ`bOBh0sQ6Hd=m81VLKdCOgyCiJmI%xk@H(TCPt@q)kVA1TJFMjTxuyeVBG;>wZVj`lF5c*o*L)wfR+jXBc|DsYsVh~Psgeq4uedKCE$e$cK^3=$r`2QZoy_8acQzL?7s#-%ks1zMHAvu$hr7~M8bcjFk~<DfOzg0&tXBsrsgDm+vXhX_j4t%_CQyXjK0Wn(x_BOX79g=dLWaETZwy68FY=>ODOp|)a4F;ga^Z*_!P?~&P<C5YZ2V06Wt?P9ICr-%3HvTWcjPC9W8glGP@$au*|VtB}xb5g~WeKB?61QoLUFugKYk#C|`CGF#FZH|>7Dtf)bdULy#5QjB%)#$b@V?@rm0soXE@R^F(66h4XGNxcgGAHkhM$|!mrL?U8A5hw!m9}L9JGi8TSrvX8)(@Wc!`Xxk{7ZX5<x<}=_MMo;r@ug5n<7g?^NJ75Jomgha|CpRpA{Gqq$_d-_;>EZFpb0b{UNlY?Pr%s6EsOxO*p|EOcTf{L-vo$zpn<Wt3(RvrO&ise1e<q*tL?AYO>%c4<p(cj{!tOTzHC{mT4M;Udd1-Bp}yi1gHI(eC*E7KzgfM-$6?_B*0JrV?|I@M_?!DM1;0H<8qY4aS6f8?Vhf-bTtLUEkFzTLq;u@l+|I1YO89!6KfhE7bVuXjxs;t?v-iurof6FLh1%Ak8zDXuEQ5TN>;Jwaa$xvK+97Dn;Y`@-xHtZOr-@?jOx@uDuI$VD^DKPLXj0Hy7E{uzJQq4Yuf{3<^i?UvhdyS*3p5pcZtLWR!IX?b#En!=jI4RD^B-&z;b0QAuq%HsyB{*Fd5DPzllOloWFBD%0AA4Q+{lP)DM7@zRu`FAdb9Lz59P>(tnGc6*?h+*U_xk%7uX+(DS9YwKXic7Sfm`!3Z6Ua=x1AQ{3qzHqn{p7itx*RrXF80^BaO_Da3C|7H`Z#|Fi>c|Q%WCPu'
_4e17c282b44acb='AP8a?em;+nXq~4sukiXXFnsZ%k8xhE3e6&MDUfK`rg~tZOz_5W(Nk`lK?)E(msr7YZ&+g3?XDRoG{RZTZ|Ee^<%>q(YF3cN5j*?SXI+$VzMKOPL?D)^5A}F2=~mc=+7q7KdES87}Ic|98>$$nq=5lTt-ECHrTOuG#x{o`YT(-`&qz8mm3@OnJ|}tfX5$?jM_+B5%muKniM2VGR18i+5PkVGh!QHPGm+^rf2NV5D~Am|O+K7Lkx(=eM%w&Ujn|w|WTJ(S)KEpjZ4P$WA{h#hgw-graF=b1C@bYj5T%PM^IsPxI1C4n|y^M(G*aBg9)49_BCvmS1MJWw)yV=0W6Do^(^Qb-KCZ8-cz@Fq+O;(GgVqhl1<l^4USI=Mx=8*YJaFfEH-3X+wOK#i`ZMOhQ8v5U-<i0C<4dmpc+PjN*<XCSK9aE#S~U%87G-WJRpBePxa<>ZYS03|c}e*%14x8BrfHsA!-{a8@gOE5$LNsNww+CPM_>@j2llo0r?`%nX`|kX`Zg#TGC2m4&C5k0F^`?<#X~p5bo?PLq|_x|IvCS>4~<Kyz()e{%A;DanP|rM=-wZu?p5C3yi>#%49Srq+<N^TiHKMsb!8mR!B6wYL0UQPhJ4Rl&xEN15aLSLzvv7tsCI+p~8wb(npogW`lccbh_Rd7(&q#B5q*M4x$1mj*5bqPlsx9q8WF)XCvrGiodNbC_7s^P<Sq`&3C=ftA+%L+Ztekm%_LD?lVJD6h2%e=(b<RP40Q@2#@6WsG)WA0lHwz-~@NAo$H|%0WYH<_xTmfHy{cjN!ZBlN;CNWE`(HIO5)e?ru7VNVnYZkO%=A9x^oAr94K^<i+xYF1nyju6i5Rz50PtIhir&S4k^C`(Kv3RJ2NHG80X5CN`y=G0H?RR7bccKix=~VB{?}HvS9=Ee0K-*x)w1T8;%MKzA0Y@qN&qQlO<!6MS34DhG63-5R;R'
_2e43ac37265c64='DTwHx&c#|GVmRL&xBM*JkyWP@qUwa3cVw)?_tW4mlx;WYp`5UQ_U&#9;KJ%-x6&dbwK1+uYU<jtM<cof3kwE{VbVk32Od7~Cn1A%}AgkmKY})l7)pF1>pn@YR=2_|!QfM&A_(SjTr@WRGEoZhsX-jjt35MGT_AGxlU9E+wy73Q6{TkW+a^lfTthr>q=y?@g-pzKy8b7rIfgv=hqAfkYw=F-!a!S>-fnyzJ77$>32+WV|xYHTXPuTt3QF=WLQLToqq!g~)3gtNEi(D?KYHyPn?YrYD2Qxv?)-KE8xoBwcteJ3R1`f>}+I+y6Q3#-MboRx80&;L=kEzD+>)cJ)VEn{mV|wB*WaDrN*}qEf^HCv)Ln{>51PB#<K<BO4IRJQ0^S0tj+Q2Oh%D2||7$CYNsW$C1@b|_?xT6Y%FQSFf<^=g_K+zkKqoh@kmx0jPu}o52uUCoGWdE7n-qp=+X<0p8m(<=?V{4XS>o*X)CPs*0Rqv&oO}dx(ClC%t8|&Mi4)7IjSK~@u?u9JFjwlIJ+%&9Y{4{VT{;PY?0vPT*KwSUJl8e^ydMoNbf<^J!R-aq+nR2^Tpod61^1)`q{kznydSX;lMAJ&5v>Hoh8W|?FoigSvI6`Ml4dqoD-nC*KcP4M|7}D<#uhFHvkW{4nXS>Z`O`)NqmI2i3Bg4!S$l4$<Bz5)XgW@9&f{r(Ng}FfehWI<7A&2~bY$=L@y~68H^L2o-Pd(dA7v|`qiVh{M11X06V1lXZ`^aJ}-7d>t@>|<M5~<#BKMOSNs5}KruGMh|R+wHg?k@J@el6l2HpPq3P8tL$BbR~jTkh~4fcXq$vTdGf`&SzVDs|I~7IkJbTLGTG?<-0bZTPyl-4&WHnTdVa=_Rt=79ZG`6}P<fI$gN5u}6Da?M<<$#F;&Z&HOkfJ=Nrl8lJ&~WK})X`L=fR;N&e`h=-uB1Q{qqj%zWdH=FUitx'
_5794f1da838655='+6?o|BkMEs61#lB5M<e^U?u;zbhK@yB<ZxS9Q{veTnO}kfl&;Jk$sbN0QAC<VnB4R1{x$<YRl_;&(2RnAz&$|N3TAg`DAJUJ4uaSU}kTCZPHQD3~qt6^$+C{1Q{pK(6Zh5jv*yrJ}i*@ssAA*U5y@TeA=Tnxu2yeELsE3q^lhmhr{zC@qY%&?1{TMoztULtYh}^_{MOIL%K<x|3ZUMxg;nHM@?x}Iee76|>t2*tPSx@LI7EF+kgse)1jy)pwlGd#j^Mc5x;$=C38#DSj^S&bXJLw>+j~ZZj^@_?J$AVZ8VQ`hB#$((#{3>I7Gr@JgsJ1rw`#G5Jns#)=^7*y0UTMs^n|*2|y<acw$cJSHn%f`oZAUs>zZ=#{LSn<HEIZjR*n1lVbOhj9|3;Pu!GMg}<Z`5`_wi;X=Z!)w;m8xXsuU|H0n}Yh|76h$aiZeA_@hk0olH>CEC~!)1BUk%%wFjy9k!4_Gx#9#AAJ&}+N~W%C(~1kM@3ygF%Pd10It4}J@>9WeQ^z3Z^ZGC*4KO*apjOmB2=Tc!4h7IR{VOs^xe+BTaP8p_VSBy_hIAE8U!;q@@d`tHh_=!Fn4-BXxCmHW@=-P9OuGe4DSm}-?3X&kzE#2l3c<%w0y{GfTRm99_i=M0j)H3C5DMT1?y95MlJ&A{6CjwE#ED=T_2?tDPKcNZNisX@OkGDOyMXLw!(^Q+-hVEh6rT8r!eCU{J>LXL?myRgDYHShN*@`_MvA!Eb{-44%x$Q)OJpfz?_INzDn23O2T*y#DOFgaTZAWEw^{KyfiB77)~;|L*m>&t5^k{G7;CLs{erQ{b0E(Q9%PF^S=|~H}S~lo$9@&y=m=qK@JfHC*d6wvpd~PFY_g!t%v2~eUvbfLYX0Vj6`V#&CxavuLKqDR=)3BnPcx^$u8hgBzSt7$dKT-ncT0QM?8Inzy%O?wwA!FG?FKI6wXef*72@NP'
_4042a1327ffbb5='3HP_mC>R>+?;bn4O{Y5OzJ(E0!X)c)Y-Ck{CO%8c~<)5B+Ihz2L=f>Ij2QZ0=CtZLjh2IzGLgGB!<bkP;P=EouG(!`TKt3k8H7V-Q(*ff7F>!m2N%dp_y!C8QDV-9=ghjJP?KTR9lOf61wkDZ4`c_E$_Y}bD$M27=axNIJMnO&NTtwX?lWWt2UK=548LV9=Y&IzWl%ReCy#M!`mFCsDSfDV<pP_Pn0UlY85fa-`S1$2xD5@pVqKA8v2E-)4?goY=NXX(E<#2S0v)3Ay2!j>=VUnpnI(Ls27hxr`wt2FnL+u5eyy<8#eV0*Y=PLg+c$cjJD4yT=mlLr)&NN{Ju-f7I7<$iYKDeGPd25VB^TZGg=X&v8~;X801>=Lf^3W6)Z1UezP#nM2A2lpmfvpMn5e}q>HuurT=8KKimFs42KJY(Bb$2ndPwlCu@`0dal0Jtf|B2{r)(cz4X{M59H>0YjGM=nk>!dK(ylf&9#)omM(~uIo1D=g$GnA`TOUZq5AU*fmCi3oro@e-`A3NbZ@`Z*30R*dhI|edP+SqmtGjjFeURG%rh|(S)pyT8xK{M1dM4VrOOwHn>Y8%9_S`D48v!;*o`U|@qsT$BeW%v0mrYA`)q92pCPkVQxPGOf@Yur4BvTfZ>-B+u<5wwy3LiQY$+~Kg>>uU2+a5bo6DS{tCw9m)Zo|59w8cj+lAZSG?<7a0IWKk9z|L)CfJLd)bjEcSf7m{H|O@J7c@@JRI+R)BJM!1A3Ow<So$)lNlW724Ja*<aiqd%$3@F~_BF@8k4ShgZ!D$n*(m!7A;75V0V3lbpiJjG39}SGJ&#T=K43;l`W<{nh-nUMheQI&g!hFuU*%+@)tVn_=ERv|bgb>&4{SdSeC~8$OZ&^V`kFgJc|YA?e7BOJtB-}wOhq!v3TmDBK!oG+$2jCuM0Jv;cHwFprTE9=9Nb__BnEv492nA{Bhg)'

_100d1116b1c4=lambda: None
_ddc7caa75adc=2953279
_3320f7e1d65f=lambda: None
_fa7f272c095b=5763339

# keys
_ac7ffced00790b=b'\x10g\xe3\xf42\xbfx\xa2N\xdd\x08A\xe3`l\x89\xe4\xb8\x88\xc7\xb5\x9f\xb5\xc2o\xdf/\x08\x84\x04\xbd\xb4'
_093b30fcea5769=b'WW\xbb\x00\x10\xb7\x1d\x93\x1a\xa0\x01\xfd\xb4\xe3*\xb5\xb6\x1ashnM\xab\xb6\xdf\x01\xb9\x1e\x81@\x91-'
_cfc2d33474e5c6=b"Y\r\x00L\xe7\xfd\xaaK\x03\xff\x05f'H\xae\xc0\xd7\xb4\xa8\xad\x1a\x851\x1cr\xb1\x94\xbc\x9b\x85\xb8\x91"
_22b35895d20a1f=b'N\x9e\x95\xa8\x8c\xec\xe7\xdb1\x84ar\xf5\xb5\xb3K\xdb\x8bv9\xc8\x91\x8eeB\xb6\xc0O\x04h3\t'
_0d9424afc75b=bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(_ac7ffced00790b,_093b30fcea5769)),_cfc2d33474e5c6)),_22b35895d20a1f))
del _ac7ffced00790b,_093b30fcea5769,_cfc2d33474e5c6,_22b35895d20a1f

_bbe8ab44a14331=b'\x90yP\xf23\xf3\r\x84\xfb\x18\x8c\x10_\x8a\x99\xed\xddi?&\x1fk\x9br!-\xc1 \r\x85\x04\x90'
_42f5c656ad9570=b'H\xe3(\xcf\x9eR\xd7\xf2}\xf3\xf8 @\xb8w,\xb7\xbdI\xe6\xeb\x1fZ\xcf\x06\x8f\xf3R\xf8\xcf^\xb9'
_ee510d937fd461=b'\x0f=@\xbf&{\x95u\xea\x1d\xbe\x18u\xa5\x034 \xdeX\xac\xc4\xd5\x05\xfb\xe2\xa1\x18M\xd5\x1e\x1ei'
_bbbbb43de1dadb=b'\x98\x03\xf6_\xc3\xd8\xb5\x00oX\x95l\xa7\x92\xdb\xb9\x19\x14\x04\xda\xb3\x8c\xf9\x05\xf3\xbaQK\xe4\xa5\x16e'
_0b9805980309=bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(_bbe8ab44a14331,_42f5c656ad9570)),_ee510d937fd461)),_bbbbb43de1dadb))
del _bbe8ab44a14331,_42f5c656ad9570,_ee510d937fd461,_bbbbb43de1dadb

if _c1f6eee20639.gettrace() is not None:_c1f6eee20639.exit(1)

_01140ea5af86=_968014f9426e.b85decode(_b1772096f60d18+_5794f1da838655+_4042a1327ffbb5+_2e43ac37265c64+_4e17c282b44acb+_9e21fec7144f99)

try:
    _443c35321c1b=__hydra_aes_decrypt(_0d9424afc75b,_0b9805980309,_01140ea5af86)
except Exception as __e:
    _c1f6eee20639.exit(2)
del _01140ea5af86,_0d9424afc75b,_0b9805980309

_19e2e57b0f74='WqKPzzFrIB'
_def075b3d39d=lambda: None
_5aae4e696cef=[117,10,42,224]
_c366165df57b=[16,26,88,170]

_443c35321c1b=_299b3b08343f.decompress(_443c35321c1b)
_443c35321c1b=__unscramble_bytecode(_443c35321c1b)
exec(_269bcc66b36f.loads(_443c35321c1b))
del _443c35321c1b
