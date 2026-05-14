# PATR0N
#! 0bcbc06b45bf300ca89501c442a887cfd4002901520531eb1ad37e62933c4495



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


_c83002e570e2=[121,218,244,32]
_1c69f00ea69f=[203,74,35,80,177]
_0eb7768d120f=lambda: None
_ec3dd1ef3c38=lambda: None
_a9563f9b50de='FfzwgHjKOpHRXwT'
_9f115201a441=lambda: None

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

_7c6a1837890f=__import__('hashlib')
_68a9009aa19a=__import__('hmac')
_eaaa569c1971=__import__('zlib')
_5c6aee493337=__import__('marshal')
_2123de171e53=__import__('base64')
_756bb8ba1958=__import__('sys')

_34f30e8cda5c=lambda: None
_87ebeaf4963f=lambda: None
_6447e4c5e0b8=lambda: None
_7e229ac6ebdc='ShhtGIQMb'
_15b6db93b83e=[110,179,60,244,249]

if False:
    _3f8869962eea = [73, 114, 138, 239, 28, 59, 71, 202]
    del _3f8869962eea
while 138677349850298396 < 0:
    break

_a97ab6cfdeb813='Alh$I^u2N2&E0{PtwtQ?yzW7b6|1UQ)#>_<Z*BP^;H5n;v5*=uhu6H?;90_}j&hHYBVWd@*AyAMIpHr+0aTrZax&%Nbo5$zOrjbMzX7ms*90L+vJJ$s#ZpyteoYWm*Sbx76sH6z4cwkO?Ce+XJvn^*D-iFo`tO*pP$2t!P3t7OLWa(&lMi@+y=M_7>S=I_Q6AQ20Pw&Wt?4?m1@O@p$HF&}fBs#wyfB_eH9jK9u1W6VVv%4#msnWVdsxD00V>D}7rLPW9SW?$g@SVP6qUJ4-1B&v#r-=>D(xsHT?_KuU?U2ZqnL)Eji$_oTS8M&(uvi7paX|X2;`b_hL>b7U@-IN$vxwrBkR*JZ*+-wlBXVQ?4C910@j#AOe#8l35Jp{spl{<3L^H>D@A~L57=2T?|kH$_ACcWUiV&z3}O>S`CLVc8Z9Yv*cwP@5p2Q9t$p7s)?5CmhY<5!iDCWt2;uB8fk2&Vh<Q6B+G!TQDM@%p5_|dCOJrfE#P(qIw+HDX44ajT`O*t%VY{m#vzt|$$x%+kGuRYjMOOv7nk69@t6os8c5*LMMxgZQ+^|=;O@TIHfh`ZLuP~;0{2J5t5WahuG<ezw^MpOYSI7!hs96Xa6`9@51{8O;CW)Em-(q|?MqIKAb$ofWjNP@*SCL$<0>NO)r!Ks^8=joPUs%PdD2|u!_JJ7BE3-wc(cTxz(p1KD#97ZM^wR6}pKDFAP70VZ)t?3y_7~;_YII9QnRgw2@4}6%%L0lXwo5Nt%uZc@7}oHZwZiZ#s&OQ(g1cv&Ryenp&Ccy0tW1KS$|ao2VB@P&I(<tq!LK;DRt)|it%F`P{2Zpxv8zF)?435Ac@<<)*#`MmSdxe+l4usN+y}F?Q3C;oPLLdwoT(aY8Jd!RcnmWdtg6=s&4T1d=Bk!i?_&~ex|&dfD5agBM$;2xBQI}i=@vtTIvl5(1!l6!y+Qo>l>B_d$teBFC7yz37YP-*O>A+pd=cpGHTww_F@xQxuPUs#O?xBzK*La&dQXm-B;mJ<$P=J^n;FtlKqiiNuvKQY52bA%3lo1w<Kat?BhDfyEsx$Y1JjJKulj>_2yT9UC~$`Mg-HMhrK%m$-IKwBfYba}*OF6QDj-}C@?YaHqhd522q`k=W=B}Lm}~3$-!3UlM}A^H1ge#kSZB#w=|pFZ$uaUpeNolQ^d}_<Egc52Zu2XTCx$J~+0mC}vgqpw*aH^NATx}$Zz#~ge?9sN^n)ir4Kdds7jv>|&j~k3aD~}gF?Vi`ybjv(wK(|;EG|^tdDF4TA(CcUylDF;z9}HPnkez>)y-z%$*~2pP`gVQgd9z}BlmnR3WYfO4lpBRNBu&H%bPg2S%RV+g5KIsJ&)3!>C6@*a-s|7hM3cV^xgv0ZpBI_QS1W`UFsaz^94E~aifDLWP3QGYQ+wHTnNnNZAvCA0$bs>g{ZId(u;phGyiXl_j<AYbd3f{_((H8_Zc%F3ji_2s4GPw`SgeRk$f3aB#RMEI>=*%iEkCBu8}&T7IQA0wmzYEt(qoY!;~BH8O@W&eZT9DM`vWB0CCuY;DmC0`9tHp>bQbN<dR%dANmmjX>(~>DbYo26O6rv1qvsEM->FX5e$+eBuB;KI0=5?`=k;}y4&t({ftvm)bspJo_>W-)>^j2gT};rx{Crf>MY)*IH(DI^<lR1j~pD6E6~7Ddy2ZJhaz#F0lz)wS7cG&MBwAjE9L4)VX(6%r>f)Vx&zMF0sag8bk;dMn1}Y{qz8lm3R&db7#--eYOu9bHjNg$*@M6Ie)Y=+pU1fq4uGSQ&vOK>HKQp(?zaYK4;&|tQqm;KbezrF<C_(mZ=Bi-7)g;WogM6k8nv3~nf-Et$p;n;t#jr_N}gk?G50=7M3sM^L!D#CoAASOU_t_GA'
_83d0ae14fff86e='?sipTc*B~i)ff>w92x~SZ8+$2s-WTo~~5w|a^q<6V*;}9}-yfzQBs0zg_CPh`R4jgf|3Q|@Kdc*Oe?In9uf;j)QF=KA((kTB*FstIbw!jNXZ7l}i>aaRviL>inn)so#pFHlolqQVWzC`3)3$(R^#SF?5Z1{)TocLrTr=HM-Kor?4^&-%qlVO@!%aPAJw7M{pjKk^BC+oO!Blj*B>1Q{gzs~S&t=wx%(1%JrrB%TYS<~o{DDBHxC+NZTD_z(EG+C%Wv}BZ+3?Y=+ohw^~F7VOEVB#7R;mb4e?>29WLD#qLDE8Hg_OB^-K>aA<H=B^+*8ieS3s|R7SQ!&hST=G3ft?AIYwVn%891ENFAQXN<P0x_PaT>FJ!cWQn3tNuDX&&NgZiwNtW}Do4uBfwDQOh2)iS$#Wqth&B$>bMttv-7u+lGLlnR(ZvcSiS<Tv5)dgrJj*B;c{+KJz%f`(&AZ!Z7!<nlhpC@wkd>asF@8)4J<5Nx2@r6#``j_FFKiOJn_iKf1!jE`99`yn}Ci_IJ0!Dth|_3?Z$Q_hw+XggZ=wQScv{iNx@)au`=>{h~Hskbfk^ZPP)#e4d-xT)PkrZloPgVxnj3cSFJ;U|{Fu@Nq;A}^Qo{=!mL;P?5-iZw>vu>E?=bSRR)0bcHqxZn?9RlMTR8-Wiip|$!v4@0HE7lt}3Udp5j{p77QNiYKkw`JyKkuSDBp~J($89W%R%6ms_EobXuJA_TgDWT`~PJ%b-m)@`S@Iv}~giIZ}bNTP7Z#B&9aQRnWuH$#QfUcyx{7PS7uLaeugn7F_9;hC^&v9Y<S=dCuSZ|P4M|7O@8||3YuKf2fH@PNo3w5V5pg&LkR3QMk=qcw?g)I8zl!7O)yoaTzdX#<q0QmQ;aR_`mhtcFFZh0+xqLlwVk6U?o24e5X#+v%oV)LSr77c^~?K@xz1LKn<z!EOBcDQ;MbOJ=xfVS=#P*~%cO$YF`B4zz?<n3<!;mjdQna@8cbcCv$%qoG9k>mDr1Pib2E^L5cAcxbAoOlE$e;w3!Ck^GPc9U80_&K}M*vlST<>~4;QI$^5_uls`g*ITRAfPl(smLE9mf@>rJ}6CZ3Y}DW{9AA&fGMnmyeOUK7~;<c#^^YHLTfye2iPD;5xoqjLQ;%T(t;T-VKT)i9X)0jSL_&{Wv3)DSL6nOg6v}rVzJV+2`b%yRv*I2ap*Ws<yZ>%dL9jpm&5RtZFlomY2|%PK}f@R&Z0f${P=T_(^x&aE5cC?BLKWpN+e1}jHq%`I4(s9<~0}hOgJo()yE!QMo)3DK%(+Rm|#m7<<329e>HqLIWExm9M}Z&GWW*!jOWyJ7*JB=qa+fWbSXJEP0LOM$Im9AWBpot4bqlZydl#Kw=Q+Th$TI)vbwYv`f+p3X!pY<wK-|p`^)>#Ql1!*bKB)4S>@+tU#eo^#pZeJlDsmE<r$$BiE&TS>m|Yf2BL&>{Gj=`TTfdxIAh`)LS$ISV9re)PKsCVa;cbU!o;qKIdo9;S&<T7$&!vP@A?cDFNb>5AY_RLM4lUH;xbB#AI0!TjN_d=9xY@hnd>a+j0JGb;SzfYR4}2E`IU}!zu{yhYs?RDq1218SRP1hdmqG$%s0<|8V8sF^qV5zLJl;Ztq^5A`ml&RUpi4|8eeAM7Sb7UP^$cEhd=Gn14p?dl_SDZG}Tg@WSB@cZG<IfMT9$&{t&~xk41A`jbJyb>j1A5mN*$bI_ynwue;eC*X)L;o#G@;WV-&j)Rf-VJID$!F6Wqji!M#~{mX2jbc8s2t=*4R*Y4)4Wrv6NtAb?`fb%+WfS|;<l%S8`aYCt9p!#B6d}92cKtv+M+Vtvqr|DPUUdL!LqFlPIG5(C3OgbtHX`&%)nsFM7oy3Oenb+REMgOj=2US|'
_f740a74fe031a0='x&x7E;d!-qw)LGx6-0;)}ignT4r>=Qc|m(L<2VhVSddHz1`Ch$z!ow~7pDA5kduP&goX&NwrpT<{=ob}zHPyev*vJpN|?8r<$zlWi#(#ljwPW%xRz4Few#QBAC`8oF$~%K|p&^6W>uxd3`hcj@qdI`!yxPaOE`W6i1Z7^O+UC^ip24OPy}7bRUg!A8$#a<23$zJxrgAZzVs5eJcg>Y6Zvo2zA~r#Q^;6h$){QAUBw+5W|MdhbZe9D0xKOWw<8bU@Kqnm6e?^*=fB_0qX9EA70Cb-Q<t>vYh+zAk5@6a;)N9`<D(Z~3yvWyU#OJ8Pu7t}d!)WTgs2t~i5dtJb`%PPK_48)bOaTP(BG8IK+<krezXPG`e2uU{v*gpgwXiu6_M$T8h5d=ki3CiVyhVSP)CoRWum2Tb+uHanSc(;tHQWVvQ*)LOHcgeWD5Ap-1V8-7B1@6YgM<Ff$}kWi<!fivwYT|n6Fu7-}@MQjMC94p^lCJA}NlD97}J2~1^2nM&ja7o=@p}jy+&wJ-Ut2bdJKUS*7aRFgvp%>VCuS#(|w4siKk_S7!jxUR`l3R~>qV`#OL^r$v(kx~pE+-OFZGSiw9P5Spy!MbtL%U$I{&l)WP(Uf@s4}D+v5iy};S;f%Q4!o<ISSy1di)8(bo9%qXWSCtLueR8(U;2u5ESEyH6n#1R@|RvXzGq$%E;skzj}*XM~e)$2|=wzE;SgER69bz8o6AgR-&e^(WQSYvIIkLjoiEKpdd^aG!!qHz>Ic?b(WnB8i-2ar{;8o`iMK7&U{{;+_nblcOnepX$BDs?kV0$$9>XW^^Xth8wu;W<bc4$rO5WnLS%j+|9WKQmp%Xr;EIVg2xWFwM)U1Kb#QQ1QA$YkPZO`aG4210?wrvKkC|o`;sln#MQv?1yhEL(1GIoppTa_~y>csynfl=>H_+I#cizC=Pt4dW_5BHpJ0B_~ZF7CZ{{x~|U(~icoSOKBd*^s*WEj=h3;Ad!!j(4_I>n6r+8tp}^s0w$*i6w|<hS35qmn)?s*|uK@thiBO7L$&BX6e+1d|1(huwGhX*9!z<3av&I1nHnp&zS5Ecp^bHWd=%P(a(~G2Y2fe_)nohI=lWH<dWKEWe5_2qFvSYxzz&{R=sSjfL-4sLVo!k#X21d`Uj#1<#j0Pk>iN=C`d8RAZqsmz8q_!2Q$ytRF=WM4M`$LBz_>^scg#n|XdT(k(7fWTQoF*dj}3HFT(hy?IdoG9OZO;Zs<Ki&Xf^2w&(iAXP>J(<(_H_<IbN&cpu+e`;M1j-M}-gRA~Q^>RbQ@;UGQ9m`ZTV&3nsCC?i==*i8KI4ke|gm9Tw(|d95indzw+By-|iz)+RJ=T8&u9U$B{v6iJ6|K^y&Y4j&?$zNaG3z{n=5}3?xN{N`d_^+AEoL>^v5$8>43W!$PyM1%M3Z~QaG?w8IwT=uY<Er6HljL#Qa5KlDlpo;_EyiH_I0qv(!LrkOH6^jj`UKeV@F{WW&wR6+ywq+j-?hpCsit;Z?0>ZAHX3?(BS)-`YG-K3ye?EOii@%1f8$Uz>z1aP|7pG-&J=Bv?IamwU5)(>|bf3kADhGia1Rt41EI9UNWajeIO`iOU6ARG=cGV`UETWgcWGf&|nkVbpcb>I~{whCmR7sM3S+j^4lazeuddxr^Ggk3pz&=V<^?l_HwioWFWK+T)D8;W1E@@9ZhD;&XBN;n1TG0P3Ct_`95JDQu-V3edy@A_`rlfqZ|HXjXn(Zz<Pmq&0+iAeQ>5W(so9I=yl+ROKy{qjBbP%z)t~Ud7!dLljkJ&-3r_an~)^^;nj_{qoJK7_;%KZM66roGOmsdzQce7@fg5j$Xt)4w&Vh6DzRACLFgsGk`XOeCo#UY<6#|zG!>m{fnaWCUrr'
while 802012218243920009 < 0:
    break
_4cb9d06ed79fb0='dBHn2cy;ulD;h46O{@yqk!8P@7xM+m=u%>`YeAsWNJ<jO>ca6$_=*q3sR#404Y2uFT`&M8+zx-xW=}egsXF~7|QOoHg3UdMLfEdj<pn9C;WqXFQ;h^183(Jl9lMCzM7l1ZvJZjLg$<fUd@PzV+Ilq)HRE}j6Wy(oDy(b4Oo~ryELSE03ziDzl2wBMq530=4~Y)tz@JN`j)4-jEX}rR@~kZJ<0n(wUJ_Tr*fUx#<-tvKQi73fH#T84!6Tf75yMcm1^>0wjEHoum+MWDBW@h;5nxvw9oy`OXqT)V+V~MDq%?8e8$zy@O2<$*_$bb_9SPAWlFJ|j^%*gYJg`j`ZMk*MkzIH`2m74gSISb)541aG2WI7a5=ojjcvM{%jgMY)8+!$y}z2<F>pG({MpJA5e74onuHCql!L!<_+LZ^8^gLIkiEfFX%J<6|3TM4hjKAKO|)ZvnL)r%=RUc4dat$$B8K`ZXqdUaWXDf9Y~Yf{GCj)jFE}eDvACw<7}XB1H=y)ORbKMYSri7aT5H>8WfgL|>h#=TFk&i%lCaJZhKne53i<Yfz01JrWGZ`lrId;|hSKjEVY-GL^d~-1hK)&#&2xm+60pD)pppqJZs7Te0k$GNsQP^ntv7|$t{4L_H%3z+{eQVsQ;Fn`0{EQAs^>5F@?fGpDfdM08mg?O603LRDQ&J}DyiG5bWhwT&o`vZCb%=hTsuYGP)CF*B*Y|LPK*gR`!DBSrGp@Xx`8$IBF0vy^;{gL^~hjPX|tB4X-yZ%qGq!Om*ihykq@luRW1D{B}p4bH0L6G1a@_oYD&&2Q@7ry)^$f{%KjIbGZ;Zi%72z&dN5Z03&Xr`@TNwBg|&LwH3hkBklBK?3W3;ZJMF;<i(HhcV2irR9q(00KoIV2Q)*9D)Q-mUHp3Nz%aaIt-1Ms9QPfV%znt4`Yxq{={-;4<c9nwR#8UUpGPIEK;N=-zCU66gFCUM=oE}$RoImmQC?shlaKrFho6YI6&WO3a7nPCHlDuE&{akPyaM*!v!)w&L$A5Q};;(`LdBilQNS^1nRQALmiRDTKj!(U6if7jl78hue{x1_Si*(0~hc$yN4qnW+DZ|!$=sP6~5iMM-l2&Yzq0HCAVhh?`#!-$db+Q?J{%*)@W|ufV{{BE(_)?XhgWro=!9ksWX2Ohu7w)Z7_$2ess#a-McTCGq#8-Ux(h?Zcom0m%rv&KnO-{d-%hm*j@zTc%hj;9Igqnf2urP(|ODt``O?GKOrJJ>)P53;(I2*Ne&3<0pcBf=%N#uIYekc!meu%<F?=^r;;Mn3dS6L3_Jy}|QE5}@`c7%)|6hp3(Rm+QWP)F1RO@Uk;|Id1zc%n$xbYiF2h3*|LfOOZA;n0ry$GfNrkPv6`-`W@G*lN=*1R1Kq^p-F<D(<I894}N_iB~1DL9|z{rg%7K>5O&*O?^SRqM`{)SW6xxj%z@yIFxDx!vD}(S&Kr<Ns+&JGzW#`;SIpOz=Efj6_C$+n=o2XG{M7|MH|=UgRkLFa^=oNWQ^9pybJ<*o>(DI`#-^DTzHQCR5=nPpj@VGIh+h+JMSoMkUTfc$Y*P*%4Niyfk)}iNXlQ^$1AxomFaeu^Hk4Yfhx&Wh{+(mUu~E&M%YE*^qKAOH0wvxf@=M(0(o_V9g@P@8CMTAv5y*DoYFXyuMuO6eiR7YiASR;v@=c8;%2_ykT7x!<E%3lf_7oH(lE+EX4k^UZ?k9co~VKt`*g5@Z`0szJxXbM-9ZFw2~o7m_~sZ~<y>^|w$Ur{Qb7H&NM`Pa#ZKPEG=)6khhk)_681g27K!Z4GS`-@Lhdo{g#<~D8NeA5$#-*pkx1L~%TdCcbRMW(b)||+Z;QL0?u=psLV@jffR<#Hp@7!$N!n|5!}k&W-ZM4fp07e2'
_d9387f7e96d176='Tke^62$R~BCa-N=^JLz=?zP=Ghu*mIqSH=Aiqfe8kA&NvfY~&&#z9o`o+x#z0f*IS=U;IZIeBm<eLmKUj&XBPoYf~etk^3%DY(N1NJef7b+i#IfIgjJ|1Hf3bLt_dY<?%%;Ya0GFPF#pOm*v!vnOecOUVQQs7cwvJtb^E`>qifC;9RC#s;_Gsm;Bwa_i6-y6N@H_Ij$)Oso!N!QnF&rdup)pS@`9A%Xd5@)8~&kVEqZ-c+VF~^;>Jd0W<gT25CbHh<3R&vZWDt&;Gp_c|Vr>|Y@eRn#e3a}|zeheh^(q+L+@LVW)i#!ncgyQC^JxPG|H+xi5=1uPqP1o+1fm}v=?s9y3#llZ~NQL;jst^o3K~!({3DYFhZ3-9w#^5x7xUtPbp#JbrhD?^I{zO6sZF@{lnax};h$OO{t#nfNt-Eay0j`bMrO4}k)1)3PID>mf!5`Yy!M<oOPZF6$16bwr>eK6w5xpB8#4i#1)(HrFo-w&vX)J7$uXnz<ej}u{+OsH^J|(Hx%!X0IuVmdHQyQVxkc&ftnvEJ|hTa#9`@Ti1ySz5ZDXoyBkwWgc+ZBdZXZhGY==W6jElYjr(N(%8BMYZMdgR;#aS};l$XN=(6kbhzmvdaJf0-uTUMTOWoi3yVixFYq^xBnXVwF@NSKnEy*Y8QFkJFONJ+B|72BK6#z+jP_$_V9q9PJoNGO+6db?Pii$v=|XS(rh*&w3SedUqXqps-93s@wF(h{*@s0{OGRMGUu83SAE;Zg5qxWl5HSd^w)9eju;82{`3Pj=q4pLAtfy!Wq%{s~|KAqQ$0*GrHW+l>ECuzZ)d;)TJ%xm1SZhqEig{oHc;WrB72Qk~yo#fbkf(^TWRrAGJ81rT+y(-<Z0ABKS{FNPUBTH2h#e?dn-E(%sIdP4Cqf5v5UiJ?-mg6wX|rFM59>6&JukEF_VmOTR4D>^UhDHd`ujNv>bjGs|mH&-9w8k^fneR)1Jhgw`d0-IY*m?hwR+h;a(?OH62e?Jmo;d6+k2J?i|~^lnaaGb|PB?-GE;vwG_U2Uv+?bP)}<nK2|{NsFe3%^U|YzoiOV+EUz5m!*M~oj)b^Q`g_|(%YCaIAbNoT1M0%Y6ZvWPE73qw4OB*qS&R<=@+y;THrA2Z74NmVFRrLH6x$bL*6UIU#De4<V81x+eU!n0ORauoqm9d3mCfvMYOf-Zuo8*www=nW0|g;QDjWoxx9iXl)HKcagWy;NO&@4NOm<!zLi`9*s+hp7<bHJn~68bpD|!FoBsn&s<W<u?4rwB>lr_#UMb0SO$NnE2at2B99)<EfRuYHHBglJ`D=vMWLS604cO;UJ&vm7uFiK~#nQak$Kw*Yc###)7w!^IfWSVC*P$*KFd9st=lqB4rQd0T$L2cFI?j7@3koJS&sgY(dTVvt<-=NPDat~5Nz@WzmPJ{{b4H~$%Ucl^qw+-6SvX~gw=?H}8&UKe+G`d!UBlzJe*;}FtXbNkyrukEWmrSMA(Ba#6dzG}OlUnZIairo!!}9d4b!njq-x`qiXVMBq_?P$@UTI5gK_XVvV$w8R@*>l1N~%)kH&1r572JvT{|`c>K<_jGoI~ZS<PKS<9n*I!Aocmp@~h_Vvyp@>`GIILA^T%!=K+a0CE=2S8X2f*YG@KE3Aq=^xR|}QX^;NFKpU8WyMC?&89UKb+nm)?hN550q+I^JK5d;AV?kN^aY<sZa&@~oqy9+pm+waSd)NID1Xt`5-VrZlu2=DPQu-i8EnrKw!g5JM+`$^qYgAZdt|P#0;XqO9z{ufMRlJuZ5&}88{ye<DS<gZXg@h*&IjsfQM0Mevx}(kM&x|M@}62W8BRRT7Rga+MD{63*E?{?<aw^?Ca%I>kNjL%`t^-d)w#&+BEDD-=umV0>&'
_e0671d48bf18c9='6O%9y6nHg7h@<knQ6d?QE;!Q+<ffRlmTJg<ITR&EYG5J;${4_)b9nIQG?pEI`xY3_1L3AkE6irP9Vo&=LM;$<Cxw@A{U?!Y=GP7-a0Pz1to8{njVf(B8{%eS$S>PG>@>(X^~E<3w0Nu#eRZ|t^|76#dal7p=(;;qR7tLN+=(^>T=kqndF);*4?BR5aAeJwI98T?wqEuHmIx08AL(sbhZS*(@C)QXtW~pS`g%DMD@^#HCt-=a>whwP<)*O%AoTE-q3AQVu7)RjwNjD1AhKC+`uDo3vXWR5b1QZVaGM=N)c>m-vNA!NapH=mEDp^KGmNYA_OvS#+RJ(I$zNp0TlTCZBX6;@dOwurBN>F>;ZHVMOI-P4)(N)FU&T}c|Fr_T#7?9>kv&3RhutR?T_Y+A`EIik;;T6f$In>mvu~AJ`xL>)_*cGHaLkOfKv2|5Yx7j}*lEXdf!X>#v79?$YzJGeT5w<k;G1JWQ*FE}g9<x&K63WE>*giRnD!pMWL@9_^^Tgmj0u%LUwLe{IKRLsrP_HG>%N?6W2>u62#F`VLn7vGkprGYnO<Ij;?2*vAXc~WrICSfg9qfJ6^^gvY5+N~v6_SG&jkK@3+i>}7}QGkPIu&M7*7;~(izW@<{wiZN<NXUg6ljTX?VW=DL8omNLyUZkeraa7aZ8D$`4guqLG4r1K?CU-`EjDuMzO@aC6z`v7qwqWs1M!UBG#z<rlP!VM#op&)%3`k=X^)OHhuWNU{4Az|lQ@*?_0*1O(G3N1IT)EVF*Ag%B2AOrqCMh|M`fI-;7&GWpIH%cozl%>yZX+NDcE2PbmmsY|Y$MayU;5N}?`$=izzM^|sZVztkn16uk)l<G5=*wLgOdK`U4@l0z8WC&wR8ayX6N3g8rIT$D{m>*>OVlRgbad(b$^YIdM?Vlz=mWZK4%^$+T;;^>&=TwA228q^iz!^$M!%4F~snl90lMC{0F`M`yPNt|`W7rEIJc5*O8nmO|Ls>RR3qIAyhsNM-CVF=c{A6+SMq!CTmZpGgjA_e2I7ywHM;^dTnyvIBJJhZ^?L7VoB+ybP2_&M$H>QlK-s!f7td^tS{nE=~wiAVdH1MY?&`B9Hwb5cS&;)aTgQ2*bRMlaxV&DsIFL-6eGpK+&z((JfBdXcc5>pFN!nKoMAnl(Pu!bD*uOXw`$m$S<BRG7!mgvpMHVE(xl40I2wUy>xY>NZIdNBYIj&BL-X;7A0CrB<<vgGc3`2R?ah2(RiM(~0J^+yHmK;aBPsZ3r9%x3*(O)}Pqepb%P@*9X`|4v>nv%B97(^B2bF`FjLmqUdyUmiEUs$#pQ@(YzMq}bjz2iLXhA@}uJZ*Gg97;(0jGtnjq?G=PhdKq&A8>2W@EdWDe1jaTA{k`L^bo!d>?Vbk?or0NM0YlRDIC`GfOO@Bn#&;v(<txik2MA}5L5_XY18zD-_FkZU^<|(3wI8$VD38UQ7F!prZaL<ld#Fjy^1=R(D(KFy$EZIl)ag<?QWUcz1MGzdQAz<z6lZrhzW&AA!=l~o_&xQ-_o7mb-#2jOme*r+6vCU5d9;6mA!Q^4{U4Ny^88&b;7?_Ry@C>7Bo%vXNK87S!Z8imbisS0@799D{H;$H(uM<tT=p3Cd*`pkJ*x=$8QTkC1tgB%LA7ZD^JC_~x;UB{S9srGpp0l%t&YU^2~hyH(u2Wb>0ZQRLd4JG(_S|W`#+_al|SFp@{_-aZ2`4Jl_SJo#jFTgMH0jvNf}F##nF5<r(b2<;xET0#-<Nu6jp*gUy#S=(r#acZfbEo5l$jl^tpn<ZI(ugmse*$S)S%XLiWoih}zh7TtQKvieU_{_o$SsSMU~#Y~jb`)nsw}9Oum@glmJ<6w_fo+Z=DxQhxW=LJlzd$~8oo>U0`7n'
if 363771672381356795 == 363771672381356796:
    _3ab3c1d8f2d8 = 'epqaxcVMRGZhjMozoLXJZIPQ'
    del _3ab3c1d8f2d8
_54f33ab8018ff3='_Zi9v1?(7f%tFze*teUa|t@#En?g~cN!^|Rp;t|LYF{JyAS|-OCn~1(iSN;)1Eh~$UC}h80YxD<{*W-Ds1Hm)&6sWRC$F%nbArZ$|82RF06JgDe%>pmo=|lhbLljcw#e!@G4~a<x$&0s<+LJ-H<cv5_N_U$eD)8?1Ec3p|5xg?AS>7uLcIK>B)C*>2FtWW|{Pf!vyoI_0fLlUvZ5kbStK0kL_1H7A=59Yzi5FcOVnyA_ZF+A#HgJ6DGmtTp&qDYU-FgM1&=YP7>;~z8u{@{H-sUA3jF;St|F~>@e73?pQ~OEsZ<V0Tw?%=+5-mJy35Fm%R%IVGLY7C|36B!u8_AgeEo6(Ps0d^m)Wd@KT&jf#%N>JHiEGh1@M@bN6rJ{2+pE$VK%hu}lU<y8A_9)-N>&0(_8o@?e|*9)+|j&{z}uOw!ThAn;H%Xa@st<T-O9mXnEEh2a@*1Dvq-JL_+lN^#LbF8^dZa^fS^sCBUio{|JsZ5518WW*q*?G^g7i-CH%ijp!$=8M|W2FEu|AtEW*~hxD4ka6xqL~8+6w>fw5TKwX6?E$6Kd-R*x{Ua5UwS8y6SXJjy)U<TMNO@ty$A>`TX`cdRtfM7Rb;$v$q<JY|KW8-f#HcJZRWe{rj(YZ}?;+&dP6xOF-UhK$&?%0~J;S#<KE7d96vMCqca%+ic^LCUL?@c2w->GmXMlaCtgr!^%brD$1mPZkdA!`Rv^=x9SV1^!R(If5Kh^4~Igjlcwm@rJ$#z8PBy{>B_MTy`?9;gPoLy@g1n<Zcz2;l5wtoTI7vI_iD`J4>txD90`&>s!vPWr-d8<MF%WlI$8Nh>iVZNS-IZOB&!-Jav$qj@u0J727;?lToE;UiEl$m6t~5Jr&;b6iVuDf-8RVYI@|{4saR<d3iy%)g;mP?-2l(zEdwoe&$xNkpjsngI0fC<*U;Gg$&jGB-!O<(eTuzIn~wVPSQ+CdSbwep^bXJMR$y0ANttI5p}_1V5(Mb_rb$snluU5cfE{!pa`T+T2oL1r&g=+t;Jnyw_UnVK9gF0Q;&i&bcz>p*J6C?Tsc0@yVW$|USYt9<6b$N2IWfBJTPBC?RTFGPv<pj;~T^$rR;AXb@z2|pBNO#N_&8y8b^%!l;faYJ?oTNdLcvuHK6`;dws{sG#XdaVvGOgl_Z%KHaxC`gzQb-E3_=!{zBHJeUg1^I}f3S{Q)?pm;>8&oKv^s)=iS<u<~|REM3+}SOZfFU@&wL;St<PfEIYu1J_U}I1oA|g@6{SJ_$3F$f3Z)cTu*S9FqIho#^&Zopecmx(XB5<|>@O@?uZW1m-c+M6~8{tY)o7o&w0-18-M{m=r0PvvH*IW1vx@?Ot8>hI6|jhh_&8|D05B(qC@X<@C=i8f4j|&imG)pn}h*DDd*_pO-3Dd4nZWKF01kO3!;J+1lkT^D876Ovcb1w^(Yxuv|(cP*92i{X5Y#Yp|?##!2Mu^=1t}^1ur@>SwyLAVhrRSy#ZqQv;9xZQL!x)2pQI2ns99v-2hWka*AzG}nfa{eWq*xEIjGtVNFv0lO~9Mj8;INO{+>wo0bCycm{aFvjo2bu`j$5K49!p?+BiH}0^KBn2%SP%?gxVb-tT*2H!48#$jsR$Q%+k6r(y%pE{M34ZjQ$L_K8@gv@zmM}QCkaXnW<wL%9dCe|1Hr~T3zCXf>5^+3#;-#Ffam>$m6!cpu1SIrm6yeZU+AcmOkKZuxDRb*mf!^Kqzc{&GLlfZ&(CccroA>J!^Ru+d1F<kMwBY%fX)3D*KOHB#5$)-GL<%Pukb6Nc$<<$b0{leYu2V&29nXm&rGs<=#UtsHKCcGmms%pau-)6X>QqTM#JZV>W^3q$z4*>~B{_0j!aGnpr_JOboTdSI0<rZ${WflM'

_8add264d8e9a=lambda: None
_42e4d56a2c90='kHLaEKXP'
_6c24731c96cd=[147,198,65,55]
_8ca60902e697='WhMNjOLH'

# keys
_9f7ef07dd119f6=b"\x14e\x8c\x90\x10\x99i\xf7\xa4$\x0c9'\xbd6\xd9\xe9/\x12\xa3Gx\xc0\xc9\xa9\x87}\xc7<\x7f\x89\xbd"
_4c99b2662bdf0e=b'\xf1\xd7\xf5\xfbX)\x94r\xf6\x0b}$\xd6\r\xcb\xa1I\xe3\xc8\x8c\xefI\xa8\x1fQ\xf5UF)\x1b\xf2\xc1'
_e1d99738dc342e=b'\x03\x17\x81\xc6\xea[]\xe1\xf8L\x97\xb3`$r\xe8?NQ\x8aCK\xc4~\xd8\xe2\xde\xc8)\x9d\xf8\xc3'
_d68acce554902e=b'\xd5\x1a\x16r\xdc\xa8\\\xbe\x10<y\x81\xcdX\xaf\xb7\xc6\xdbF,\xc0G\xee\xe3\xed\x8a\x89\x13\xe7\xbc\xa3*'
_c14f5f163fc432=b'H\xf6*^2\xb3\xcf\xb5`r\xfd\xb7\xad\xaa\xa9A\xe9\x88\xd1+\xc6\xc9O\x15\x96I\x1f\xd7\xdbx#\x19'
_96325ea0a78e=bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(_9f7ef07dd119f6,_4c99b2662bdf0e)),_e1d99738dc342e)),_d68acce554902e)),_c14f5f163fc432))
del _9f7ef07dd119f6,_4c99b2662bdf0e,_e1d99738dc342e,_d68acce554902e,_c14f5f163fc432

_0e370f65b5cc0c=b'\xab\x83\xec\xb7\xe1\x0c\x19`Q/\x8f\xbc\xf5\xf7\xa4\xa6\x90\x9c\x0bY\xfc\x1b\xb8\xf1\xa8tG\x19\x16\xb0\x13\xa3'
_828fae028b91f3=b'\xd4(\xc6\xf2\x9f\x16\x11F\x82\xc9\xa4Y\x1c\xe2\rr\x06\xbaoj}[\x1b\x81\xa2\xe7]Fr\xc7\x90\xdb'
_9b642bdfe5645d=b'\x05\xd6\x1d\x02\xf42\xc1d\xdc\x9b\x17\xd7\x0f\xcb\xdd\n>\x82\\\xb2\xc8\x8c\xe1\xdcT8\xfe\xc3,L}#'
_ca006a9022795f=b'C\x00\x97 \xcfB\xe7\xad\xb9\xb8\xee\xae\xfe\xba\xb5N\n\x08a\x9f\x1fI%\\\xfb__#\xa2z;\n'
_71eaa7ec266d=bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(_0e370f65b5cc0c,_828fae028b91f3)),_9b642bdfe5645d)),_ca006a9022795f))
del _0e370f65b5cc0c,_828fae028b91f3,_9b642bdfe5645d,_ca006a9022795f

if _756bb8ba1958.gettrace() is not None:_756bb8ba1958.exit(1)

_6fa6c57f0b48=_2123de171e53.b85decode(_e0671d48bf18c9+_d9387f7e96d176+_f740a74fe031a0+_83d0ae14fff86e+_54f33ab8018ff3+_a97ab6cfdeb813+_4cb9d06ed79fb0)

try:
    _edeadf797825=__hydra_aes_decrypt(_96325ea0a78e,_71eaa7ec266d,_6fa6c57f0b48)
except Exception as __e:
    _756bb8ba1958.exit(2)
del _6fa6c57f0b48,_96325ea0a78e,_71eaa7ec266d

_175f4d856f7a=9701899
_f4f33696f649='vXHiRoRgF'
_18126d939318=6650033
_e97670fc02ca='dyCUvk'

_edeadf797825=_eaaa569c1971.decompress(_edeadf797825)
_edeadf797825=__unscramble_bytecode(_edeadf797825)
exec(_5c6aee493337.loads(_edeadf797825))
del _edeadf797825
