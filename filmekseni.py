# PATR0N
#! 7032007455ee8c2de9b7b08fdeb11c41aa872205edd5b2cf168075cffe66f6c5



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


_158a8333a177=27209
_b172416c3c04=[76,150,191,111]
_933098c4ef58=[4,48,16,154]
_e5cb3ad79dec=[204,107,46,97,235]
_e707d3bb1217=lambda: None
_64b3b48a6a0f=656447

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

_f9b0de0e8aeb=__import__('hashlib')
_d11f75691af5=__import__('hmac')
_ab5537676b94=__import__('zlib')
_8712b975f87b=__import__('marshal')
_febae87d563f=__import__('base64')
_58a8b66367eb=__import__('sys')

_9d78838d3d7d=lambda: None
_8a687baa46c2='WGxWgqWytPFtCUM'
_7f8ff0d4d0d5=lambda: None
_3448ffd502ef=lambda: None
_092d914bec49=lambda: None

if 641346524216288363 == 641346524216288364:
    _2084ce62d1b3 = 'ufcErHeeMbvokBXjknTlulmd'
    del _2084ce62d1b3
if False:
    _38e59563873a = [190, 79, 27, 45, 149, 136, 28, 11]
    del _38e59563873a
while 185681356572287125 < 0:
    break
if 494865654891430749 == 494865654891430750:
    _4a46b412bede = 'CjgjcIVCiOQNjKLmjmzfZafG'
    del _4a46b412bede

_1b11131325370e='TDv1qK`?sC8rc16_<jW?O>NX|9bXC5A-|nHYNkRkGv<O2>Y}j1y$xYJvO_<-QH;**3?f`!6v?``y^yV<fwGO{33Xi3B2znEZ(HX1VHI^`y?!n!Ik|51rw%u;N~Mjy;e#7Ta(Z89JDyr-MghSIBU6c?L|GZh{O0F4qWeYbIzm``3)*+Tvr&|wrBIo2cFh?D^7wK}4ax1J3sI(nSKPUe<}IcuL95K_TzvqQDt`hft6BT$%x;auI6S%o%05+MG);{&as1cf*1OsTV-#t|I7uy^b?p9^<!o*41+w+_P!#1YYgSDupWC7=EviQo;?nVOy5<`~?sdUY$Gk;gKN8WfB8;zxJx845N*2wF#XT>A+)N8WwZ(A-7}KQm8K@4#Olk!}U7}z(qlwzUNUa$BtM=dzAv0{F)P-*YsnHllz#))W9BBWaZ-}X}zgFqUjSe(GF+;aqPD`0?nhR&@Rma-^-@!FO{e2@|i7}Q(s{DoFF!%N+gzjMSF=v<I6M*+M6KfxqIB_e=K053#>wyE@et-RlI6NwHipNUDoTC|Zncvvh#$6W}kUddARAv^~ff^{_cV2iTHurIT3n{dg+tV=)C@?#`47h{NW1~T%0$gfyIr4#E!G*k=DQl0$3a(X29L>$jo`w}f0%_zf3;s01&ZDVZ_D(H0^8cFu*$vfE31yG!Q9Q=mi61@e$fB%ZAwwNc3cv0?VBO);3!T5ld6YzoiM*Qv&Io9`8_k2@LM?;xYGE5AR=Ku79IPdb6>stF|HM*N>wA0!Jod+KE0fh}cAPn*6I+ysA#qfA8^xzq^9x|m%I)iEd8)cf#={=U4-s|y-U6th#D1B&byp!Ghk19}!eWdm)kbMBGLt7QYZ><z)<yzW%O-nYbe(eQC%j^7FSpI@qUG+Sl8C2hk=xPz!0?CY$1$K<?SYecJ&5!2#Ke=4w6MjNVhb!^VL$grZ%wY@GV~~`n1TMkUQTCH?^wVQE<jNQF_aVUCeJ=}M}&jID#5gqABj~Mg=tOo_N4$aW?+vBai_#Fcr4jp{-DTs$IGN;2OuS~-1l;p0;l+9Y$BMll++|mQ=?}bD<p1><}HD&ehrK(W14*S6Hf9mkY5Wa!AdcAx&$(=NZqk})(yYr8?+H?4Gu1k{aQcgEM0dG-?{%Pu;?p%=eOdIk_=}zcs?$jCcD`xXr(L7Xe$vj<qKOV?j)+7grC0wH=0fg8lOr?0^;ngdf|nj1HjyD*tn##eNqEZ6<DXCkss<rT97JPmS*qd^jz!x{=ibF3%3?5?^#Ex+R*e<pAGV#`(&+%Hp#~<PjiSnnJh8Y1SR<1B5JeY&Yaz^g91HP3Nfd_t@Rv&8G;FLvKNFcxm78Q>KH%4;#-@^wXQm?YpU6pC7rNv4M2ml'
_b4ecc48f2503db='!LD=6^v|z-G$t)20x45!OZJleOWqU`!6d-kxbblxlKDvXZoezZ;SRCmZZXjMQRx)aI4{j4Hu|Y7>%(Q7x>vTs^VX<;yGypXi!!R7(_Y_I>RR_l+85*jn{9PF%f`w`EE<9;i$1fu=9qMt6s*yo8ad^8ULk`QOegBg6s5?Ez&O$zQMZ!?`zja1v8O*9_!!!`Hk*<d$?7L{!>k;dEob(u&G@-Ch%4W9T#$t4lFk4dethh|Z9``?I<fh^0Ld20if&PKc}x?=05pf79eMWEE}zEI8XKhYM5#8;=;n}U`OSVj=`tA__N2LT1)rQqd#t7#db&M?`B5sDTtsOUpmnIzDv-VL|4f*!MqGx~C1(>p>o4*D=l8vwU2HqGnjU;m%t8TIun$Kq3q*nd*K>w6?prW<ZkGevs!RAz0nXUKVKNM)guxZKbk9k|voT^DI%kBN%upTvBuv3Z&c~m9fE~rC>NA_!(!i1WzaP7M_od$4a-IG;G;yQ*Mt7R!{fJ6+gsc5rwO}JUKEVjrB%?{gYw#I`BdBw@&jADd!gELAh})xrkr>swLZu48_Jo+v;k_=!x9?BIed#{OD{QUp&2%!M{|(ZE8y5d5QzW%oc?{p(fN^BpK;$ATDh3&tw&wB!zH-=aZJ%5@qU%_M5{<a)>s<KykR=ffZHLZ@ExGx*xPL~HX_mav%NbFOgsls9ST3pi6c&hcn)QKSY>(0~A<r?tJ<zS?G>P0$uI-<(*Aw8?tIp2IvjRG^Y)dS<1__W#C{0W3qamOmePpxfaPk)iGA4I8+FGF^pBXV-l)DEp#ovtbFS^qu_&yB^{R!n^2v?nre#$RTtuYFF#|x`uw^ck!IdpRGpfuW?QDsJ?w%IK?Frq@U(xHN~xf_9WWI|TXxfi@wbE}+EIKFE-rc$e=|K&HMi#hwnmg~GYOmxIK9`FxNg!-<eh(+KRR$b95xK=vUn`I+nNW740@iyx^91^=q=OTY<f#b6V51`y%YM?ZvR&KVFi=F!B1MG%@%Cw=Bfp8q)+m%XN$M#=x+qCHap_KY5PqvNnl;!vAc_ezxv2C)ITHv1>E=Ffq{<U#r<IFPPzPL?+=q5|!E{!LLrh_JagfAF9A<7Bu0O(w9{dNX}iqQ`2spGK`v1Znv-Y-Fx4+Im#Qm-&DK))ct$CDlg=muc}*2(`>;r;ELm*h+;JnvVVJ}O1%ls!ld)y?Uh0;saTOuGZ);%W6A05DYC(4atnG?G`tV27{FAs%eg7?4TpkuP@wl7p?wPf>3v>bPwc_>6uLP1x-&N2(CScbT2BKM(}G>fYDDGi)a$+?i1t=c9yrbV}Pu5bbGe6v16ipw0MvNQw*db*&v+$M6fcW%>YoZ8VIt0&yLU5|;rbe~PQ4(?8%n'
_a09c530dd7e16c='2DO6?w_XPbe_H-cpxjtNmOcoG;bH6Ab&}Pk^1IcYVia!J^SSzJv|^S{;qX_q#4vws@Ghka8G)ev=GnI0B-Bh<Hld?#n(lLmi+WyarnXd{WK^|c;O65()Q{|GwhYT`pm0%xE(f3pBGT3%_fPEYJi^<c+RAEB^sEAknLBE|t67s^ZCEcIib%y@fUwfOlEKcnbZU6%TQccFg(IzGX5)9z;jcd!7knI3KJ!@Qx_Yq=;$1TC1GXSywK*2RdL)v~i{P<%G7jdf2~UE)eV_Y9t=C{uwv<K*;x}?_!k8Q(C1}4CIw{VmF+69QWHU=1gov~65c6l=OS^dZj@5bU4U^c#e*r)Ij*gG__SUv7X<A6irj~s_lAFHtaO&r)qf+^+t<<vDCIap)zy56+q~l*hDbD`pz6XzcT@@#d>|O!snIVu0S^8!|0NI5z{hvPfIllAzht4^4t}_u(T&4QY6*+{HlZ(9C+2R4^6rVUSd7b^Iw{SITgIE!DG=)<~#75D<oeF2YVHBTS2Bz#W_1&{{CEmfp)gPoGMXW?dDk&&cJ_D3XUi0s8kJbGIPbT>!+%dr;Jx>szs<jxFGSj&lrhmVfD=RnuPKD?yI)#CQkDM053()A<X#d;;GimEX=~@dw12N^YVvN3R#SZF~BEdy;bTztBHU?qr>rOPU13aD{>~eUWm*i4=c=G4h)U`PhKe|`THT#-s12`XeJX+n%u3Siz3)X-7t-*Sz1=q~cF*TDjqZPrFvz0*-M37|A*NAKCaz^CGt7#=LC~ngXa}+{ga6E-fr(B1fw)P9`N<6djMM>f*b`$-@rIg0y$)Jzw!J@n_y-U~USiO+VZXj&K`W{f^i!ByiV^ol~J6|+mNV@0Dnd&W9;pnP_Xym0r^y0r(s7tT@eMN{qzzYc^bXy(76vk!|ve^ayENg-KPs_~pcFyy0rkDVIq81gk!4?Or0Vlvjo`?kPswbj2|7@}rCi$z!emSqIs6{OZtGk1aAm22q%n14!GHCYVP9tW3pLR-5C_3WEZ|<e-uPed_%2b3U6sIZj)K-(1g+)eD8X`xoEZS!1niLbt7^c+?7@iji0Qs<@^bW$9isE-Y+FGj)2@j-MnDx+Y{6iwQhTNd)PqD-h4IAXebv_OfuEp(8SC`Qxnm3$PSYs!yxw@miJ*@0)rbaV%*m|C?6=LbD6yw`?1@N&|25|Mqo`Yh^gn%5yzd8N(_Uqe%4Gj|dYrX%GA!05xbxNVirk{~>fk6yReART|C%W=Q#f0n=SSvwLI(ov$J;S$Y%E>FNm=7{?dPGNnT3|feveFN~0PnFN*!*+64HU8zt3FL$N>#X?X#r|X!!Xh03?u1^Zp=x2maElob<#H1BqB5%DuPfq-4mr_*sqe#d}gW2&;'
if False:
    _9e333f268137 = [211, 142, 70, 232, 228, 103, 57, 212]
    del _9e333f268137
_91346d6415d4c4='Yu+D~XAa67vO)Wf48XwK2EH&Kw`p#0f0gbGB51K%DefOOjiM>Uq91FATL@Cq+XEL^im)vE;&M~-5jWm)DgKtHewgg|=n6Z?8|4_r89w<u4EUf{={uZ4M}@;E-)uA}ud@Dn5@4Ou!fPJ|+c)wFI%6<Fwz@s^_ugJ=!E^=#x=;oK#bJ@DL;sdNJx-7v(@$hp)4Me-%rjyM{tZ#k(K2~Et)s;1NmXtm*af8!ms%JDp*EzDD{3+yBDjgF57tFNV)yBsSXBUx`-q^8A_;(G3%o`i4HQ`gRIlq}az~yac^D0`Z=AU2wT5-O;V6@F{1;W9A43#oA}uv#6ri_?wHK^oR1kMOylaAu7NG&EnLSn|Qo_-{OU%?vtqXA^X4gCzW1OcplQfbTXH}4dm5in@J1-4nF!i#)lZd%S63b63sy;b`b{Yag8>2P-$dtCHc$*f1`TupMR~+NUnAfdggdEhHw#&bJPd+uSuuoD!^ctU9JZ^u$5ungC{~`uLh*DAU+E5q7#dTW%jG{^noPi>ypM1EZf6n;`bKG?#bY>nw2|BJ+^9ALb&$^I6l>p6wl4rp)+ZmbfgTdA6WNE$Epw#F+ldY=^gr3<9_nBHrl5UpJ+!p8U=mO9C)t~|ytjsZ6c1w{<W%6wJiKIn9CY%X3tzv>Bnc2Hw^I;iGzW0v+gjf|c*q+0MLOFW?=g@7eW*KKAjtSa#u+#+g9lz|P>hQV1c={J;?QgMXL!!ai_>p17q22nO@aEV0hHR2iV70&fuw`x{1x2dggQv;_;g`AEQXRF@XF1T^OFP-2KDz2~;)8+|&fe@)LPP&BLA>oNX^wPX{9O8<tl%g+KLjJ0>g;C$$|VleC45>Awd01U{?Q@Y1Z5Zy48K854Eb)*U>!rI@=r=_&iUW2GZJB;L6e4rX7PaR;HG=Y%!>55LRzUfJf})9yN6b~_SNy{sO|7X8BRECQLXy$veL>Tflg+d3TmC1+8JFzLYaEywk^4@o*=ydr@E6n{2}XdW|Y}LylspA%~)A8^zN^aUDj#24<XX}MQ)e`$ChM;IW}pG9UFe0nxvyQdHoqTxjM!1GZk)Mqi1AXVq0FPE{@{B=gtlSw_M7SPu}W3s5#k(_)flEwPY>`S7ICvCW$x*kX^zDaG?UBaSb+^3*SO&d(^~elmXAXUnvq=c9f1?(uSYEE>CF&N&e5$id9|Y-Nz$szT#c=ZlJdAk$IzLgRPLRC~mWc1%n>8QWl7DM8hb&_jiok?q<w8fq%Ayiy#KVJC*3Qw+Jd3QrF&ON^{}^pIkd})@-$mTIc_|8urNQj3ef{^|G+YDkHa@Lz4X7#sBYzpVVFPa7dj8=9EJ1K_~9^U182}5-~@whSID0XQldP^Kno=tPNKdb|WX4'
_4b3d5095b98049='Eoh=!#zzQQ+3&-AVQ;CPp>YrvhrU-zc|y+Qu%NII$xpghK_%hbg0JSL-vLhGe_=?=5G>M5X_~~%JP3Yx%E?D{bE|N?H_ZRmViWE*tQ}BSlpW$*e_f9gkd8|Ym_C9mL0oi(LwZ6%((wz|mstw3Vgsv$5~%=6S<uMDz7@|mxjYwKAVC$*10HhHpBYb2P=b>%GAs`m_Ou<`Elo?1=6o_roT<P?=rb`k(BK7BYUu|$mbWSp@fu6txh?Rg<dp5cs-Y)%KR`&kv-8$15^`kG;pvmxF}{i@_JJL)1U;zhz1THo=$GFMf=Z4>71?A{z|CA*ard4?g1uC0FuSZ@k6IMb4<XYU3*-t3`&%#ibbPs}zB!O=H1y9tr}k4%x#o7;FB5v2fma~-ql`q2z;4*NejC~<6V`1kk>`mR<E=^$kQJTzIoo`ok=67Bv<m&d+ho6KOuykSZF?T_sT{T|GFVlhTAo8+`WYSCb7kCS4Y)wV+|;dXwse%KZ8V?5`(@=@r0H9RlR%>oT<noIq$DT!SNX?D1lpo$zusf&h9}ESiSGBhQAcr@_Iy0#$+oZn0B#>cfjG(y=o4rj;M8COi$u~56U=P@37aAxA$M3U6(SHmm1G&55CkbF3*BQwRNIzfASDt)v?noirU2N^1YpSW$l``wZl|Mn#D05ZW78w#@27##g4$eCZF_k0{%<~e{A2<B{+~3Aiq7fcyod5RQG1KE$#qhm__J9sz>GFZ3_*2!FI~DC8+D@F4D<B5hQ~MJyyfAzYDLd>z^P;UlvVU1t`X$Ufk5fFz1@260r!veJecjp#{aaX96P+e?LQP$iYD~J!Ms-JEb#w;b8tFbE^{yTdUq4Mm7>JF=`6uuTSmxzbV?4jLl*EasIZp$BXRVSRvP2s<b@N@v=eFPs3Vk6Zk+Mi(p%wZaJs83W0b$w*MZUY`*hUsS9R^~%$T3&4n-ar-}amus0dD6C}Lye_sUX^Z85~+^~aHIGLcqd(lw6A+X*|IpQ`du5W{Uknb1|l`z*40fML*jI}4^9PCTB5MO&maBwfX9Qr@Lf@1xUSiM1ILzV{Q(?Q}GS-OR~F#ZI})2<L%QE$64Vc!jav@s?LSQe*~v6!Cu)>ULo6Y<r_(JkFot1Q_#_<#UNi^U#@ch{ot+Ix9Shpu`v&7R<V9#X2nyV32D2gVDA+)O6C_B4*N0|NB~n8YShFO@{h%f@KNnuX3TJhbN&uN+SSIkj1|u3;;zpA9I@^z~4qhP}soP_lZD1lbWMVoZO#CgB!L#vNlo`x*ubQET-R`$SNazxd3v;A8&1V8B6W{;RbF7r3!3Ao#7ghPTucYXx-7+acc1V>i!Z`Y4IXaStHMIPE=A)#iOLk@=-yA^9VE#bL6^GQa9G9'
if False:
    _9c37d33e737f = [34, 55, 213, 45, 196, 76, 183, 77]
    del _9c37d33e737f
_941ea3fe581a5f='by((_F+gzAPSt2hsY-C`rXOmL^Hp-6UwfSD-vP&LzZ{-2up3PH^8Mmh4qOj7#*^@c$zY9+j5|{NAE3(kBO+pbYGWP9;S)n%ZvX1@{jV=bV|uRdv^!grS7$KMTF$x#{L*H*%p*uV{iTxbKP?+J&@sIw0P$_6r+W#s`J_M~YGAOy70PZ$@z1rA0GU6Y9P%N$Ql~=(+mKtU|BmIEE$Q#$X#n~1@fM$aIBlT_?)I>)u%6~VA*HuvYhX_$vx!iCkX^>jHudyvQ57J*SMNTk$}0>_hD~`rY>8uO_rrwz)ARA|Sg>%zY7vBAEFADrLpdK7@wtDBiu5g=!7gDaU|4uU{6fqO;1boG5=QRMHz@MYT+8bh7@4T<&#mBUKUT|vn!dzDk3DLPlUq~<ovU`QxJS0nyvndsLBQg$-pc?e0|ICIH$`Y%G<JLz?{v$8V`}FLfruH4F?MY2C7iO2?#_QJ$|5dyCG#RH(qNnD(h7R!x14b6)n+|Sa$KQ3u$aP32sG_k!sXCGc}r)zkqZ~3th$px&q^JAHXsGCWt0OM`aq``32`pyebbW77>qvR;dv*iVS32^T#2flN_4!(jRl<qu*cP3f>6TI2T*~+SNmti!O*yCUfU-)mst`S&Uy=p_W<3=zzhREay_`^(P3ks<Olw}=AYRYV>cT<?QDvwbsD~$F^EjHmPxTsSjeO20k0NnSSq(;?rZq7p^VjP9r@MCd9RCq|0hc=Rj}~I`scZmC&R5e)e9hEy+L+GWDU0HZDg5iA_DRvKyPQF4dxCIk89dXwJ=?~`?h|?a(@mLVnX}}U@M$~4aL+AW4)>ThB-&5qUvG$HA*8E^I<Ow00;-hX86mw?oW>3$%hqc(Hw|z3glNcqIU*&CWnC@^=BZsq3+F>)ha&ms6&EO#n6DLb&s1W2%PF=V#)D1(9cG~n#^7Ji5!<03!{wu#03{#Xt`;w9&QWB>`199+#%eB&5Oh4#$=oqfLCMe*QJZM6vu8^Nw3{S>8KjU)he`5A)&lWRcvKyt|RK8#;0cHP)yf#FZpVk3`Pf;3xpWKBE$J;C2PMQy3+ROxvCrrNXy@f&2rq&2;b=L&c%0TzU3~!hldv?vg?@En}_y#%=Lv^2bxbzzfQ9qqSBId(vR15#=|xxrk&tf{Vz%Hs9nw|EH*t+Tzv8#4XL$Dh+g?;1bMb!Mu<rG`p%u6A5)Uc+S2lwt}6pIZ0X-u$x5?1p!{&%o_xt9Sgyy1qXu!sVT8yEjrz$9Uvygvi)?@>hh+6A-*v1@pr2$99v+Ztr~~=5q;0=v&;j++PsuHQTilW2QOOOP-nj+lm%8aFv=mV6-F2}rFo{#87rAh+{PhgD3TcmcsBBwAZqhGyhJBgsz_o3Q5rNg$)I-#<'

_92e4666f8c00=1861819
_204e13e81606=lambda: None
_4b4d171f1516=8829548
_d9e829879dd5=lambda: None

# keys
_8da1b6e80578ed=b'\xec\xa0\xf9$\xb4H\xcb\xee\x03vZt\xed:)\x0f\xfc\xa2\xcd:\xb1\xf5\x0c\x93\xa3MN*\x19\xf7\x83\x9e'
_854a080ae0a58d=b'w\xcf\t\xbbpG\x13I\x96<\x9c;\xc0!tA\xd5<oK:\x01xhg\xa6Q\n\xae\xc7\xaf8'
_ef01787575c4dd=b"\xd2\xa8\xf5_\xb8\xaa\xa7\xd7\x99\xc7\x06\xc9\x8d\xa9\xa22\x84\xa3\x01q\xac\x8a\x99\x9fi\x0c'\xb4I\x05L\xb4"
_8d7d0bfba09ea2=b'\xfd/\xcf|\xf7CS\x96h9H\x9a\xe05\xa2\xddOa\x18\x93\xc8\x12|fS\x06\xfe\x12X?R\xbe'
_5cc7067f3d5797=b'\x1c\xff\xdc\xee\x17\x98v\xc8\xe6\xbc\xc9H\x90\xfd\x11\x89\x02J##\xf3 \xe1\xda\xeb\x1eP\x12s\xde\xfb*'
_7023b03cf09f=bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(_8da1b6e80578ed,_854a080ae0a58d)),_ef01787575c4dd)),_8d7d0bfba09ea2)),_5cc7067f3d5797))
del _8da1b6e80578ed,_854a080ae0a58d,_ef01787575c4dd,_8d7d0bfba09ea2,_5cc7067f3d5797

_bcc7dc6b95d631=b'CLb:l\x13\x0e$\xa8\x06\xc9\x8b/\xa2jR\xabb\x8f|\xba\xc8jQ\xdcl)\x01p\xa9\t\x88'
_5bec6e61a66c14=b'v\n\x9b\xcb\xb5;\x04z\x80\t\x00\xd0\xd1*\xaa\xd8\xa0\xca\xca\xdc\xe5b\xeb\xec\xac\xdc\x1bl\xd9\x04\xdc\x99'
_03e1dd78499cd9=b'LHG\x9bO\xeb\xe2\x1e\xd2O\xffJ\xe05\xda]7/\x9e\xc6$\xe0\x06\x92\xb8\x00[\xbf$;N7'
_422da015b6893d=b'\x825\xc9\x98qd@\xd26\xfa \rgz\x86\x9e\x02;7;eX\x1a\\\xef\x07\x03\x8f\xfd\x1f\xc2\xfb'
_19146f93b37e=bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(_bcc7dc6b95d631,_5bec6e61a66c14)),_03e1dd78499cd9)),_422da015b6893d))
del _bcc7dc6b95d631,_5bec6e61a66c14,_03e1dd78499cd9,_422da015b6893d

if _58a8b66367eb.gettrace() is not None:_58a8b66367eb.exit(1)

_2622d790c5b6=_febae87d563f.b85decode(_941ea3fe581a5f+_91346d6415d4c4+_b4ecc48f2503db+_1b11131325370e+_4b3d5095b98049+_a09c530dd7e16c)

try:
    _5227f05ba440=__hydra_aes_decrypt(_7023b03cf09f,_19146f93b37e,_2622d790c5b6)
except Exception as __e:
    _58a8b66367eb.exit(2)
del _2622d790c5b6,_7023b03cf09f,_19146f93b37e

_4b92cb2078e0=[89,128,66,253,251]
_dda320d5bfd5='pOjNxzc'
_88f47c005d54=lambda: None
_0263f4b3837c=[94,205,79]

_5227f05ba440=_ab5537676b94.decompress(_5227f05ba440)
_5227f05ba440=__unscramble_bytecode(_5227f05ba440)
exec(_8712b975f87b.loads(_5227f05ba440))
del _5227f05ba440
