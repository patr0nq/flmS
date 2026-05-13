# HYDRA
#! a2c0a94ba71226173a6955960a86f360275c70161954470cf93fac7c4cfa7067


# ----- Platform Bağımsız AES‑256‑CTR + HMAC‑SHA256 Çözücü -----
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
    # Çift-katman: önce bit döndürmeyi geri al, sonra XOR
    result=bytearray()
    for byte in b:
        byte=((byte>>(3))|(byte<<(8-3)))&0xFF
        byte^=165
        result.append(byte)
    return bytes(result)


_af1c8f94950e='cAtLHGt'
_823b2df1cc1a='YYlkEr'
_74a766376632='hTaBskn'
_4e2f8a413f02=1540832
_0e74f5a86429=[128,13,56]
_2c145de13f6e='ZKdAgaEpGbU'

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

_92a0028ff146=__import__('hashlib')
_911943e70130=__import__('hmac')
_2f0b0ad78a5c=__import__('zlib')
_6bb085b9e642=__import__('marshal')
_5867aed926aa=__import__('base64')
_af53c5383230=__import__('sys')

_2f7c428692d7=[57,228,34,100,201]
_f4bbd8fc5990='iyjIhVeqqB'
_ff2490587184=lambda: None
_bc4f3aa9fa0e='OEwOsSLmDtcuBA'
_0c629d590e3c=lambda: None

while 656718588602241805 < 0:
    break
while 374419270255999568 < 0:
    break

_0ffb15f78db8fb='DAs~=;PCbTviQnqB7JRvOXo=sv!A<`X>h@f?ttKDPyPU4X?Y3Q8j$OR?~NrU%SWwwJd4&Q8QdcmE_vV>qT;fwR!-hFV##S6%eVrGiJSJ$H}8C`lG!zYmHXvUz|+lT%cW8PUiB#wLE8|r3Of#^sRR(yQZrj>zMg_+2B8zMpz^vuD{|A8{KHz$f^iS!>ZV(j|0vH!lK{;iD%6+C;;*0C9AqCu~Wwk>gk|gB<8HZHe8g`2vk^t`K+J`qAuMY@}AcUOOWKq3C}__l2K_>hAVCG$Jo-rpFhQS(XHB%gFjR)%k3>N;?ak7+m&5LmZbDK|G?PMa5%(ts<DpAfNQi-@lh5y;DJI0(TpL$e3-Qn{%R-0KerfFz6%2zj#rEJESCF1QZB4h4}F`6q_Wip2oS;IH<v{8?;L*(3CHBdIULyBO&#X6Hxziy5TrZ2S83S1u>v0B2*C!o>T0;3z}N7;Qq~g~IKQRn)QuB%_cu<Hw~}WJtC%!eF9nAYs!SC~F*FoTtiB;cDA8zCWi`{0aM4}^8>Dm)5&uduPg0{K#_b{joejyLsQTX2IeLE|Atg>B3wGQ%oqh=)B!A^bF#1d;-Imj8$eyKkzXsQ@M8+v@@_Hv*brZng3f8Tb<#2MMV!?SV2Xn5(Ko6p|zf1mv4HbqM^h4+><D_d)uWn5nv)3S?{gzMLbpl-1+y;3`E*^z;m?6fCV(_Nzi7s~n>EhFMT2iT^w=`5;=Z$7aA@Rq;Y$CQ2t+2lUA<@Da!H&*AnYh_2X0^|g7g<(nZFHSpZ~3qqGiKrM<Mf8V>A<1S2sEqDhc~rC#~WX?sZ&M!oRu5yaLUrQ-KGgNmla{&;Am-3{Nn3%%#&zz_xU?c#?jmqM-i2toOAwaQKaM22&ojZeLqr;@lmdQok(#X62`;abexIf{t6m^+;wx=kJ)-1r$=>ATe8Bc4cX^fn*E+)dFW&A6MiO%(Bib;av&wx3xo@g#0J{E@w$yHc7Xyz9##m|3ZkuklTDH8=#$aY8W!xZ+Jri622w?89^qLd5_81ttB=T(m`P7&HvE<%<OV<Za`-!o0Fs8ezw{y}O@n)R5_zF4ET2k2gY^N|SjP!ti9YuDbzp^DzIaYb30D?Bl4I)=XYP<rPGrIARyX~^z^oNo(OD%!G|1<VWc05qWPB%2OBFn#*=M}l%s|o~GWaFL;$nL=v(|>Am>C)@Nx9H;W_Y|857>=O6>d~Jid*Nsj)X#K9qz-8HWBL;nF{Es{zm@ooLNaZF$xS*PZ2^g7<%H@S?iDPQm{^LpyoZ5kIzO1;_}_G*!Ld;RAV%)^vyS_J@oSm4rB9=RAT4>R}@LQ#NeixIa?fHX%VPs{BzEc11)SiTd*>XqzaMhJoM>2OdU+!|C4Wp(>Ucd?YJ_LZwQQ0nC)R=x&h8^#n8EVBkws41qYYXWixhMl!{!#pr&#3NN~^6c4n{-Vy^AjM=dR!`H_a5quJedXx(R*BZM$__!(3-e7+L>m=V{MUGrl$Z_l$?kWd!%ia64pkHv5b$v4g7aqsfr2-Y=TkNE6~{+4+4HCw!TaF-HPrEUa6RUaj>tmr2JZM~~^*RdE)5qJfMtm8Rfflpcj4$W3M__bBhg!kYm`p@tIU;QP;{hp1<TzKT3-B%_+!k-{58f!H-?`FpMypzhE|1hc#e3qXvy_m}'
_e50f94f74d3dc9='`tA+nO3?vL!bnBA!)s?3NmY_xI+EgNYS0{<?O7Y!Lpb~Joj=&tOa+qQ2;jc-N=t+zRTPJ7Y%AgUGw#o|njdDw|fOH>(bb%GF*ABj0S*5#Jx2XFyWwDU<$m6ATneF$&S<Ea}ir&|~ztQ|c!7n3s88h7eCAQ31YUzA_c3(!rVG`inX=DflXn4g5Lq*zE@!LWOazV^6aBsg}R<Dun;V5DFC)Ikt!?fw#9P#JLD4!7x4e|8B1LikmTE#dpn1jJ6I7o@r5c}wqf&#_q!jw4T40%y18#p^HvMf40pr-q<SD;~hk~N82W<wt$3I>J3e~5{CA~PTNu2c@fAv`}=qD50tG7fWDJqJ-yD>2OOsC8NJdv2q98<1z1g`-R2B0dY;DO9yHtm>+DOpN^OMQTK;P|)10Mf*n)K|7Dr*6{6SFj5sr@I?H`<iv*kMVTy9VxIX!8gc=J=t=@Rm&p*uOP~(5B7WQP>5qh>o6lmC(#|cONd`0CFvx2}9?xz5?YmoFr~;eh{8AqRMK#dmS8hDowDa3Vh)+{YPL+x1-J(lt1yvjX7;NRG3IKIRmoG)X9a#_MDmZ@*)XP|3fwZ0?F=f6^w0ARk>`hmU?If8pEZ}dNSg|lgfeNLL07W-8+5UT0#|AZPgGl$*NZBr3?nXy7h-|#^79VJ{^uD7wbrB65TIu&Z@Pacv18+>+JdWgfzIu5J@kO^y@{J_Ne|NR=jk)*;ax}{-ti+3zXlYarx=yf}U^6&l=q~xS1Tjs)N)2O{Ak~`p|03t)7e`9n1F<nE*~=8|sPZY6FasmoG(_;xI^Ew?mL+BCy3JhDV6A~bYn?G2M+KS%?o{UC@U@ljtw39di{mC}cM5}2fS;%WQ(qbYj)c=-giu=J*HL-3tp@%@Y-bb-EOKEV8Hc%AYf1Mq+_QYX$s^0K1Pk#K-n=kTKx2$eBg*POnwEt{<=nT7tK5445E%RO=s#~qh}$nAv$4)U?G98dH}|jeBzCzeUH^7uvw|bM$unxWlQI09jnMp`>cqERsx#5Fz8}5eHN4Z51}^v%+z+wYxO6Q#>#H5Ai%cxr43T{|?d?IK#i8<4CDcEc8)#hQE-ul41Es0b8%YI;jiz|#r1go4TAD&uq(8KIi60iwMWS%Y7UC#fCkb>*b#uOr8}YKfINq;}5l?gY+pOm)emqTy61)UUN%Ic}TIT5R17g<g*4QJLu~vx&$7f|p6s*Ff$8p1rZ3xWp3v-!Tc_}09a5WlTm?~Q0U+&Q6EY(q(f$G(-$1|+q%#|2A{CWv(91~7%30_!Pk*)tC8LwJ<KL;H9AYZatsPwc4D93C_z>0gBn0U6$d)2eJ+0IUNXLW=B(c9P-F1<Z2K`vEuQ(sr(>NJ<8KMstdjCOs2E3qMy;rEgkr0#ylbve?k`L7=V3&@J?llExcTOhcKm5*D-)k<GX`rw%G%7SUJV8t<3^+i0$FURoO!vrMjfh5j}1%Fm64<L5#Z~8YGq~KMSGhkf>uyY1*G?y^rNagqff+uIy+fTd7oCFP3!Sai>w2Vu6!)5{fa+-=cwRW>H&{oHZd7fX)<ywlm5ee{omC&D19=jV)q4~bqBH&!amjF_@Fdt#Yw;A8i8-7n2Wo65%2X#CS;T<lY(YP$Yf}OBkIShhdEg1iI8(m>$gl9g|$ajaKkJYu%STdJZzA'
while 937179712725035118 < 0:
    break
_571411c84d2d6c='j(H2H&aB!^#PL&~nHAk{BQPP(v@M`M)Yc@#4px-AW&^29T>v6z@@%cX^w+IS5u!`Tuo$5+)cR?v!P=}Qko4_gS9$;|wUS?%BN(@O_b+|GD@D03XZebJ1S-nuO!3?YgD7H+OleY+3<x^cx-_#q`fQ~$5*>li9DfS2DMx&a(!scc(j%c$P<a8AXaOXB4kDh%PEjGe;oUMFt*WhV(O>N6U58+lk-Tz$1s#1I*M#7;oE(g!2|&Tq^nA9o<Jaq{c1nCbBnjySerRgk10a2a>;T;!NvD+KrEcvJEoMnlw;iP00PUv&jMvsN{RN<6Z727D|!sE8L3B8C6(snmVGXiVXtHeXDK$KSTCwlAEuackblNONVbeeuzWW%^LYYl+2Sd(w|K5>NZTf~`o@mgYPk)^qU_sY@6b6(_EhHsTk17K_BP?)r6*{htLyKYjCwv6tp+P$oLjWkOK`O7nv-I2%uV=qzqToc(BqcJRE#g8)+&s{1@yOQGk{5AbwkO;|3*;bOY$`AFXm3J(C_uG_{z+5)9;yhlk6Yac>t6KXh=d4<eMu|<g@xjBSCvQF9<!6#cNH@nD5I<V@B1eqVRc3};U43Q~^9%r^4t%k@nnwQ`HdMsM@(Kzz!n?96?W`E@trCMJ}Q~dIFQ!~}oiVX#^n}Pvg#Y`cOFm8WT!UE>kfACV^Q9;^1V&48*)<Q?2kM_abm0W6|ym`S;vU6$8q(GkP;ZB%T?S)0Ip6sgvmohHb=A8;}5Pg+l>qb~hqB@k6RKf{m0l1CoRsJua$Y-igrbE07-vm{Z`)D+!(v7aXFEMZ_8}5=(N8*jWNBPOswqP%%n?_2hcpI92g7;5k`8|v=YSijR`{8~wus_ajN8KflL-6Zl!xYWD$T<VB9>o97F<rzo*ll~dl>NVBrg?S5>>_PtH1+ZhopiKg^s2zN8na2wX|sFoUTd;xO-D5JRMskIKni&<pOc9F#~aURf@3QR$}FQXTB-(kmLut6&;SEj40xE4r;)B?t=?BCsHR$0m3Px58$f7}bJ}0hjnVPudCu(o`K3*UlL4TK>xD&$=pWmujX@vj_-i!iO;@`3hXQ9HC8j8oJB>J3w!SOl-Ow3=3BU$lWqZ~9kGhEMy%hUvl}BGG>qj{zST6uc5PMJrXec44U(Q3h$b1i8QAP;Wm}liVIj_J{k1G1Uhz?~vTNzkNfpisk<D31Zp>pcYm~W@Zi%O97uP4LE5~V61tr$rbV?S-0%tTX`$l)$p_vsTZOPXgMVvR!)JWJhD_lnP#>Cx4YL7k}rZ0>OcC3W@*8De3;<TD18yX@Z#kzO!dxiq|mw=jU8^hc3uk;ynrHfSsO0~0kA$Ffb+u$RCZNN}0*z}j~;JWPt29=QbdII}(dhbss~bQ~nWcXOz2F)LSCCoTm7%%*lKUAM{e6}ZM9Zxc+=-#8w{f&7856!VVRXM%sF@*S=22pM5$M?K%irIZkfqeXkx0w3WR^slt0bs7*HBuJ^@#y{z;*Gy|q6B6OKpPIZ@OCY~8`3#2q{=r7QqzFbfzDkLpM(k@t-@zt}PXsq4aJvXS>4YBR*_~rWPdJ}bA&bjKfXGBoGY%5m<4rD#+(to~H<8tjxEmNw1imPK=vy+CD2{;&kLvW#*UgvS>^^yeOEr=3ew$9$qucDaYAkgzgT!w!TagGLj'
if False:
    _098fb1c2c280 = [80, 37, 170, 131, 16, 18, 17, 198]
    del _098fb1c2c280
_54b6b787eac2f7='WqPS*&Uzr$mb)B?7`DQ%T=xY7rp{i7G}uEP2#jHvLAxTI<MkneQNh!znjLcN>ZX`hKIVT0rDS2H<PMJ(kG1rlJU`yhv~AZ@YS(6Hq_E`0yMM$MCaC|gr^2<(-**Jxa)=o9hDdjgL1S8+cg*huc@5|6CJZK`olig;&;C^^h~#N+SR5R+0NW-o?ro9#>+RlX8w)eOilMcYeFbx9wZ2d~dd~?dw%@%;jxes4=(+VSBIRv`&a7ir0%1#2NPh|bVl6wcj%EJmR14fcpKrW+t^_AsT4M<jFSgWPV`?mE>q`PeZqYcIRJ~n?Nfd_gwu6^X;e4~&&&%F*$lU{bpIrAL{6X^Aj42l_cK+8w*r|I%crQ^R#MS+Lo#cfXfSGJ5!MI6Ep8<rR^Y|WB<v0ai%s=|phG=`)o2WI{qbEoVsMECgmZ@VrWwXXyRtJ5st5xT>4QtI~6HWsnVcaPOlxAF9BUOY;Nfx>1<_OV=Fv`GLOCg<#kAR4;VJyg-x%qc-GfC7Xz?Ry*>j|tJCiLm)14;TrV*+JjU3UP-xOAZ6`r#p?wAb9WNuyI~MQjzL`_G@f>VgANf~8(;oD^@5GT_#<;|}C&M#V+#|I>~!Tjvwbl(rmyj%@)?ka2+Xvb8Fl<+T;Nl+VeCe~+knY5mD)UHo)Ff2my2d=W+F$0G3$b&dnX!JF5!W4bpo7YR4eHu{|==<z&Lh{e!3UUKTJBV#_d=>^H{^LGsO;OKq-GTnGhR(Sd=QPUWiF~HhZ%?~N%#W|<JT26lg^)UAHJ@lWAX5Y!dGStk0)<4X%4bD&rvA6jG0M~wQ^G6c@UQ62*87n0TS1`hj%ItkEv3Q@`n4=>{0|StQ)af$N|MQJ{I3KLRAqH1p6mK&CY|C!}AG@AVmiba3olQIDU~lY~C~1|GalyOT>t(AA{B+pLB)8I}JOC3b*nie(ehaBmnSsth@;yyaoEou%eom1O!2Wa;sn5=YRx$Z#?k!yBjmNGBUrKY`gF6H$+GjbYM+P$Wpsx<Z{`&!c=ReX~(U{3AmV-lCH{t%an?~`+opO)H(w);gI$yJ8Kr+bla`6X>`dW$Q$B12ygErS%bknCX)=KBiCSL{;r`TY^S~gemL10i>S71zSMp=gh#&H5_2|B&*nBh&*>9Hc;$*vktq~zPEt^YXEpB~GO4NORU@Y3#kd@av{@Riqhy={RV(!+}gYT8cvDHWEk4>_3({hyE{cHx1x(@Nv(!Oyqum{H>?G*(Sr<usq&sY@c1Yi1ZD*#TS~_uA3w>oTSs^=OkhJ-0Si_{vip-VIl6VIS#NMZ!X3$lo@`6Dhb=!xIbxHmfNfvD&6i*rQe=+|s70xbRNlq`)>>47^3t*MBoJ{2@c%{-W>N#7!W3B|B_Thq@M@BTi+cFH(U?MnTYHuDGvjvE|<8+cT>J)^%$mIBcE!Gl8@%zaO&q&?HEnXR-jk4kU?uPqt9Jk_$(Px3DgJ&pd)*w+CwAyk}4>lr-t2;x}Y&UG%tiKVf==JdjkVd>BaX&`9A@Q2=n-i(esL8CVM!C&;By000tQ$Jr?m1y9a`?N_e{(*RwJV*KIsc|3lByctv}FyyOMIuFV(aBUB<+%;=jK}D^sk%wX22$)dh+<#3M#iP9?)R_h!R4or@7eRl)oHIPQp1GXf=4632ZkmhouP7<-fH3'
if 382615693481777625 == 382615693481777626:
    _93c05540f72f = 'ZCNeujiuHqTrtUusVbVwJyZw'
    del _93c05540f72f
_f496e184134cc0='Z#Z%V7R!G}mQD@KOoen^2#YN}8Tnne__?Ku-Pe%oIL*uAzGA=vsdBNAK9pZbGhvdid>LhO|zqtaW+UJ0g)&>r`QKK&l>cgaWyBBYyM=bDj-G^I&e-sI*y4bktbRPFs&NP-!k|CdF)Sn{|RQfLbWCVYP`r<BO}+G3T565Umi?9Ww%7k^Z-^lz+nbNw*f&Z+yo~%g|Z0Ze<f)ynUsUcbuW$qD9ygSKp)c5aYI54swee_+m^mA?tL>u$~`|UipS83+KDeW3Vi548>r~!56PF0o=0+P6`-mAk$q>O(`)uNytb^sM~U6^DM|>VwCAji3;+W$WmE&rarY-yY%S$Z!O;lv8URLl;EO!DJ|~1B_A`pBO1d%pq=_w5+1%A3PoHoXD#Qq2?YMk=JcGyD}@o%AK$$~w(~aPwLqVFCwQZ_E;vPp+9#5CG%h3xH3*0MhO?=ZshK$uh2kd<pgp!rB}j+<u5(8`Wrk6LXLkuZ5*m#WtfLR2q!~`fhn4F2e190}7gF*W{AEOADVRh{lhgcL_<Dvh7o}_g^<7uZBI6LZksOIO`(Gz8lE0h3NP#K`vY8!gMEIzt6Fu;N$5}9SjyBcxrwCn?!&dDy-UaM)gM;Av)t3;oR+Z}?kb`HWbl7*CvW{nN;9Q6&M(?lwBW_cA+W=vjG?)Dz@30Q_1=Ay)zPgTKtDF_1_o6aPP8{gcf>_2I0+A%(dN|$Sp+V#D&NPN0kW15z65>7%-b<dmoq)iYrOOCj>02?}g`A}pIDH5@t3q(-zuPwB&SH;*A$GbgSbO2CB}Q|+aLV7;!ou;WK10=*_hj{|Ta3a@diiKZ3M{ILyuj)C7<0(s=>};a$gmo#485Gztq4vUYjS$nq^_3$$s)3TL`B}81)u+J{yRQK?QI461+LvUIYK%=%(Hv8Eq40*J6K%=qETI{?}O&4`{mHoUi2dj(irLZlM5b1<Szl55R_h2Q^=*sR`gEy>-jq$0oN=aHNVKNY-;g3Pt++dSrrjfvm=$*^KP4vy@cn>;mb>Rrv-`0`jk`e?h~rS0QvuwN-<6WK3MZjX)KUROm24PO9;BTp*QCpbi=JNYp$&OoY8x;7;55PjmamL@rDTQN84OSEm{SD5Xbwc?aE9=8$VG>y+%E!;uAGqvFElQ+B}vHQ&$TR*K?2HEM}(tUu%`Jq^suw1U}l_A*xHwxR;d={o1b5f}nGxOi_$t0?+RI{T$9-n5%FASX5Xv6S?X1-VZ#(y+{b=1EkkaALvM3jj#8Wnzy!s3iIwG)_BY{q`?JWO_A`DshA>1PI-s@7h*Pyu;D8oH4Pe&!gI2^PR(6pK(#m9Zr6bAo%TS>QT;uH#2mI;Z7KCZ+cM|6wVo}1yAJwsDC*rs^t^eMM-!$I(h0`QPcZN2t-=IONJy1af)^W(gNP1pS>vJXQjKrC3v;s}6zJ}-qDpt=wSp#;OK-l1VXUiF7oq*Yq9Y8rHH(bno;-12(Lz;|Bgl|@#<_N*uqr;d%chhb&y2eL<%f}Yl{mEFnfUws8(m?s6PWxlRMD(Txg8uR<~0p;LeC_aRLwLOoU*7?DkO55=Z2Ap(5`y$8PBueH<??Rg1AmxoTlzw;6Ioiwl}RKT&LHW?~s{;DlN3;3X6^%E*yEFy`*X2DMfMf_Gua_-!QEdY?t!J$O{Pw?_J}%K<6;e'
if 588886861012514037 == 588886861012514038:
    _e2831d4a1bbf = 'hLYJfHXsfGBuiCXSrYuZTXvO'
    del _e2831d4a1bbf
_78387c5696a584='pY;Xs<NMQy*G6OpYckZntXK7q6wf1g@2@<3^M5vzGoyy7Pj?aE=M1nu-a2BOC`_?IK<!YXq<D0$fG0>H)G1w~!NB~D6~u)ITEOo>h6g#m$VrE{O~{;T%zmax>w6a7H=svp;F!Hjndw<zYGCnu8}<3RZk9buhRYLeZ<ICUtE{%c|5(S%U*a7z;5y?cT}j&&)XS203w6qLXl+$$2NUhwzgFq64oo!Mw8HZzpk0@De(j10T2XAB`@mQTnsf_{575f~4e$x*f22wwz84;xj8JK(i}t#VXBn73j#*gGVfJ~u}KEU_<OlBbb8xdi_)9c-=NSY9@%^%l}=GrH1(_M51|RaIgPuRl?8z(lM4VJd!#zvQphzu>Tv2*usou|<3MfPTv=|JE|ocO<wLvHh|sn!e)43pUOxy1#=ffsdgrkX~e1U&tP4kviyBbfsvm>J$PnbVKVBh{?(>utq}v{Oigz9loMl4~qAZ7#juU5q@hOcofNA@*H!t@4z9)#Pve(&cVoO=m9JT7%BD`l@1j%XL$vEJhe386%mjhY>;w;#f{tjNZ4uBc~OP*I-z=Sdzc&}3poMuHE6QJX2tU14*fk7$Ov3OZkoy~#mj}K*A6vZMKAvoRwUh=TQ$k>H!dOu=<HP<_9?}0ou;|hR5c5r3zc&hLdL&tDAmy|gT>^W7o8o&11{6H0P(7;Kq<}#Tp0*pHGeKt8=yj@IGBVmHD-aO6(9Vumchhob~70mfnRA2o56==D)Nwx9d)y+#-zkFEFm(l4HtBjtTjrB)54WJeT{z!A1H&dwX6|6_0)J-Lu1#Vc6U>z=xtCxIdZVqDS-uy{{D}0l#rv79m$U_$Q4F6pcdS2>u9fT??d-7ULov1O~L|jfkE__-KGFNgCnVQpC|5pxybs4b;40D0ATL)Y*DB{)&76DnI}^Ex(wcGA<fSbkyjvvmbYwZbgBT$3e=R~7*-}<fdmbM3z}A<KD<jtDRwH2^%mVdvSP*Opu;Z`g@>zqyzN<;YlITr8~V{$-9JxR=gc0XsuopY1@5#R*j~}4Xp6q$(>;L{B2a3LRRQmN=s~+3i`^Kvg)lqb#C3+Z4{M0p6<ik~R(PEIr%2OOq;Py>l>oi$q2|qN-L6OZEEPhi_zEEd0d>pb1Bsgq@;Ev6C19s0D93BF=f$Ymrncp;8pY3ci2$R%0_Uuc(c;-!Z^wE_nJ>wEQ*k>c+(OQ12aBy5<t9}!;f8H>p>VS{w%Fci+L6S*;^A-eOD~DtF%n?r8fPCZ;6&k-d(OMC^GL7bm7(R&SzVCgP%4msp`l43tt#JQQUIEWf}kJMgP0$~#JjEQySk$`sj}&HdM$$%9J-ISA4?%J78Kuu#IBmT)m1Akf>bflH!x&P<fw{F#CFsf-#O*CNYsw*1a%OC&lqt+MaTjh8DW!BeOZFvJ7lyVcWVw3>fcGqU5?S@Tv;VS+_Y~i<P`kf?P*9<yXN-2cf>rFj{{G`bYY2KasPrB`Zy0?)rzFxEfRJH7VAg4o3CS7Hw2LYEh`Yu8~|AnSLc4UDY)98q8M2Uy%IR%`&He`eM1(tqd2D85*1#xq^hl__wWC*wsj{5Vb3jD_@9}Cr^uRxB1?*Nu92v{k5G9$LK|ys4<L>`x4Ejx4?dXvl3)QP5|iW+-_{Xv*T-Y-Xj+u=jfGWj=m5T^#'
_c6a3834302edfb='t6QzI;S%9g75Dlu4+pVH{4qGJC7DMYdgeYeB)Vs;pGW2V%dHED~T(hMEF$?loedgjuljrG(WL#ZR6&nba#$)taHNvr!0B$wTnr#JxG{$sl(Nlz+<x*efNHm#ZFtpUgZ3!sITI8#bSw;<A)3n|B8S*=R8xMoSPjtF0Z8wS4Qyg0|{{ZlI%6EqH=U9OVU)?7{az>)~B=8^`=0GRujiC2wBx7P3r`6YC&1IOvKu?gh@QDz2^+u|0Q%Pi<CxMrfabB$yHgTEE*t;`s@QwA=+(8hkx5Ey}pr2;OV06)(wSBDSOlwAA%{ihh}05mLw*ojHg(=x<_R&LqoRJcKV<`GbG&oq&#YGhhgtR4CE%7_LvI6G`jJ|uhu!5EHI!9tsNSw|I$8T&%F=D>sqfe4$~S}^R-8UjRC<Zd`(S&THGC{5)Nc}_Ej4DuobL}Onw#wO_4-k^Ljv^HU5GjxG<S8FWz_v@6T^_Hgw?wwWWA?^EeBYzCy+(P=-hmU`mY{IM>U?MI$#~adOQ!NT$IQ_ad3Zd&e7C*@wb08I*cF*A&*WODqo7)#ZAs`1P$-CxFVvDY&Rc$@|aE*%uTHb!B$Nofg*;`7~)@F|m54uP6{a?gW*AMN4<Yfr;U_l)yH;gM9gPdf|lhP0Z5}XY33s$Vz#%{$-?fkNfcZ)2L*Reb76y<;JB-Bp+RUgog2*s68C@h*H{N>GB(+Um)If=KQCrUlF2JoAC2=??Qdd8f<1M#YcnV_OP_aLoZAQ`s7Jhy1Yc(VEP$k1UZM*nqe9j^Q0_R<4w`OM9H{Z68{*Pl#-uD^PTScrF`0?sLZQTPBrEA+T>hmuHmD;o_^}7Vx<`uZJQ~0P<61$K72xpjK+UGqa1#u7R*=BvtU3=ymmiMG$|Rkt2Wgx5W>Jw`KYeb8w0bh>!#x_n;Tmz=}S}K2_TW}aS^Wg`~ZpiYEX#y-7l<F=`^}sJE^u@$Lr+kk>k(m8hb#9wx-{hM}3Yz9QLiA1-EJod&T9Th`D$uJ||~j1v^IDj<i2=k&*MOKtE)WHj;Z&Y&JiTmr*I}G<~~<<s4_IDs0E&l@oEEf12&8<^e~D+~FrImUFlYow5bKln2r@gp-{LT8{3o+bV4N4Ygxus{@eSYR1RHn^U*ZvNl@&S1sj~f7&etrH{i}7%Jk|Hf~!?aBFL;kvfeMTFOauhti4n{FkTkbWOj#@xAUOT+k3eUoyV&Cj}pnY_P@p126v(Hrr~E?CkIrH8+;A8AB2Bs+piDuiQ+szch?0w|R}!|0Vu+F`oaL<IFbW@v#_QyjYrS9Sd4`e^q8}sjEmLn)KHn#aYuU<%Z}eo9L(L`@S3OTW!-C<RXFU^W8uA>;-g~pgd>Ik;@LC(wp+Bx9Bid1u8hiV_);m-4?1@2KVzB7*)w^NgE1<*#vCwiyNMyGg@1Oh4kVeu@SFng@IA%y`swnv(0UfoPi*SkMr`fb)#l$2LfKds)zg^65iiv1pd1K>yps!Zc}ml%@?y0)@0b%Dp^J*P-`emP-$$3zNE@K4ZN2Bbt9<)ue)CEd2(5lPKz%rA>q<6h|ivS$e2*L2624_ldoj?t`IgtFUc!1{>(!Lmn=`m4CEeI&jwoK!eZ^#YFCAa(R{ohOVk4%n!>H`(N}rfGQv=v%;H7?G(~V|Q|(HPyvDwh$?k(ty06NOk$bu'
while 382293567793791199 < 0:
    break
_af444e73542783='4AfVCXAE}Nz))UTl)YG)V*p-OOOS>;JfM>E@<xM%W;h9G`GIVXo3se=TxD92%DtZ;61<oBG1&JA!e1YfrX?*G(x}PLPIAN5IOqjmg7lA3A_~G%=qAlmu3u(xBi8hZr;PYCH=;e4dVTlSF+1myL7G1bWcr9dry?T?vzNi`KT@sgUWYqyW!HdUz6;qE_GS29E$&U~0y8imLPoe+Xmu@abyOAQ6CTr}jBSh(?}x=YC}7`>S<d)ocr&A1u;@_ukGBa*%E1O%yMcKDfrjTxm22;0xd#WV(NZ&jfx~Q8u|Db!=p1@;sKVv9J$khVIJknKn=5$m`jUY<)BxhVH^yTFVqq2{pYOmy6D5UZ3~H(}c|kRalb+*_dPK}M*W#`ycW8v`nR(r|O!RN-;<i{bV!frkNVICPtNgB!%p6j-?h#zY@~OdzAAF$}316}~RNv`n&m(dWws$pg_42w|_@r*~Rx?emSZ@;er9P8yfZm0J>fVd{T&E;EuBOZBHbdJ|b)PtbAWf60=p)j2&5L8YE|>j<U@P0Da%a0yK=*KpDvZP1`{&-(HFtMu@7+5@HW=|HXhE&@b*d-OtWq}Ebp~!CCe1U#d9TVj3Speab3zS&e!im`_4L41Kl>9B`e}2r;k;A-Q6=p*`xZ|x7gKD^lBQ8)TnF^3Pt;%Iz3jTtoQvXTY$K5uKBe#Kghu}BFuE<>e2iYH_sFU{x7S)7zhmluw8dv&-=(VF@@zcXQvJGzQHzTH^~ZD`H~t8I!(d~6Log<bu*)XvDK?RQ8`t+BPm`=DT<Xta&+O9K{N3~T(VMUkJZd6d`H9gX%9RWkLYFTjCtB#{B$k?M^6aRU;I}yP{eRVO9bz|?;jy8Xe7^N64R_B}8Ci=pe|xTe#v%OYz36sEz<ON4*N}*|_ef~)oBfyK*`}x1>}vCSiyzi?8lvdI_?RohL3vg&9v#ByB?y~b0K2IbheLIcSd8arcvn&U+(jQ}9-n(lXeN6Fe8g>^ef(4P1(Oqn=Dvoe8lf5=(K`!#2<b*j2Ju-sIe=NU7dcEU5GBBN!2Lxe(sBRo(J#X6CRvdUk!){0R4}vo!zj8ICg+m8Q+r4DGXQu?IrCVN_zl4rF3~-hPl<ieTrg2-Q+^AlL*#+fBEho27zjki_bRi)JJ;JQBA~yllG<d~Ju1O_g+y0tn$MuNRl)MU=e*iM2$wY#8e=|ycUH<mQ2{@BYT7><q4hc_Tln2j43XttaeBiJjGzwcrYrG&!m;6dhcCuTf(U?emKiw=)4gIWYnnW@`uvuMGE5r2(!yc;@{a&!D{o=yrmG9=>y14OAd1Tmc-5W3O8$0q7==7dN$5VQh)Rs*>B`>c+{*$at;y>we=*8M4A_{j(2Y^$I8zx&-R>DY{t}NKDeWI6qM#CVy*Tob02LTC>xUq>qX|MiA0uoz4cY2mAyY?a%M}#plA3mXjMH%RLX~T*IOtu3OK9QahDNbWymE`_6^*|c2Xn3xHj;nq^I)WH_>bEb*4i^_K;`(5_Xp)R^LW-}Uu{u&Z(`y*_-4-`lIw>gxM?EdYkk~#JG8*a)nBzXAwJ+!I^3?TrbDjbDW&y2&jU%0%=RKK%F?`O?f{dqCZR}pdsHYiYV(z%uoGk(WgA6&7U-dZ`4#csqCmEXT|<_fgD4g~BjpL*gNI=#e829RK~D'

_fecda871f972=3739205
_634364b14a70=[32,114,180,234,117]
_1508a7d1a145=1488726
_4c1b095ae6bb=lambda: None

# keys
_e4ce91646ed4fe=b'\x9cZ\xc5\xdb\x08z\xde\xed\x83\xa1\t\xb6\xca\t\xd9M\xb0\xe3D)L\x82Vr#*\xbb\x85\xe1U\x11\x7f'
_98c2148e6dfa27=b'c\xb30\xe6&y\xad\xdc:K`B\xfa\xf8\x17\xa6\xf0:\x0c<\x16?,.gi\xb6B\x12J\xbe\xb5'
_068e468fa4c5d8=b'wo\xcfKj\xb7\xda\xb8\x89\xf5\x8a\xe2\x90\xb5\x08s\xf74\xeeX\xb4\x86\xce\xee\xa0l)\xbc\xc9\xd5\xdb\xa9'
_e2c8d4c5f06e=bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(_e4ce91646ed4fe,_98c2148e6dfa27)),_068e468fa4c5d8))
del _e4ce91646ed4fe,_98c2148e6dfa27,_068e468fa4c5d8

_acaaeefaf3b26e=b'\xa2\xa0?\xc5\x02\xb0\xbaB\xe8%99\xeeL\xbc[\x85\x81c1H\x86\x8b\x1bd\x19\xd7\xeb\xa8S7)'
_06e889338b0351=b'\xact\xb7V\x15;ug\x91\x01\xe5\x9d\x1f\xae\xc7g\xddn\xe4]04=\xd0\x83\xa7j\xa8\x197\xb0\xa7'
_0ffc75052fd7a0=b'l\xa3\r`*_\x95\xcb{;\x8c\xb7\x10\x0f\x7f\xcdE>\xc4A\x0f\x90\xce8\x16\x1dR\x17($v\x0f'
_7f05d1d295d366=b'2\x1f\xcb,d&h\xccx\x89SMn!P\t1\x1a$y\xbc\xbf\xc2\x9dD\xd6\x89\x03\xa09\xe4A'
_cfcf201880947b=b'Qz\xab\xf8Sw\xb33,\x15\x82\xfc\xddjM\xda\x9b\xd35\xa4\xbe\x95\xf6\x05x\r\xe4\xd0D\x14G9'
_8ef81133d773=bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(_acaaeefaf3b26e,_06e889338b0351)),_0ffc75052fd7a0)),_7f05d1d295d366)),_cfcf201880947b))
del _acaaeefaf3b26e,_06e889338b0351,_0ffc75052fd7a0,_7f05d1d295d366,_cfcf201880947b

if _af53c5383230.gettrace() is not None:_af53c5383230.exit(1)

_e05891ba4cd9=_5867aed926aa.b85decode(_54b6b787eac2f7+_571411c84d2d6c+_0ffb15f78db8fb+_e50f94f74d3dc9+_f496e184134cc0+_af444e73542783+_78387c5696a584+_c6a3834302edfb)

try:
    _9641191269a0=__hydra_aes_decrypt(_e2c8d4c5f06e,_8ef81133d773,_e05891ba4cd9)
except Exception as __e:
    _af53c5383230.exit(2)
del _e05891ba4cd9,_e2c8d4c5f06e,_8ef81133d773

_0e9205964765='CEYrtjmcHw'
_e9a7186e4614=1331751
_8945856a0b0c='tOPQXuajzXj'
_e86bddb43aec=[19,74,179,165,114]

_9641191269a0=_2f0b0ad78a5c.decompress(_9641191269a0)
_9641191269a0=__unscramble_bytecode(_9641191269a0)
exec(_6bb085b9e642.loads(_9641191269a0))
del _9641191269a0
