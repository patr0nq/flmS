# PATR0N
#! 8d2dc58933902d5c72258acd9602bd459827625d43019a3222de33edad437da1



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


_7b9a3f06fa77='ZFiVKjK'
_b8064642e79f=[85,29,12,248]
_dcda6b79868f=[248,240,88]
_764849f16026=[76,65,145]
_3b92a3ec331e='spiclkUN'
_268da7040424=[100,97,168,254]

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

_de295de0bedd=__import__('hashlib')
_ccfbffacbf45=__import__('hmac')
_1ab950e1ae0c=__import__('zlib')
_db6bef191b6f=__import__('marshal')
_92516d5f4490=__import__('base64')
_20928d29c42a=__import__('sys')

_2d020ce5247d='IAlBayi'
_98d5b17af284=[100,122,185,96,154]
_9824d25e7698=lambda: None
_c0ed9baaf0d6=[62,13,205]
_5cc61b2f7777='IIoRVnnpH'

while 215499509981048680 < 0:
    break
if False:
    _b9ed8db386af = [173, 90, 245, 208, 225, 96, 67, 100]
    del _b9ed8db386af
while 605202786459003687 < 0:
    break

_032fab9bdaf269='lLqWdJfalY+|01=+3)s&Bx$fHXAbdynP_;aq*#YbE11n-<qsR^wAKd=W;BKi@VV&x<zj0OJ^T)2ns@D)xHw)&Nf|XG5ncG>g`1#hjLeuV3EX2C^vPPeqOn2ByrHAQepn%7u%n%eqhgaV*ERMUBhy#|5}%p2*0znIeo<S)`2piY7aSYE?AYPk_6do6T^r*GF~}vYF+Uvwg^Hhp>}@UxIUg^b?klf5F(qLnP;7jtu8bl@>Qk79>CON5W3(ay8^${mU8oaB;`-XGfr1GH_kfAc(2gQZVdYD!*VZ6;2L;T;D2F5zu5LCk`P?^C)oewbiE4KDBvJ8|8;ph8YKI88OAgSk3AW%#uZ1ry7uQ2EV9Bp{1RG?PS=~}`Ij29DMsQi_^%hzjv^*oOEnuYoTsMGAA`%97srU`{Bf^W%nSGKOH$2LU?~|{UnU1sv4Zf6l-kmbQdHymUp|$G2kkw6Vlnx9ZlP0>#xTT`VFgBr*0US068p;_a$kF9$>9);Ws4d<5@P$3I$4$><o-~gM&_C#T%Sub3O~DL9JM9OKoJmBqX^**B-yjjZ0Ab@v^&6zh2&7ZbDcuW%=XY`q3md|h4b|DJZ9Oes#*B&S@G6{C7OBPX0V^;BRx&gfUItbrb&lB$M58K1ogyHesI;x~vI@ZOU*ZHiNOiX7lu-U1J)t5})B`~VB?#9kTS_NEAV#4CI3cYZ?}n8#?jD*P3HOL^!XWl0Rthd6>zsIEML@PyMGU^P33KdXeBgF;t}E={2GcR_JvkYa#OyjM<MsQ>I$t>`K2!o_B6K15?`JeylmH=-v6EuMneU9(;dR!MwoY=M#6E4zVcU*+Qf#ebdA8UroAJmtn_#W_I@^m_l38-00bc?UH6koL3;DHCY2ScH8{X!{!)uhmx+~DI*t+Cf4rhF|b}R(yPhT3yq|GoBnO0D*&|+2}aF=z@ZweU`m7sRSA*-1J?B1=P)7@`xrQL5NKfgU%0|ULRW`ThV)<Fq<Vo~L>s;KM28!$Pu)D{gKYuf|?q7gX1Oali|4^|N^)%&tea!`(;vEX8P7=loq@^yP3bCe=~c?7gSKN59MCv;v5n!fkHoJ6G^&jd}cImWiS!p;UCp2^|lLn}vw7>JkxPY*T6PuY@KmJmN9rKun`XQ7Tlz#QTkZw`<##xuR9f2K<{pBIS|$AT9LlI%!tZP{dJWvTVL@VA?3m;K6RZ9skS3Vr@JJLr8`*1@P_SxeXP!`cM`MF>Lg1Cei?gI(zrM?~jsUsL7CUdGwP=LMY4ApY#%>#c6)k_|*ko2yZpWzIDj#c+JPX4j2P;bW@tyg?L(8P$~rXH}M}W4_uJ&IrZ2-F^~MetBY*UHMJKsG-Px6T^h<>uGQbAc<=&J(@_Yn^{LQB(<ZbkOJH5vqlJe2h&#8X!D8D97ia*cKm$o#VKuhB(Fv%e;|nKWbR+ol5kI)&)UdX*3JRp1^Dj*(DXEWA`#Mol^`<^b11Z%lcFFHcm?Htot-r7ENug5$VCkOTh;N5>bMak(+~oVx>H@LGtTfj3|ZJ98J}`n1Fv>ea;vK`JYK!o!j_c3LB^QL3l{@rA&$QGU+8w@h#bERA=nQ71<ph5tZ8bYlo!J~y@^kL{b7q^W+EsYw2gZG%^8!(90(aKTAm^_Q#hG}VmAegyk?YX@M||yNL@O2_}Tg$LdINcnAY+H>pl~5tndgRWseNs)WYNGQ+Zsw4S)B%_BToGL90vqT9!Yt#pc#$EHJ-n1gFjK*i6bv(TSsGbrN=Xvl^3dpnt3AnJw`BVzIsXv^4vP?qQim1RIzkD0%)s;(7bRoEMNT3hph<mBvp&gYZ8Qi>papbiKFL|J}1%&ranruUGu;95$>gMc=ju!&6rPg#I1wt^K}79Tbm`UnKOtPo8<fHFelkN2;gvYpxz5`J2Wg4L<'
_f227f81e4f2d39='kcxK6tVW&B6@t|yVH-eoA8%<H*QZ$;_@d5=)O=h7wIEv6rsiV&hF6JPt|W2ar=IWa?k`N)wl;JXBPX@uU9qFT-t{-hA3>}vXB*E_L*ny7$HK$VL{hf2>mZHZyRP0Ef7~lM=tr8NWYeZ-^unZcRGnSN`Fu&bLKn1z3d>KK9&^Up4vAG^g&LX7Wn-OI8#bZ3G)`+}#D@@{m^gObAC`1MY+=&QpKGo<@n$C{wSftwsK3Qk%J#C06(Pq;u4bL^QkiEI+@kXS)udvJ^)pPi%@*&>l7cb`#_zh5`gv<dz+UxCGCzpk{k+)_c0@6WCTb}M*IOJ(dd;r}T;&fX^wc}IYY*$@DdLoY;p)hIvf>r$sQ*Ho)4ggJf>G?((QhV78Qbr(H7$|7q{}mDWKsDgq?;Y>2J~+vC!*eexCR6j>fy1$g`h<o3pOiFpvwh%)`1YgEI;wrjSgHn2&-^eJd1cB4O;Snh++}TOTA;dEFtc7ZA#7DL*yO=?}uXncnz*3_h?Twqmf%45l1PRz)lSq#crfWA8$7lOp|e*zZAASfELubh$$il7T!Zzylgd2TbzptR^+Q_f;D#KK+fRh%>-|q?8%M6YTW63{L?|)j5K+XtMYQ{sf3euy=%HgGvn5bRyASHhV|uEf69uAxW(~p*nA$3kRLj|T!$<hdaFF{Sm=94u9|i+zbDASpLC#-f_cOx-swt5pYyf7iwid)ZM&gWk=7>u4(I=rPQIxzmI{whF+fuNzPMi<G`O%ha*!*d@iI>uI~CMS!}S}9dT7PRK^{NIZk_`PSd@ToR9jJ2r3d&Dc?Cyj(QPAK^(Da#3oh7UWt){UEt}k|<<g2A@JggDj7rm;y|mdfHmkQ;MM%u}L+3`jx7#w8KZIS~i1$F#IduPm{$c<bgUw!4=-A;!G?XkE@)#dhwvYODr)HDc#vP0wLRbcxgYBpDf?${g^~@c%rEL5*8p6C6p6Alxq@DabA*}OI{?Ti_a-%@c&F&bx0Pa=3A#VS4(~gS{Vc}1+#tjxX3i|_FjBO7@mQuq4AU5q7Fo_j@y*)TXy%Ajr@aX)5V09`s;f$erdN(urn}Kcq$$5Xh`GF@5ig#!J<^`TmTPHUbg8t6)PfUZ>&rBCEv0x>$hCHV;cZ=KZiMNcG<n{)5Y$D%<-?8G)*@{>0MCigVKd=^6Z4iRz7;c-GvfxJ=s>UZ{uhTP9>leRGCnI0r(os+4)g`=?_uJyO(9})5dQ?O=MLadNj0Ii6p6v)VfM#1v+ib&z9>}`0=UDuOBfK^Z48buOKP<_s->>_<+F?nh^bq8nV63E3dIY|hR#$L$XCH(bFncGaL!eZ@ga%yX7t^E2`U{ejM^s!~&*T|xJ$rb^|KtBtb(Pc(+<Hfz1nn)R+QGrCfrP9J#!96+LGG0rlP}uArpOzw=MuEe#x_M%!-COP0JtciD|=X3|3HOE)IogNhsa9U=kR}PBV@D~{f5=!ki9FR!w*r#B^+pvAUJlpD))qzx|&n9w!8QSjY=%oP|?2F`5W@FlF8ALr0a%oLNnR~B2axCSjWkqMqk3FzrUHX6bZ?vy>gX2tHe&Qm<8vjoc`2MPcRawODX&|`gu5QW!`*2f+5%S(_e23MMjL_ve1f#TA(H1RoyGBG7{JTb^67Xf4AVHR}d=qe?PW~su#InF@jQfS5iE{gPgD8xX?X`zc9PhyVpY}v3BtNck2-mVodK4PSvFv;Ska-l_%=z+i%1&P>-!iMub-hM&!K)w-AeEO1-$%YgXly7~k`tPD56yh(yBCFVGdnH3~C@bMWz^*1O3a)yl<}crp#|ouzZ`$!|mS5B4%nbFWV-{cOpe|5pRJ1Oo-N?f$3G98RaE|B=D!=ST#Y-|@dU`m)&?&r|=)UpVcl(IY-ekNgy4LXCk~h!j1IWnh|*P$RLd'
_fc64d10af13b9b='KXL()kf#!yj4;K?lFY_jSn3;jalXR2>lsS(Lvw_bFNv#<F3DzQq)zzpcFj!>D+y2P#cG@P98KV`Nw&mJ-?C1Fv$&(9kf(0(cm~&k1RPlbX;)A|K-k{6N8n+N%6YF?^LDm#LH9zv9`1R!O#_<sfiG4jhkt~r8dy!<P4re1?60_rX*2m<cwL<_zGa>Oa}sO|vuZZ=K_KAIQVF0|?<THJw3V3*^#kQ(Zz&abD+Tcg5*Eing_ZMJ58bP)hvIK#j~%!xCV26s*)lM7Y|{!nohl%cMVP<t(~@Pds-$EfKnvXbO!K(ywlM)BLDI#_2<Ih#?x%QaxpU-L4JQT!k%*9mp=Eu*szmAv?nOKob?ke6tv!YggvvA%Ugc6NYi@Pi+CZerw8)kQLV)kndPt)d<Xo&ynqZ&kxd9ktR**buOKbLkh(VoYf0ImqSb|)tcyw?HsJ{W=rg#Y?G@)m1!<}nt&=uI6qzOu7XXfx;S1+x&t@D!5Wa1<PdhhweyYTS2ooN+nQ5-44B?27ibyfPIJmYRigrtWJZ-Ec-FHfM|EP#tJzzFBI>mmc#odOjPrOYCsmLd%NcJ_p>X@MK{j5XG5R$zI8dw%TCKF;MDIxNE<30JolHw1Uj_Q>D@g#adkWgcx@eW_Ul#Ri;nyl7sWCySrCK$rd7saqqNvIr<9p@NE~*<b11`=iMrolOZ?d!zb#t352YIFveIpkBEIRTMrNaeQ#RMJDiv@{{_Mvz9~;JUds;qfGlJ?{;2Vtjxx5&wp*!*td`-^b*9w&itNDCxW)elppT!s2Hun|4UzI8DZ3s00pNg-_By>7gir>7mudK76QGWFBX4(^1wkx>dS-4S4r;jYC%Gtue%O*{z3FxAO1Pv34G<kqxi25e6%r4z&Ht_W!H{c%78|^4Th)7M+-^1fXX&C3p6PtYcN(H+AAIQNr-s-U0ru<RP)pTScDRk*m5_<su3Y*@E{{W+Bn*VOI1NukD$@&V^-4TrGr`L@>eVW6nOsw3U>al{iN?$T{bo>c^uOXP<a(9d-dr3G8Sn@SJP_6Jo?GetAmhT`fXtRjl`w-%6{!N!T>AkC-f(;kJ4S5VBXfyRT`qKa$x(h3IwUvy0@NPYw>86WV;sqX@-6b#;v#<?VB6W#L8!m?^Gjub%+_19lGQw_tNI>K_ckaFBI!YB6bF`UdeX6QXGg=q4v+Ea!cz&m8K0H+Fwvk60ifhIh>h`u0I6t!N)WQ#Bmc-<ypuDvk?41t?lQt5El}_4<)#wYYPC01S4ZEUog7t#~Cg^j1ONyhK_I~2LHfG_}tTQ#-X=<PsktQAlCt0TdIOhg)0(kqwEZ2c2C68)`Tt#MX=5ZYX6+_a=%rRfd6ZgvIf5V8v|LiiYAbu_)$?#45r@$@3o^Pq`wU<rPN6PFk#&V&YUn5*!8HjV|`;D0MmTe+k;E)9;)%P%1zM+`xlbjYcTY(s_$674@@=kfg9bN#gox&Chx*;t}G$^zyka%QLo6Z?Z_zk_fDf{Ui&1VmuB@XUL)8r8={q^;E^0m|4E@LHNgJi&a52Fn#xRJoTUfRXj>4ULQgYC&zLyT`SRK{8k*F9rzPBo8<{}#vRz4U^GtFo`L&tU?=BAxn)W>lTwEg=x`m-v1ls;|MJCC*h6gA7J=w(|Ia}6n#**|RqHcYPnj#e`bbZnAeY5iID(ArsDV>>()~ne{wxm(U^c*<JLgEn3wY++tBN|y@RVq-F;?&nH-%EMH+r>@qxUoden(Tw`#^Jg@J=B5gNe@fw!ObT}a4=!thd&``%HXAaCN6h40lUl_D!PO%Y$ho366NUOkWYPdd5G`UC0d?lBg&XUTvwp-Cj(|3JAl|(g|fViOq=4eP$@w+`D<5vigQqgV!WtI7|o00a1L)xLO6ktx%`!u`{05kRJ~-;k>T+Y'
if False:
    _c9e1a853d7ee = [105, 54, 86, 179, 17, 132, 26, 228]
    del _c9e1a853d7ee
_d619881c5ceea1='l@N{inG}~0rCCVqc*Wi#=MLP47rmeF;Rm5kLSTn20rk>RS!0LST@CE}KH|r5=4&GB_@u^;Lecz9Vg{pCB(wGV{H7KS$$*;Sn7oR=v9^+`UPmi*HWd-f>Imnm!!3x0AOmEof*6W!k0}!h9fw48(JMc<x`XNPXbm=W47%7ylX{GXCl`NA8UP=<WzmMc#wX3Fk@sPChTve6{!Awdw&&$tN?ngZlt$FY^?mZfwnk}@_{yn_Uu;{5R=|M_dM3FLF;XQ11blKMiwFIh>HO@KCADZUoeF5zehF>)y%fh9O2GbY;TU7LL+gCBc)z(ogzf2kKpI&8L~WyWWD7I&_SXQ61gwI9c)_I-%XZqvXpQu^AP%9{yCz0J_(-V8Xgx{3Aa1p!auIUSJxYtR*2E0_Mk6Mee}7P9`12$S^KnjFm&06V@>mTct341Qc;2-j&#P6I7gFn~vHlBUo{YxMAgCp|y3R{xl71BMf*@=8Nmk}>x3?3yX(pt}FRzN?ber<X5~Pv+q>NmxrE@a$h}4G)0M4cP|3g+>U<ejwL{1LsB?FW`_uC=bR&xtGcOH~ZpDoqf^TQw>UmGUmQO;4>>fq}3d4%^a-~(+$Nd_aVU#b}V;_lz#a{`|_h8)yog4s^!#hBnl{+RnLH(3Mb3AI-$JG-)h_5VeHBo+<5vfJzFQ@0zk#Hci1t5E-myRK3k)u>c0!bBScJj+5oV{)do|A?U0>R|@E@JVtZC6E|ZXv|Dvo}JP<10w4Re)&;J8={%q?od()lDHr6(KRjD$M}jDe=qi8c$~1D^-AlgSjHA;5m1H7oHjv9Tol%ePnCrjXh`ZNyJ4!i?O;PE8vy9%5DGpMjs6eEj)H|jL~qW=mD9L-E4eC(DW>h{iVNKqn9%kU;;(x^=GOA&F#EYIkkGlvsJ(n?RjyHaB#8mq{rxc_(85X@eaT}j6_Qx%^S=_Q%B3ARf-<=b1o^v$Z5BL~4R7!ktCX)c_p2$#a%kLJ@(eR?i1(DlA6%D@#L=FA!+f0-+@#F4Vt5zp2DHY%z6$+V3asirB07s84Kv}y)oL;aur0aUH{Dsohx}Bl#j1AV)SEVkYLXzIbAFj0g0yc42Kx-IwTHyuYHsBjw{&LLT?azOp9aK;JQd>Y&-eGME6JRr2%$j2Q#psA<fl$}n;=f7*l^}fMO56DZ7zz3GpWwWGLxh<g62^O7G^A`lbDy|w1Su6FV%#cg`Qco-8YTBM{k3xWp8QmeSXXD*^x4L1k3Vg&DurPC}56{R3`LI7<I>>up^;U@Y#9Kv9w_b!^ls1DepBpc%bLJ$2;aRBj|v!+)imW&+>gp+!5;qsn{|C>T;!#rw8%cW))gi*M8OnFRI$Y{ohN)FkosaZ=Hm8OTkf^-V}Vq&%;J?1kk&kCz1)PXV^&Mt;4JdXfdu-kR|S5nmKM77oJ7rSg667ByIC<II%Qp0jJ;L2oD5)@RW@WbRXtwQRGP%eh@V|c!0K!m6}uriHW{s)7P+PFpV!(NR)dg*xBv-`B!H^8wRR`LQH*$Pr5wkR|pX3kBs*Sl|phvnYc`aDB`|#Q4^A~z4b7HUDfN1j{%(AkCfmW488KnW(t}cCQCEf?RLi-y4(F7KAq!b#HCCvDo9LPXJR*aL#u~|0X6ssl@j>)^A~-@Msy4%A9K?~+P6Sc?tN+_aPs~H_g^*R7*4d-I*9qD72|g}0kM*U5H0eRbrA7kHL*LbbnC%3e5(bXIle{?Oj0&ys<zbdm19l!z)UU?d)kd(+C-R4T>y#of^Rhjb$9JGMJ2XkDNP$`A(Y=QEE57rI2(dlVpRC<?b6&OXGGx~-bkt}$1RkBb;ebGaTo>UVXX+?Kp3h*X0XaG5j1AeQ|;`B2^7ZfYj>i5KQg*`>DLY6w7Pl+6vPi&)9?(mMk<WV?5%x)&<8;*'
if False:
    _26090ab23ad8 = [251, 62, 133, 80, 141, 112, 193, 30]
    del _26090ab23ad8
_634a46ee036e60=')YVpkNNj;KeWJEY>s9k7CHcmB^6Xi)7vlp0*YO^pChaM8M5El|IZN(ct(i3iNxUIV6_F_s)qDB|PlX^|o>LU{=PNve8aM%80)J|`pPDXKyX&Hu&nod$wI+%Nj&`(<u(ZG~8>&06Q=0Lhv<Jd+$1E$lfh|~=JO((afL2kobye~uOamf7kpfzvOKwuRX9UligR|B%j|ZhN1%aWQzgWyw9h~&{!&$=G523O-tH)bW2Pq3uKj`b*!EIP3L%2L2fbZ|r-Yg^@NzxkcYY;>C%+v`<pcqvuKS~o6%9|_x=0#P%&nkKgY8I5`SeT`_6KF--^c6$6Vjs|H>W|eN_TgK1sebT`W>gLHgiKyzO1&k8*FnP@uCeb8lb=5i)$Tb)=h#T<<b*W4Yi+35lvJ<Rk;5?#R}ug&v_P(A&W0d@VCc!1y@GjyrU8?u+_hRR+n2J#x$SJsbX^>m-4n^VF)4rqRd9>#>zh<limZ~c^$N@C?zVm{D2sW~+xhe{Xv3HA4mg-(_<^X!x@VnLjLxsaqq^<Abtmp(Y#;pVc1g|!3p<4gQn_F2iuN-T)=Sm_{&*5bE^LNL*-8wrF>Eb45EZM;%fd^nG#NHrY0%BuDS`HeB*%(J{DKA5pcwRJ^m6dq5>JaOYQZ<T$f5Iap_m8t4?T>&ZY`c)_F+y{ucCUP2-q&88(E{`xMgb*^2LB)WIA|#PeyQ-un>@qm6Zd0-hP>ccvYjZ;-Y$9D%)lw_2o<p8mzy6sU#O_$-YI2cC<x(lUmwM1JJNIJ1v3tl+2bkGWMp`wb-<gl91pSI=rAqbnc02ml3Mi`#?I+uoNK~6Tw_3i>9!_Q@(4p6bQ>Aeu4dTVZ|5xcCz;Gu#$KNK-_WKSlhM##qVzyLFd^kUvXYZiiiswqc|z{jU(~Y{sif-yoB5{j=1eW?>91+VL+2OeGEOPhNDoO+CE&;vNtCS7iM=lh;Rezys}|wDgZx8U9MF!@|F6DrWOq3vqHac3`$Do7Pw)Bwd5A#(=u+R*m`F>W#}fd9L%c5>z`0wpgIDP&KGY}(!|qD<Zl*)mkGcA5-RQgoP-!i<aLU8rP7D7PZ_coz6{QlYxIk5zJ@X(a~c(?d4=5egYk)``nAa%C!U2F!mmu{ScG$j)EIXokroE`>fN0sQ`A{!3?qeJ+GAdg>AY?1{7D~3i<F47W<Y~St#qWWhxdtBgM<<<=^K{&t06}{5yrl5Hcz|YK#4mWjg{7+=p##V%XCzW0|{oV$=e*H)Z>HUFFNlDh$CSjDQIQ#`G=H|7^3mhY?bpf3K&$d8eIU!YiTdRoz`U9Rvir~tW%VeOwtSt&I(Z`Tqyy?!nC#n<sg*mz`QSeQ_P1El;V@uaXBlSNdw6L{@?!DX!xt@Bn!5PUVcLKGfZ2+_p=CHph_|ZIN}2%>Fh@ici-;aG(By=didHP25+`JK0P)V!lkVSO$Fqx&(`sCSm^OboX899fddc!U8(Q`-z33sm!CW3tV2<ASm#>Z<+&wu%E`yjJ}weRO_B#k@!6^?oKfHfW&moxX?@dP7hPD&NB1w7X*0cguxUf2zLa3gBn?Sf&=WlW*lt$mbiyWx_6vG#L^%;aB2k#P=Vch@!sAHF)A#@N0Wpzq8a5Wz*Z^NQY5%of!B@CPDh+rEjne@0g1X_xEs;eu_AN{I(Kh8ruIXaQ&AH_&BZX9<*+$Q9VL5i+<C_NcZgG@<Xw4uKyy4MH>g4v-&>qgD6J?nMWmh3+A_*^udFdx~BWtaR3#Cfm4RX2iPMrPj0dw|buBluK@KcoI&ie8_9~CGJrH5b6=+B;6TRiuI-&WY^S^P(sBmRCTwJ;Z+p~X1LI~vTKSq?^KfRGY%PQvg;?HVEu$(#j}13Qe`P6S-zcAq>j#D06y2JG^<O_8gN5?8G7O(L2U@|OZx;Q3&%'
if 458322166337381449 == 458322166337381450:
    _32343ee87aec = 'rvGQxGMvfXMLFPOFJuveWFSu'
    del _32343ee87aec
_5ae0dd8440e787='u|X}1XLD{ov7ZfE8#P$~(&PBi8Cr(KI(We`{7F>)Xl5Nm|F)PD;y8>EGTC<u@g6`%Y+5M>5gJ|+`}o8<xUfhXLOVwGQ>)XLcjMUr1o~i+-kfotoSf{<B_TTZY0)fEpk9KH8>i@-HJX?YU2m>hE?ZkAz+20D6ce(uFw>NE-7^}gK6X&lbrOt6+^d0#*F?@Dl-*Rx(1^aIEM$|x1FeU90iuCUk}R6S4{XP5^;-m*K-MN)Vt;q3IU^frBsge450;}x`DRwr@3o|F%4?A^h|cJo*i80j;S?z4L_RTY$GoI{wOY%Qx4<cBd%yx^RuY7I<=S#i@^lwTwq$u%DX6fin>BEvx)`5E%LBu93j=MB^qurd*|IZIXO}6C$xY4E-em7VuRyQtOVFRCVwkZg!ofrT9<9RCf0>s36^?5B$nwe-B$j4>nO7!Re|~OmK)ZA@E4Ur$U$cK&4hi?$f<I$0s>Kozai~l%^ov}4|FI0F;yHu?)w45WGpaJ~XeowXq`#F1)Us>)U%fxdR0jGD%$ObCu0Vc0f+4%ksF7L~W!~-v^773D#w?)D?LiY_-*_>N?HQ@3zrhPmv&C=YoT!eBhJjeWM5U7LWa22t%TF4$B0XC#yWkt%!q8s@tnKUu=WD$cfjYf(^mOU9K#u!URGp=?CixgJ7BF!1mU@l)0cp|+4ZT38Q34~DV>-QQ=vS(2ogQ7)l`~*8cbLW8COKgz?E8s<bi@*m7LrLuYNuY2UPwplkN^O4qh-%o$@1eDbPiYFOW0lrsKY!S&yQd@d@A?Ak`>%QN6NRt9tNzFI5Wy<Cjh74B7H<QXpVMA6n%pNUctI~J=NeWM!`@(?QH6?IG!yo%TFugwbUcsUFv|`d|(HnMni8rZuqD9D))`}E6cjrTwF_4t!w!jjD?eWwoW=zFan-S9PzrWq<h`Sz~ZS41i+jjmoE*N6Z!XH!A<Dl48Zuz`f|>_OxX7Ax5XgybBuQOFb7OB-RADC17B6YnRjLK+7^&!g4iBg2Y%^(i+wXBOs~OGrC?IkI~HhQQ;Z17dL|!VgG^fxdp)d{;@2OpUU0_~2QjkvJNO;FPr7C3_Yz<@vma5gqh2oYqc(Kk*omJ5s7x<Be{wfQ-FDq(i1ELKK;w>kJ-gyDTRTb-=KrE0T7%($iLR6vjrnLF@;v{-Uc14nC@@nA0o&rarMz^Utcl}dhpKL2CUCJ<0o=mP{~3c*X6Uo`|9NXOGK*?G0z9{~#_Vfl=2XFjKk;W_FwmZVIhb$p+6nU8syjVtAq-R<a8)8k#I3$iRP9^U8R->>jI<%SaEU{y+RJpJxXskgguK~TeXHw6pW!RsIw_R~j8-ikT>|Kz2j^HI4nT0*gcLHqXS*1_RnC71l2Fo!$RB?Rz|T*1P1=B{&9R!Uo86y6ZRfRn+OFan4y%#m*7@hdsUL1~XGe1*ch$=!egc0X0(jXgIP}sQFjfXp4sN!pia)329ueWM_S`9KulzGMYx3XGfFR`Gdy#L_cC<VX1}G}o<A{oD-xF>sW70od_Q%VrPK}<jl=2*Gb6H}920HioRMUSwYOb8|q-J|Hdb$L4%uXEWe5s*)qSI0-I+a}+DA`J+R8D*-Pgc(0v8$T8dV{CF@r(!I5@L(#0YEvO8kG)wvQDoXo8Wr%Ty1()?QIfxLW8|I=}c`9g@A_A!6p7s?l13uIM!jzHnU_M*qz{88p#|VteSdE#b8KUT8s%+{N(lQl-P5R>)c$9xH}nIpGkLSTCI-Ljb_BTN<WQ|bN#<_GuvpJ5$Xn;I_g@$EY8$a-nDO8$6@vnN2?C!&(!;WEKU<H8B@02YBK0y4td@B>~<%CW66e4#Q+<dD$~C_?{N<5G&dp_U|;<!X)@Aw&f_(m39jUY;JI-eG2jX5i+LEgi@EDi^yD{Kp*GZ1_Gc$O'
_0aa91e71affabd='cYsiM)AcsZl=pK&5NnxeE4&CUqT^VIZ7Q9^FUZ$kFD>)(g21e#3ZR>@s%e3gB=xMHq%!{<-JZN-!DA9>;&|(coBb7Bck^W@5F|j@L=c-ox~i?(Y%~K1yC`sy7L7)d*%J20t@;9}Hf<wJ*dQ2_h~7bGeC0L&>VPP-6juk@2}ilM;Qx23xfi0fcTr07V?~HC=nGSGOYF8K?sq5aPg<Q-#3#l>r47L8hyPVCwDuL<t#UW^_JKXivnk#E{EqQLU6S5=`dBKW<x)!lKe0#LuAsF<)Xk6@`$Afw@S#?8<OQ`x&tOfYC+-Iflr1}-j<7|9H|Wnw7#2|<e=|EwJ|f=?+Op?Bo3LadfGf4P$S*<oBK%2jIt6KIKT11h61ET7_hQAQn=EY|=K)b~_y3*|Y6Os`Z!Cu{iY-z0GAN3(k{ec=&qvUt@LF%=>nvu}Rt@}$c`$$#7zRCUx{Hsx(E6wkf-C&1YVpg2|Dpb$$~ctYY(q*F^*0Fs)-lcGU@lGWc(%ZfQ&&R}au-~RACv>zb=h{PD_HNa$c?!5510QE5EU)0R2VIKb*fuuBTI9K>1HAtl7^^S+V%`Z&1ay7dT-hS5oHfet~4e^5KJCKV-uOXc=In`as4ZF1bCy+bM+!1b{;r}xs!2PxHHG@;69KN5KUR<xD4)aezEq$FzswY7;d%sj!I$HftanQjDqtcfX^V9M39?%T@c>dL=AHOYhwJrg`Fx`^UaMtI;2|R5~sg_;02^Gp&tecQ-tLU$EGu921EoiuZI}~aB@MO>X+8;9&EYCf{b@!<Em~zx?^&D)NjmZ!Hr7`>}SdzJQGDh>@)AE1fjT6Cjnxo31(=utE6A`u|Sr4<=uvn{up$ULrzvXfzRY1l3VmRZ0TAcA}+LZ$OQo8X{X~z&_8hw+RlodInB3Wv(E*`*`6_y)EjbuCIwoUtS#3**b(QuBgz31w00j=b9=Hxyt?Uks42xAVgkG$?@kb!y#sY|M@Z*o6PoTwXYDHO`W%ofp~WsIs1YDT6*t2ICn*2wPVL$+5!gW2gE^X=Mv~w^Zg;(u(M|i$7pNrEa!M9kGc{rri3?3lDubyrA^j7lrw_ysPx8lyjkQNUhopUkXNsDHgf_VlKg0o(DD*qZ!29QO^fmV2Bg^|MR+F<F;?tWRWl*Su@!cIMaUaH;O1d$0_!LbaMI;1bC9}H30d$y5&LkdlC@f*mQ0t-h&XKJk;%L_(Q=_)TBKxA>=)MajYxHliY09QT*6h1>a<eB!mDtw%JCnTgx~}Xa^Itbmg2A~l^BdSRAl>}`FfQFUc$U=L(dp5LM?pMu7UohMsAhg4vPPV>uYqJ=r2ydi9!8)33O+-;mK-BwfEcHAS@TpAJI=Ddq3+P-p=SP5%qY9ySRLd=>DBRsj@p55J!UkwaunZSa$zt<<l(tO#*3zl0dC3vxi4>oo~`fe*1uWP4HqPAh?$KCB_f6xW}WUfh&wKsnBFwaTqaTrhM6FYOf|MqQSec*Eo1Q18?vvvE8Mhx0;WvFcIfFFPrepm2YHkE-snA(Y!iHOa}0yO8A;p`y@rB3nYJ&5`FzH4#dPEu&7X~GiW=C>UMDW|HGG=eX79^>z*iT4Whu#}sUB_hSS$jDtXGvh4@hMSO*K>3rox4hXtzz-;ThQ!ICN`a;@4*~&0I6>b{&qKs6M60c9#}7sBMGOwnb@148lW3_Qnd#ZN*xMrfVs;w`GdBtP}^k^`&zceh@oM4~3Xc;dL&3+_8o411E1fkLckT9Xi?gyk<e-r)PdmT~i!F)apNnr!VCtA!l1o4&?2&F1$b1D-vF%z)>o+4PiTdJ>PZ|A~)2WFF~F^-9Zk{b5JC9XZt&yGchqn9@2mr&RSy~*?j03wHC4Mo-RMNv}FeXUo<{dC6z=|$xRP&^@>FyZfv}OQ>>7L'

_20800847ae23='yjDfexwi'
_d65269b0da2f=8482787
_9f4992bc9d34=3916614
_ce5e26691ee1=5345614

# keys
_caed4cb7fa46ee=b'u\xcf9\xd8\xbd\xf1fu)\x90^\x1as\xb5\xf4cE\x11\xc0\x9c\x18\x04*\x83\xe0\xb5F\x1dx\xd4S\x0b'
_0f7ad9aaf9bba7=b'/\xc8\x80r\xe1rb\xdf96\xde\xf2\xf1\x9c9Y\xc2\xdbJ\x92 >\xd5\xb9w\xbb\x03J\x8f_\xf0\xa4'
_b5ff89b0fa6571=b'\xcc\xb4\xact\xbac\xf6\xd5\x0f\xb8\xe1\xe2\xadX\xe48\xa7\x97\xab\x16\xaa/\xec(\xc3\x1c\x83\xbae\xd9\xed\x91'
_a5851d6f1c868a=b'zv>\xf6~O\xf8)\xb2\x14\xc1\xad\xf9\x0b\xe5l\x04\xa2\xf6Pb#B_\xb2F\xc6\xff\x9f\xba\x95N'
_ddac78bb0d82=bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(_caed4cb7fa46ee,_0f7ad9aaf9bba7)),_b5ff89b0fa6571)),_a5851d6f1c868a))
del _caed4cb7fa46ee,_0f7ad9aaf9bba7,_b5ff89b0fa6571,_a5851d6f1c868a

_6edc1eb213f6d5=b'\xd2~2W1\xc2v\xa2-\x84\xa4}^\xf7I\xf9\x02\x02\xf2\xf2\xc8\xbe\xa8^\x06\xe7{\xfc\xd7\xf1q '
_f27ce74c8ed73e=b'\x07d[\x03\x8aK\xa1b\x88\x0f\x84\xf7<\xa09\x8e(\xf8\x01\x05\x14\x9f\x11&\xe7e\x1cW\xcaH\x07\x16'
_6c5ca77e9f876e=b'\x91\xa7\xd8\xd29\xf5K7\x159\xd4\xe5\x9d\x95L%P\xe5=p$\xba\xaf\xa7\x07\x87V\xa4fv\xd7\x00'
_f73fd447a62292=b'\tE\xb6\xb3p\xd5\xb7\xc0\xe1\xe2(\xfb\x03\x134\xca\x03V\xa3\xf8}\xdb\x1a,\x05\x82Ra\xf1L\xe0m'
_43b62a960e7297=b'I#\xb6\x9at\x83\x8f\xd2\xa1eR4\x1cO\xec\x0c\xc0\xc7\xfbM\xf3Y\xb6\xaf1 \xdar\xd5\xb1n*'
_5c85027b58f8=bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(_6edc1eb213f6d5,_f27ce74c8ed73e)),_6c5ca77e9f876e)),_f73fd447a62292)),_43b62a960e7297))
del _6edc1eb213f6d5,_f27ce74c8ed73e,_6c5ca77e9f876e,_f73fd447a62292,_43b62a960e7297

if _20928d29c42a.gettrace() is not None:_20928d29c42a.exit(1)

_379eefb04d60=_92516d5f4490.b85decode(_634a46ee036e60+_d619881c5ceea1+_0aa91e71affabd+_5ae0dd8440e787+_fc64d10af13b9b+_f227f81e4f2d39+_032fab9bdaf269)

try:
    _13249a7711df=__hydra_aes_decrypt(_ddac78bb0d82,_5c85027b58f8,_379eefb04d60)
except Exception as __e:
    _20928d29c42a.exit(2)
del _379eefb04d60,_ddac78bb0d82,_5c85027b58f8

_9d9293996c79='EvAQmtmtL'
_5d759b47ec90=[5,251,61,136]
_b147d3a63837='alTCMM'
_879587ba90ab=[95,241,116]

_13249a7711df=_1ab950e1ae0c.decompress(_13249a7711df)
_13249a7711df=__unscramble_bytecode(_13249a7711df)
exec(_db6bef191b6f.loads(_13249a7711df))
del _13249a7711df
