# HYDRA
#! 674e5fa4f081a711071d70050e97ae0eb903c489ba98569a7ecf9acce2e8f291


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
    
    result=bytearray()
    for byte in b:
        byte=((byte>>(3))|(byte<<(8-3)))&0xFF
        byte^=165
        result.append(byte)
    return bytes(result)


_727d2f68f080=192493
_63ceae3d7c6e=[144,60,229,216]
_7aa1e36a9a66=3745975
_fe84248164ac=[16,182,3,146]
_c3fbf008d226=[168,143,254]
_4dcfc8ddb721='hVrMhYfglCEhtkF'

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

_3b9039414573=__import__('hashlib')
_fa19cd50d23b=__import__('hmac')
_e1fdca8fb2f0=__import__('zlib')
_b9c03e92dbf2=__import__('marshal')
_1835e151e547=__import__('base64')
_14ff0d783faf=__import__('sys')

_95362eb2a579=lambda: None
_da41b78206e0=lambda: None
_ffb390ad869d='GqUcptcjBzPTlvEM'
_be88e38932ce=7034794
_bf1055451ae6=[26,114,246,201,140]

if 592824582388567036 == 592824582388567037:
    _f022a53167f1 = 'BuqaCuCSLDYppjjLdeJxWlLu'
    del _f022a53167f1
if False:
    _b47df626d422 = [64, 239, 38, 81, 116, 62, 25, 10]
    del _b47df626d422

_13e06b3037f094='MYwUZI&MSerB-K|T!Xt~eCy8Men~R@jEim^ZZo-`PNk;afjef*AV<eZxBJgrAsLFnxM*@;rdF7kpv}U2Ow?}Ar?WIOpJ)v)PN4+<_*-n4UbnxA?a21Wty6E|;gV(>NQ7b)H<=X>+cYG<y%}XgsH3h1-wK;59qdFetG*-MS)BSJo6}rO%aS^4%7!#R9<A+OHsNHDI@!f>#bz|LgIjVk98CZ;l;d|kBNxmc7ZC;_M5Fos4qTLG^lhMTBj$-Vl3F2;vGRWn590|s?MQB~z0@eiPvkW}Kv~aKA}jCKd`LdD(}!_WforI*JfjXhk4BBfSA7_kImT-km^KM^$7#jQLq00B$-%gFpa2?L3_brR9!QZq&c#wKh(W1X*+}JzVn9Cr3hdZ5LQ!c={1YPIT3=Sc2cdf?GsbLg-F;bT2RC>f)rn@rYVe-SS)2WN{%h0mXP#nsbrWVf;?N8i2ns5Cd#}&cRU+;peQ=xUZ|;sp$>{pQBT0b?<c)!((I5n?V1JZ>KYr#5%g|9O&a?g5W$0RbR^}%6`>HUa>E+5J@Jz~j!Y%oRj}~<8#PaU33Ifyv!`R`!)fTSQ7B3~^utj5nY66Nz{0Lv6h|)jL?YikWWUyv(oZ_x7LZR^L;dfjfR1Ppo@Pb{E=V#4xLF<sJW`UFakG$4@8alH&%diur(bmzZB?1vRqs0c5JgNZOnJ2eQqA7$cWyR23wBD*GlPZ*1uj(_Q@X;FAQ#{3B0EX?|bIO?=?CZlNhTg(gDb#zSTDm=WNjWJK)?FNUY>Tsn5wP?;u3Q{rQ<Qp#`X=El?-ie?bS1rF<%8Mn+hC@6$2<U{at2~w%b!W-w$F`~8Jrz$+LxSFi`p9YiGc{<qJlvO($|4NJ1YUd3SA2)snbb+sbTOzpflMU6rTlNJl6XR(W{(1gDYuza9CIPSf`TVc1aJ+12bJ9WDlU2FyuwXD-+zZ92Rz&@!P5+>@keY@ZNo;G7HES(Mb<r<|t{`pi>V#u(>vv&mpO#Jl~q!G<c#QwmrFbDgUNaPw#l$Lu>xTnBPXB_9U;o3$_LNp|&EDTG1($l(;+NW4O-F#|Fj`iof#p83V#N62;2((%26a>JqF)JGD{3DZ=RHM?Rnu0JRpQ<uThuoqhUsCUsgk&060>mZIPW(_W<fpweiIc15}eITA?x%D@4U<^IuGz@VV>$5(<G#SP#m%zJ>-xexDGZ8cGmuj_rIH3K#x$SWI3|IjqzUo?~v%V}^%-!*0fJy^#$rPPttvg!N3O;3f@EJ!G_kpcaCYxi)VuocT#P`5@&c+&QKF53C1Irkf7buUYIfYnEoDz2XJo}i?T>vAEqtl}MkySE7%6BEQige6DTK}SCqT0cGhvZfK4E`{+`ZGwL5j3wA9$&rYt_v%T&pVhghLys7b@SIOP89Sr3Am;K6F;qj%vGIUEX%gZEK*sh-na8Jrp~a62Gd%ZVW|r{*^S6St6;y=)XxWo;8XEKr8j&cZs&o$fK&}fLeJhQ)oreCBREV{@*e&=RsV*x}x*@t*`rN4SSytReLV-NSl|<56gD=j_03)R|<?eG2V=TahrC&@!X{T>!?W8?`c~`hwGs?1NySkI>$Bg#>ac)K#HSce7;j&j1`74Ww1yox)@0~eYHV1>-KyTplv8C0r9WptrO#2O%Q-93gqel}mu)Okf0$g4#>XsUr_=4jkI%`+oO!x;Py<`9~Mc2W1T0B&ey+QZj+~TNX{~&38LKDMKV`^G=_&x2;R}^JMvm(46Z3wzek+gyYmTGH+(2sBzzTBTr`ANzBcl?H@4bin{?QSVBrk*|46O3`Gneq8t#S7Na!hmG!gK}hk0t>BO*z`NVH@*z?eZs<w7k<Y;HyAR7m0izPaOS@vjXY~|4M{c61#c)Cb}W33TVmb4L&(?@X*-{4&MO;AN;&6|;dhM5O3#|-l(5VV@e*-nClpn+xqE=o-&%(Ild9hCx8*?7tQ>+#_^|#iGYX<Hp${c>;B;grZ+Ao8{0cJHd7!#scs28MS<_rgRt1qxXN4n22Q6kYnpzg-^@tyN{8@Fux!&JQLJm=a)+h-?3-HDhj}vLHekItQc4zHJ{>R7f6}2A{r^4f;ErtzNgv=8;wn_C|B@^mZF4Ra<GRQk4J(TSW_ASt|^v?Q7iyN5ahM-&EOz6F@VkYgf&zG&8D1gsv6t_U3qE<We-byHE$$7iI(c5Ilnw}u421t}3<Cj<xx9tQ%D@YuC`tHbIH251(eE'
if False:
    _226e30f05207 = [245, 154, 248, 48, 121, 4, 108, 139]
    del _226e30f05207
_844999acbe62f9='Uo<kTZzD6wZEdu@AoRg@e!^Tqi+3Rk`Yw8kEl(rZRq_IsjK-BwK(#gNKX)a~O%cO3E&u`K!xX^c6ONQRXZ!*v|<G!fJ2E;%G&Z=3?215(}ou{}B~|el{7n=9EJT22*Zg=&{pA=CNdL2An4OQ!&WX^dLr;G=)d+c6%<c>!DCZajXWi##V|mn#lJPeS6T8LXtmfrQcC?<JHkhC^;cQKe<CeHZyu3k+$d(ET^v8f+^Sy>ekLkOtJFsL2;hM-;e?=oo;1-d@y@rXhhp-fQQF!F0xnXqz`j^{l(5%_3mO`!0>w+{}_JS5qAWW0lk_eoY0=WGH2jOFCCu}XW*;bOU<5K6!5CUFMI<I^4*+b!sHf#U?5v%m5h7W!}z)(u*VedynVsj?(xx8Qw~B<9t4Wa-M_@dv%|KcHC=f`koYn8Uyfxs+OSIGV|K*U7GO;mwv(kl?^@yP#fbzttg>hMS@C^4Y4>!p<40^_c&KuMMpO)p+~A{YqpCAxp%&JzrGC@M0xv!}KzhYNO5PFZpT%UP)2=u%OsE`%oqFui)Dq`<%etr58+EM1=w1GOOOxO;3(jGvC8H=Q#VpE1ZNG0@hp!V_C1SSHXD+^K#e8oatzd5kv$xL+og`{<pYfeamUyy!-w?j4Wx#LL(i{VH({2k4tWXfY-IL5G1*Q?>?|lD$0kaZd(2BtIFGnS`mG6I-4agE0v2UCsL_UduI}yU{fvv{0fkNF_w<XIjXA}}Bo`n=MVS$=^rM_P8y*JKd0|+dy1%B^>(i|2nLRj11;ZG9-<4Czdg0>)JMUE*_VTR<~)Q`<VmGU`TOGa3vP?8NP0oXKgsoJ-T;3pp_d@t$ZcC1>0QuFJw1_I97QF`g)2Ys88BUjO>lyVkavezAZ#0spWgF{}_K?2&a-6rzRX7Pm*A?ca??c+m6JG^)G+Y0wYSYlfH!D;g-X(+ZA6e`13Fl3`Rpl=`uhb2ykt&|QYUWpw$unQuJi`d0~_H8!t*#_Yc>Httx4YLYF$O-C7tPpf3O-@RE0P-l@>>aux?>mFDb4^WuZ&!k403DdDiIu>QzCJisJz(E#oEU=O56473_wxQPkw~cRL`F+d+#*$CX*j^5K`Z}hOP}g)4<oS$Zd_MJ-nMMaB8qx_Pwo%H1D-{$r6Y+FpnNrPNfEl>^YZ~!C!@f^b2P8nQxV$g)GId=3(-d8*%W$utV0U8rGCDy37Y2_)jr*)%jBDdu}mR7?>?!Ne1vyc)+*}icb{4j-mN(#?}+k(gsXw80pJ&4H3cK3bds9*PifT2Zm)iNLZqac2!5n>2}J9K9%@DKhUkj6t9>bMgSAS#O?zK{FSQ*=JQUzXFpSD>WIbL?NZAVcS#0Ar)TwO#2ID>STzz9x>wC&pFm@}=n?c;@C3lsWc7*UIIESrS)sWwa>GoQK1W+R#ZlFNNMpklBe^ny=_IFkAU`)|}3GH$;JMG?F@sV;UP^I2D7|-^KqEHW$0!3p*^Lsp}le?-|9P*)ldG^u!!zvhJoci>^uSU}(EoQuS3Z`5`Nyx#QU8r=$UJTl;)`zvi-bh?bX3$M^&8wk<HM+`hHmtQb@7r0$+_xiSg~P2o!v%h-{C574P4`GEp>Xn^7n!fIY=;)jL*8=Luw)`%2$`-BDrucbe0fus9RSH5^VlVo%Kh?u+3h5SC-icHG2ZyC5Tvdr7s_laEduh`1>0(HqckRjFbld&tv9Q9LLx|TWdt9*e#71DATYs$!`P|aebk^b6Zv@e`z4Ja?P3%z1Po~ci>%WwUa`{WO7NA6e31J0-S7jLT=CQxo(5SicF%0&MO41H>M9oo4_8zeT|6M5JV}?7Frcz$&dWb|ZB3*B(=b_RAx=_f*Zdcz?w-vmd7-=EZ*jTB@_J4dPvqO1O{yPboU8&Lz%lcUq1q(Z`<K)1Uk$vF4F@C42y<|N9zp^Uo@8`2DYV?GpWdhi^SD#xQK%KvZzN{JrTurZvr5VlsF)_GQ|7b>S5b$>c}lM`&a2yuL6*gHT%NFmQR_wpCH-idP<F^*dxxRqbL1Ss&64XBFX)DdDKP(or=_=8qW7ZZviIC~smdEB9JjOkd)bIGb9~Qk4J7d3uw!pAyD*#{!2FlMincP=_iVTakFyjU;qga`rDpTQVhejsk=>DqpeNf&;OR-i$u$7Vy)z$YQh$l$wqVF|>?N96tWNyV!whvxlt-+%5GfhwBh{dh?m$zH`8_yShM{`Gt;$2BE%rmAXpB<'
while 952960094164799980 < 0:
    break
_f1ea708361630f='xS`&7jJsoTY`P&tX{0iFo{ts>>mA;H9wQcaXTqUJUMcgss0psd&N?d8%kKd+cFW%cmNp~oK!Mu_?A$iU(-JMJ*6<!xuX!m!@j`l@c`d@!J8|C@2)sf2eWQFiX<;Y$8J_;&r^p9sV>ZnKpesmy(Twn#-6X-4o@mLq+rT||M*)5Kx1y!fQMPdz(>g*V=y&$aUs<`Y8D{5a)V=|%R);Xt8r(tBzuGn6Q8)z#{NI78{gs+8dmY-#E$5M&dNz1W@vq_ds4XwD3}+I-vI7u!<&IV{+akvndg>+Uet;EnmxuC~lcqdkEa+ZDFjGjP%HR8Iv-TGJo^Tgo+~Oh3Pij%j)$4?kp~@4CWfX9Qf61_{yhO+J%Qt^^AS3lA-PRcf#%V*(hoh6XHnNS$D1xSJT*NAJ5=f`c!=;bi$itjDLGz&(<MC|wa0Y6|Qp5B<*AZum%^`rYPO4jem*K*NkFaF0YoREb;Mwtqgh{3Kj#WR3*h_|nrt5nr<A3D9%>PF#8u(bj-^6{kS?}|G`-Jp%DCKc(M#yWz7AU0ERbVvQLR5|xWw>8;UA8Mh-M*{46>Y}Op?$ioH&fOFvT*a93kBx76;oJOhb`Fbm=XB}O|2w$>##4N`V7rE^ac788<5#23tFTTVX@`6j$d|PGIkd=T&gqOl3KJ0-AwVH!^s1DG%PRy0ao&UFy8mNIQ7V&{bOz);($eZYf|Lt^*B17A|_Cm*j6Q-ZQgQ(BKINrS@HukrsneX3L}~2LOfL%lE`fGCk&b~fYV~gb4@z7*1(^&i_k8?b#gas>_nHAl#FTepp`;hJ3`;t>h6@f;+^Ez&k<AD$P-gK$JAi%6z%r)p3@F<1~;@)0Stkqg2vA8>X)6wAseeUBk5^fN9UHjs-0RaMz+CHn_{bgVlOhw?HZ95MDe@UTu>rmR}S<o1Fzge0jyj4Bs{KHR!TQi?fRE8Q(w>@QqtqfwQ4w4ySRXCXQ{~uZtm71q%fe$W@bTbL=_GO!qaS1F_0`4YnK)KXpz6LZm98{`tGmC86G>?=COy-<XKd(DqxS{Up?*2ERt)ycH-I@2DAfBBOslrD-L&rNcr!<qipdwrVcET1W`2I_`jC1dBJ=@UGoD%l>2y?WQn#cNiMGrEuyu4OzrtwBAIRbv%wP~Tmr~3fkZhm&x^>*)T*_Nax%hu{RNW%p&S4Ub5Dpv#D~oXA(_qp17`&WsY7H4RYb(K3w0*=*`j>#jB9=nm%#PjD#t3YW9AD~l9`H<u{V6}hWw1;n0NH*!9i)R)Xb)(n+qy(8Bw_LSY{DrwsqoX{;!o8sz`TczX>SLxSN_N3;cbj9?J9F_q0mW@<Z|E^ZhA!U*%j3)TS{Wd!idG8_#(J_-s>+k6Vf&0I6Qd`B$0T7ouDt3A_%9rvHg5B%+@`XZvdr83s&WO#gi=N2^P10f<rz%@x-4@BF{)D6#xgu^1#rqSO{u!~*w?$*e-v$2)8Xu1W&<u?|0>b)f3Hq>kO->qap{`4cAjYykgZMCAM5iB~Xh1tEQ>J&TU;@1VuGzBI?m;83<VqWE?h1(ZbSCy9Tdsqg`UYdmfV*Qysbl0C#r^*3>>jL6Zgo3Y6;p1@mr@v%JT>F-?#4)|)Ys71z(;GnTk`2JJ@x`T2It6Nf1zszZCiwyM(hDh1Y<U((?&!8VWw~Zw<2`RD2!i+Z?zh}&xQHObPY&aIF)Q5O9ObCi9?+^ec`EsEWk-&A4Tzu=NHN7fM`vTjthC6sIRL{5;WaU#i&Ts3P!mpG_!m&w$^Ar<G;YOJDTv1ItvfsB8Bc=K@3nE_ULL=|*{@rLPv9Ltl_ebC>xU2}vn(lK#p8qO)!9{umrB`~iSwi<#rqJ`78vJ5H(tAzWm(S55s!LQmhvGxl%}^tqEpn(m@CJM`aT<LR$GBa!L=*A??E?!MrAh)HZ%UNL!))2sMXSM>(^1%>D*3C7%Zb!$K}vwGmS&2;=OlP-<Y5eUY>f67Gb`j9BG%{4yP;`5%}fn9ufI%%LG;H80i<dwo3^i&cxehHfjk5bLPha*c5POD#pe8`+-F$;h{~c8HbGE2|3r;^G_l%#aq;m!<2s~?6gN9EIs&QTH!fKak>z4Dbic)C!vCJJ)nD;9x@`E$LC!H6YvBu=vm?eEkid1tNBIS7WuSUW#=0kO>qNd)2Gfm=Ub(HkM$64dp{4^4KC;rFgi&7y6xh5lSz4L~gB&ZS&%6vsE}~hb7OM5aEWTTINr+Gdiy'
while 767265637562242871 < 0:
    break
_fd762823749c48='D}TN-(x6W)BUvIS=GE298LVEWfM4JqPVr{HqhVhyv@8viQ!JZ-9gjx?v1bN(WyT=MUk7`9iXx!`GAypJ`7YVc_f>++=YBaxnwsKawK`s)~;d7-9~xsx5!wN=N9@T2i=Of1dQL_sbMAeT(AYjRC3KEL3`;wNq5!Y7gH^OB=e2|L<65V^x4;po`z^D74*|3J<iXOv>k^`HR$8U6gmZ)tm5xI4MA)6cTJy8R&gB5bC|gi23f)KSzu^Y48tcMxG(XCtf6=-Gow-1wrDZa@sjz3K4WYV)>2C`j-f5nGA8?yWG$P&gx2}giJ@2}G6X|J-ZsSo$u!FukcTgnBi9z%&Guux1(*5@XO|k2aI6oM%c^8A;zZfMy$PGMRD&q(nDIEBNkX<;1_vppFFP?%cd?Y6=6u=XgiTF)A85D=vdBPl`wS+xk!-<1&~&f#0rdpYsqevDc|0k~MdRU*?_f=j)`KPcM@K)Su_<-Lb0#v|ra3mTp~`iv%`}^!3@=eS!Y$7mlj*jJ4X&vJoB;C^tzUZG5;M?mp9LTl74=3a7VE1~78(4d9+%JADfPGW^I8+-<}ijA)+AQ>;Owzdz>L^?lM{lXd^*Ow!OcV7n#G#M=uD)hXsQCxRwAk?4&&+0;Vegz1fnw??$nMUjuv<bxN!!s|2D!e@la;{V!`FIs?>kZYMIFGJm(HnO52x}PHv-@c2|$O)Rstd`d|nt4fR+o_)LG^ZSB6eII@Ppy^i&s5<zygt0citU<pg%^$(i@akoj*=A(7ne++@avPQubbg(2<dx|GjU<`BQ80tRQB#@_k(fHpyVl!zVVK!w<OwI?jjV#buC`>3*vjep5GYO&l6*550K0)zMSEt!VxqnyK(V`W`dyI9@sBD&+xDR-Rv^E`i`ow6qepWa^b%vi;Ew@qm_P}#WM`g9|UL$7>jGp80nvbW=wukQ2-zE4l@POrX{|iEJH)B8a8O}UO)TPx<M6HdVkbKR*MttF>hV5}n2Y)=ksA=^@(fm*?N>cVg1<MK0`shuu)SmRYG;HU!p8llF<M*CdI^Axna6yBBmS}(-J5+jy^Eby@gK(V-9gtzKXY1d1V6emyE8lt4faMs<r@}&jL!ndonL7nff_<YKw=KKcJp^7wMFcZ0(fSQQO(*}52z55+fvHv)K$m$}x{=BqeU)j6y80=ul{V&nauekxk;CjJJ;>+lE0O0qesJNmXQeAV)3I=M*+=(*>($avx2DKH>X-3~ViI4JOvy2u<GUD~5c9Y0M+xm*A3y-{wGsIh#?dkR$XG8?xpqAOFHY~2oYFtXjl?TjUGJ6KzhM4bX)jGgp-|f4KmPvz4XL&_l(;<LuJ*EnMLpZC(!@6F4S{0ZA!Sa^GTAbV{NNA08p1W`S}+)HGH0f{3n7MLNrsF*eO%o@_E?_vsIFwhFSgH^&<e$P-R)xZQ?ab=!Zo9E-6(tWh?t>}U^ABfKZ}+IYtp)x($-UocLy9}U-e+&ZNtHN*OkPTr4ozJhAlO^N_C>FNqDN3KlMWnT$xjO3QXDEbz^<zuRv(kXH|WGJN5%-K8ZjTc>zhd?~>#oGZ=Ji`=dLLCWV<T!UT7f98YM6Pa>@~I!>D$`}!3TgkuPy2H0i`X3VJ7HR29&pEd95<N?EKI1h0{6zat6fT6B+Aj;*rZdPKOfeGIe##E7~K!cWR1PIb$ZGF}JSD7Q$JQJuS-&9kETdDBh&6*3FPa4+=!gYofbx>bW@b0g!Jfec;`Oz~8<I6#*y&GB%VTix`m9F5tvo0Wb&qj~>svpd{^rK0KF2w@ofhV*q?W`^L+oPEbgpH|cA~hi*V-;N=0WS7^{VSc(?thla2SOvcvAyl<E8-dg`)nOoSP9=MBfY`g^IaA<4ZoV_oQmnuQI!u*rwq@fHy00Y81*!4u(qu!i{njXENt?0mI`Yn!b~u?FWJoKl(9R-dj4>q7b|cBNx(50VS7$K@*VV}pFKQE-`QcacOtdbB1KIsDkEL2(Q-5WzP`D3UBstIuMOKv>$-7`jpvF(X2k46C9a=tVu6HN?-4AG>ZV@;5OGz~Yyk|!*A$KeFyVEG<#6X?0&ZM4o|=@@#U<MlI^{b?___*U>W;#x;JW&>Mrr>|v1){125h@D@luKG8Y}%yp{%^(H4Z>ld;#66mO58n+ye~;aI&n!$0hF(z-Tl}nZO^mo&x(pEFsI@$aVn6?2Lj!zfvL!pjbDHM{%*@u@leZ&u=K|TS?W&$G='
_419504718e5eae='{8xPpm<fX`x6ipB4vu!MaIqolM1p(ZQZy3`=bk(1jdhz_{U8WSFa~R7klS0X;trMoY$k7?UOXM=z8_p5E<Y*b-j8OPSU3F%gwt*;p;oItc_$j1c%n3ppvIjU%d>3b_;R}>Q8LLjBXOKqxSDC@9%WB0#P*s`TM>(wgxP5=+w@W>X-RmhZNcEQW#Tv@DcZd>DMbpV7S4bVOx(+RnS8sS+6A|+aDlyRx@?J}WeSnH$(H?hFlD%2CSoLgNmgC^Y)@D0JwAl!h@WR^O2{u+qP|PRJoV1m!&P|-JvGu003B##*zLo5`_2f%=4Pp6cNFhTKYCg!|k*x|$p!Is|v&rSg$N@!QK}ppeg@R6q>utp)7&?AXQ0PuwTKBNumdlm4bLYvj4@P;eI&QzG7*&nL5(B$cB@R%`sjvNHK7_P=o9x5s3CanpMy2m-%gq5;ZR0agMuwj~Cg`V!?O4z*`FH-HpR%*jNe{kLR=II7#dIOo-p{X<{lmqi-D!>3G8L78oDA3vAA0ovheL_2YOTXe{7j^0BQEwB790G|PjW2x@2&(l64Qm$CX3GOY`up{!}7fjj|ZDItw*aJ8O(LX?NmZcyai+coMXPMBp+fsr{deWvw{~R97fGDIbZ5oqn3!DPeUBw*8p@)o*LcXDD299PNNWD(CQo!hZGco5eIt#%U4zshV5nz>-@gbtD?|x=`NwMu98V#U5Xw4aXU;vLARSUGlUGRl7>T{$z_myX}%s#Ktx!_C^4<(KQrw@e%F)8|3^V@1dmE-7CHJ5d;3q~$WptoND66jV0x%hM{&2@z3Jsey5mjVv2R5atQH?hvss=j1HZZB-f7%!UYqqNeM9dN4N@WJe}N3I<1UY=BmUAzUNE9+v%;?-b1JTb%i1}v%Xf9bi${lMOV~|njfT<S@XV7`6abQpsA*Q4;b3#e$tr!Ws@*VjA<qW4!#_;arz;_r<F|c5okHoORY1iPa^T=fP@B)}Y;65~@(J6uHyEWD9#@j0c^+4OA#h3)O5a(Z*~wu6r0(iSVGH?>7f9$9X#hH&=Hso2GAHi6!Ai-&ZI!c~SoI)O-ZJu<uLTwvZJLq58N<*5FI=q75_jJAD(%IDk*+!|DG8BM9rcjM!_@JUOv>V%YNhobJo%0t+jJ_PYE1qN2?{g9+wp@>VYQueY9OAZ%*(49o)aa8r>jJd*bsEuj+(?kj*dllkJ7Q1<erRi^mn`?iT`zR=fJOx!MVC!Dw1%=|DLX7JoJ4NW~YIJfO<KVwnR)I+p_iaK*nsJ!aZ$%MPXyeV(2U{u8EEiuO`m?pib>5%`ERK+8+vd^rAcB3Y)Qd6m=hT1v4D(2r;BC&L5DPE|mAT_Z1c2DuH5HhfgjN!QuYBgs3XAhtq29NVqDfTn~-cra#PR7b28%ISv?{lQd48uKL?jB!<yvz^t{|Bt0Rd?L3CDM@|rE`CvqZ%h2@gcdZPTcK(7SfHEerZk%~1{JWECSg5<R(lMN*(25wjVkq_f>57yjZ!0Q+1KjjP>n%AnZi9?9CZ1}<C`V0vuooR@270<36diS+ir|Y958+!}>k<oN>0S}w#*MP`TISDm9&;l*#$Xh*p<nT0UE_Q}Iwq5yIP-(fLnubc$J?*2S@#*;j#_Ql^o2R9+x(0fK<b)FA|Z4G{?8r!*-CYX<V-Z?p3kFoq9h|<8;42vURv3S<gXutmrUZn2J*^+sf|f_{ZlYZ>7Rbz!MaMj<}37T2@X@S=}`WW-$%s&LF~_fM~*$9(NZN%QocUVoPoCJus4r@$QfOiUxz_JN8oA+D?lF}6vl4&AYFuast}))#HkQA_~evze}%DW^EgkKhEq1*TKeyO{@c`5K4jB}79}V9zy-HR_~@<)zl1oG$J7235Q^G!wZ6>sf^U<croA$Z$b6$<E=%TT=RLv*8OI|ngu)99Sx%!$*YW&lhS(g`kbB{*WHNhDY!N<j^q`N}6B~V9wqQJflnpR9?Bxefz>+k=Vz-93Wi5g9nN$N=u~RAPdA4GlfXR?SO3+s}y>HDIHXM#E($6po3CS`Cj(0Zx=Gjcw=Q>n(Oxwm0969klFrb#WU`s2p$w%Bv&Mt?Jjclf><!tV4tI)byQkh9D#6Q;rzO@I13FYtAsKXOM&)`@ifz<TLcJ};9JA3BQGn58e<&r#Nj@Dl}Dr7nLwpFO)i67#VlkF#2$Wh{hy{(kW&*%nNE89uiagAo(Qn#d^CQv*kwc!jk$+tcI>_9a;3'
while 417793881139717773 < 0:
    break
_4180327693d502='@Yp7}AKa$^o!M{iA;uZ%<ij0Dp^YcWh&-L$TFpzo!%&^By;4&-yo&vAY2K@nsl<m7lf(9nfXZn=1J8(c-^*xvNFp<U@|JLLL?J%Y{_k~6RwUGj&FoB~=zBo$*FbIx=+O|zTRCQIi8Csc}~{N`6Fu|%QD9+(fivYDCoHZ9TwCu!a+<mk5mo*xrlXtA9P>zdFQUuo+aCyo=eeeu%hH5}%S>c;&6-NBmG09j+-!O=)b2v)BS0#J%dvBWyDt_G=6V}yjOkNjpji*c&S1K`#0h6bxu84ke9eC)Ku19+t~;1U8JSA?V46cKzx!iYfc?%97E;`iT$=}}XEhr)WB`nG;F*VsrmW!QX$6Ce}JlGzr%s;HNSBw7a<lVs9c`W6P-NE3ckDm85POdNKl8K=ZVrQm>9HXz{U(qPxE=Pwy;_=*>DS&BXL>rrJmx63`#Z0FssWszC?%{TR@D~4cNIcfwaM6t4_Qu8NSL!)v#zJ7}r7JTMC?ciFU-Y-dL9Yc}ULPKaoeCWfV>UdV2u|FgM{vg%3qat~vOv^5=gNz{`%pXL2?YI+kCvTPHp{#_iPYCos*hiy{#qFURFC01XF(M9?lRq#pmte+^+(ro$T_-#J($-#746OiWGf1P}EwWSDlgW`?;_{)Yv%rhdv_+Vji;K`HVad1t48zA(fH+kM3z~HWRqXQW4cLCq$G%cWkxWC12nak<R1!DQFoUny)iYRC&VdDIeg>j%j?ydlCdhDmbQBDKWGM0#U+Pd!lU)eYHQ3%-Cg5&@)wKjkZxuXiNMuA-!~+f|u=>Js7_^p35kL8^>1vTrD#oD>P&0mUg=RMQx&#jXPVJq6_2{?5X1t{MRjmLtJtoD_dlU`JTD_OW#t~tYqRqA4jL}Z#(st<{GZ>U_)N&o(yF+?z=VmRth~im0dgC)r=(0ZGbhfK42_KPMgD)&uFQ$<$p<|S$zEBw6-E7y?b{d)jI%d2eB<Nx&LuJl~b?1h!BLbqTq8P#@kiQ|dpXDLR`c|m7@0EC}0m9Xv0qA<1hsfMG0!GCh3Sp!+b7QzmU!Oizk>UOTscTx8+|aM@IrQ3H0@it_l#$=8UWxCL*{rcWm3pQow|i_$L#_cyra6aSSRoR3BRyMc&Zdp5PQR{EPvP-1au{R_`=<@{PN<T|&fnfFq2exQSy9JauvYw?>j3#}3n1J3>c7c>0mUuG-D;b;UHto*Pm$e1gq~qaJ{17C!<Jd>hZm#XImxmaW^D28bGq81hu>Rf1s-=uN#%x$XupT^^yW+zg-*VMOu*B4YIyw9GFm2M<`C-1i<D;B4x*46dIeCm@#d#LMT;Q$!~0E#kY<H(tuSM3I;z-RHg*VfT?*#P`ew%hmE$}}$S`n+Gj_2XJnuTZwt@Ej4-T0lHSL4VP+SNwRjHZ+>AH4F?_nU;7Yi;Ku`aYieU+S_Ql@t~=C@lib433ex}K?N($`!ClOvH2hJvINfW10<>S@eKVKMUvS@Kv1qfJv3w+gDPz#0JtcThY$8i&?@Vj3bYR8Q4*X~Uq&w85LqmeyT{UTWG!nG0d&@T+o+3XbQ&_Tu)QeX^0$eksxwF)3)4nQ&E@Op*5r<z@4DXb`3}J^fD%D~b614nP@Dl&K1d)!*GB>RZ2d{dv5ok(XWibf|M&UMQ>sgFA7j29DE~V=d>jYOJmip0h!sD~&<o|5VpGJA(v-6h+pjU{!v;KO(^aJy8=S#)i5~KTHl}ES)=G0Xbks@oXR3cL%$siohA6PGbg%D6q6R!5ERxX+{h8q4yyQWQaD+1t+DEXon=sr@2s01qkX7&X^Diji?(3WUZn<-3>9QBX<;^y&$7)Ubqa=sVAWFnIZN}>figXRhJkQ0Vt$<ph^2|Y-$Vcq_zMa`dv%#`Z3?_CY{DyGv29<7JO6NjnIxTWQTM(LU1orT3L^#faH&vRrc`lK?wi@0Hd#YOp?7sr8eWD2Qn@WBa=fz{@wo(B6%kBLS})`kI(scbMy@dKe`~s>BY9jjRgw@Cwb+$Q@K=Ml3Ha>Jlzjgn*L&PUhxJ_b5iTHWtO|>PYy$r4*h^ZmDG{ETH?2$m!Mc9pFeVSG!JPwYsJ8BV_8FZR8_Vg68GmDz4G9q8j;mA1{|K+Fs8|P$~%ksEL)d0KSYh{H=*CU{yLFdK~17=aCjwm{@RNLq3xLr{+F&|uH32H3sS$0HUuvDsrF(v?H@ry*fNOfwvx4-1BVE%k`vd_rj45u**&K`F+MzH'

_98fd096a7348=lambda: None
_65a38a50e798=[20,150,220,227,12]
_a64baa0e69a2=94681
_e1186cb1f9ae=7811553

# keys
_7b723599dfa776=b'\xb8\\\xe9\x9e\x12n\xd8\xec\xb1\xb3\x98\xb6\xbc\xd0T\x88n\x96\xf3A\xae\xbf*\x9f\xb1\xfdSK\xdd$\x90\xad'
_208a91051be3f6=b'|\xd9\x9b\xb8}\x1c\x96F\x12\x05\xa1\xbe\xaa]O\xf6\xb0v\xc7\xb3\xdf\x15\xd6\xa9\\,v!T\x8b\xe9\x00'
_012ec9514da068=b'\xdb<\x9c1\x98J\x02\xa2\xbb\xc1Z\xfd8\xaaR\x19\xd6\xd2\xd3\xc5\x97\xffh<\xefn\xc2\xe01\x08\xdd\xa8'
_838d698dd690=bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(_7b723599dfa776,_208a91051be3f6)),_012ec9514da068))
del _7b723599dfa776,_208a91051be3f6,_012ec9514da068

_f4c6bd02fdacb4=b'\xa8b\xfc\x1e\x1d\x95Q\xf1\x12\xab\x0c*U\xe9\x86\xe3\xad\x10\xf1\xbe9\xe1\xc3\xbd\x80L\x88&\xfe\x9aT\xd2'
_cd77825c063807=b'W1\x97\xcdy\xc5r\xc6\xa2V.=\xccl\xcb\x98\x17e4kp\xcb\xf2\xe0\x9f\xbd8\n1\xf7\x1e\x1c'
_f5f35f4ec9daee=b'\x15\\n0\x17\xd3|\xcb\xb5\xdb\x1e\x9b\xe9\xaf\xa4\xc0b"o\nE\x8dOr\x89\xe3\xf7z\xb1T\xa8\xe2'
_c79f3404a4cf59=b'\xd7\xa3\x95JH\xe7\x97u\x83\xa5\xc6\xe2\xb7\x7f\xec\xe3\xa3\x1a\x8f\xf3\nb\x1f\x86\xf4a\xe1W"\xb6\x9b\xe4'
_78748c8e58ac=bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(_f4c6bd02fdacb4,_cd77825c063807)),_f5f35f4ec9daee)),_c79f3404a4cf59))
del _f4c6bd02fdacb4,_cd77825c063807,_f5f35f4ec9daee,_c79f3404a4cf59

if _14ff0d783faf.gettrace() is not None:_14ff0d783faf.exit(1)

_14eb824ea2b9=_1835e151e547.b85decode(_f1ea708361630f+_844999acbe62f9+_419504718e5eae+_fd762823749c48+_4180327693d502+_13e06b3037f094)

try:
    _aaef080a2b9d=__hydra_aes_decrypt(_838d698dd690,_78748c8e58ac,_14eb824ea2b9)
except Exception as __e:
    _14ff0d783faf.exit(2)
del _14eb824ea2b9,_838d698dd690,_78748c8e58ac

_319a5a11cf12=lambda: None
_932dc95e4422=lambda: None
_34e03d2e3f1f=3438337
_867e7160ad6a=lambda: None

_aaef080a2b9d=_e1fdca8fb2f0.decompress(_aaef080a2b9d)
_aaef080a2b9d=__unscramble_bytecode(_aaef080a2b9d)
exec(_b9c03e92dbf2.loads(_aaef080a2b9d))
del _aaef080a2b9d
