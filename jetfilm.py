# PATR0N
#! b62925f69e0a3f0d137cc97a991ee06d99e8a50d63be520fd5e0f636760cb736



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


_d788c5db2439='BeRXDjnlpaIVhAv'
_67e0b654923b=lambda: None
_39dfeb0645f3='TzjXCFC'
_b847208c0a8a='EGkwoGdA'
_b1e67d3989af=lambda: None
_738f53d73933=6842867

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

_98853d294e33=__import__('hashlib')
_a7628858b103=__import__('hmac')
_267b0e29ff51=__import__('zlib')
_ce20053e862d=__import__('marshal')
_6f1618cd4ccb=__import__('base64')
_2e0fe378ff6b=__import__('sys')

_df518146f6a3=lambda: None
_97b8799255bd=7185304
_9e876a124dab=1567028
_4a89868d7c2c=[143,161,52]
_dfef229adae9=[96,216,102]

if False:
    _a37971ed6d96 = [209, 231, 224, 90, 255, 80, 22, 189]
    del _a37971ed6d96
if 631632282798863539 == 631632282798863540:
    _65eb1e009d61 = 'qjzowJNQZlhDIbQFGwgUOhEe'
    del _65eb1e009d61

_51d9d64cca595a='5Mu@nziq8g`FnYfO-d&P?@A$T8i4_^??yiYz;5>4XUO;1{u`QCx~~hlW&Hx~(5!D-%TR*?CoCEXb`CSTL?Mb5}D~3&ZSNw%l$jVs`X}4tM<c^(T}y32EHP$zG0R;R32%>3}+w;s`pU8=LlvvSb=HJ1XTrCTM=H)^8#JryJ2qtB#Q#J=r}VGq2yO?t$|RE)nKbgU~Ku%=dW8OH@^U4cF!3%a`i3pRB-sQ9t6>NE%Dh?>?(?f)80g9XS}Qd|xeC0|`fNPxWDMEO@n&3QG$m)(Q*7-wQW8nLz?D5vR1b2cxcO_MEF`)>5Z!MW0|N^;6iR(>Q(7iQ5}A`t!I9GbzHtyJDBNInoX3(L4y-1AimbU>3K6=lOm{M;!=xvB~D6dDk~o1uXjCEIxxpQ*Af+nA8%&-w)&N6p734tICA<<PXIT+7D+RE&K_4jkYO<v&n<=D1+Ufp-pa|g&re=S5%U)k?v}dPgDk6wWWVh8o^{ZGj=~yn(x<vR%F6NR6b4Pp<e)hc}jt?CK*C(n9uv!AOF3C6H=%Ib!3jJnSPc~Y-No1uxAI7?5#N!q^WjNiqiGK1?lkNQ1}h%<;<EXqw!<?NJ?p?BG$P-)&{*|ZS>;eGO>=K`KE7jZP&}?+DyyC9s(|I(klb28*>Rv0tI9!SZ;@2-usW9R1tz7*v+rL^|#3K2a$5H6S(x5j)36zLD%f5o@{HWDKKX2EsFUqeN8+Q$!jy~r)3vvX4pV(*kb^57ATs$_!fN>QfVjQE&7p4sygx5&aR%<Z~O<4>Iw{*rxKMyiP3v&nlGWY;Sk;}UEdFN@UB3U?>e56+?{h-k_^4'
_dbc422d5b16124='E(AXa=JCZOC5Hwvl1uZtKbaHxghL$s{t@mz`XFO~{n7<gqHW`9(V@R2h0CinSRu3If=?|v<*00+KMdeOQ52B1^(7Cbz)Re<Oir+FS}=f!(NDfFvEh(d9&AGLA|dPwdh3@ahy`cnNfy)(15YsD0a^Aen^_lD3A<glt1Bou`qp^1RHvb%R|ZIOp<SGNtIvu{i)=!u$M_`EcHrTHa2yd_sG-ieuJi*y8L6rm@hDO8j-6%FY^v#yi@J{2IN9$)81WJ%lM^A%$8BWuZ)3~KA()ARn4`0I@gnvbuI$zqWfMZn{P;AO095EgSOQ^efwYpQV*B!Gf;BxBMpnzyyiAjeHud6+R*+L6pXxZ_Tj1Wk5)~;A@4?zI&5;|VDl5AUK&Fru>^JT}W^`N!Mm;)ZeE??Ei^xc!D0}2W6N}pEZ%heYb#J}+uokBTDd{wMy0JAS<W}k%buH=8VD?+*^w83|7eV-x%LTST%h=8jiK_KpppFsQ^-Cw>zJrAMLT|+V4ZNQu*4{`0`#Y-wMkAaGzEFo^sl(Ya;UFdh0P~jc^54}mGP*_2nPUwY{BK`2YZ;l5Lzau0XVAZBg`Pnt-D)fA=>JZ%Dk)9Zlnw&KbKVVVpVlKjCuR;%zAs)U6BdK%9Jl*gSpjx%YwMs^e+gIu(%A!2aNqr#a{L7CO^!<jgM#t9q4H(6DXx`V?HSoxF|V$jus>rT>rY2w4~!xz%s6^aZC|dRRZ=Q2+OY$U?&lJR9)l=o;+^F4C&ic;k<11}Fj~Q8fum)$alABBOgoV3i2Mhp99&4l8OsUU_)%sBt8VQER=3XgArz$&?f#Qj!-12-L)'
_f19e95b942ce7e='y&g*TGok#G8&v@*G39W>*|^O0%+`U?+(`Tv@wZcca2?kx*ltH2B@q}*%{C+e;WhwFd7s*E_vr3M9BFB-@%e)6PA*Ot#huKxaVsuUYX(XXD*r+y8U0!KTbtz^M)e>d=;qJcjUiW>v&nDglv3vjJl$cPj|%!HO2{)QyjtdpSS10}kn&+65WxZb7cgE)p`C(=X>nHzegYgf$Z8L>-)g$xYq8Vlor;3i6l2B|5VwIYmX&iWF-JTK}UXx|$G;NCTSh&BV{9)AY{36ul7gJKEGFB85Vcf>3%*Qs3^EFA24X3wWC6o|55V>YEGp_6Q3yqgQ;-gzTKK-_>sezJ5wiOO)8D<8p2l73dNFEwz*VDHJ<0kvgNZQj}?5-SAXcxzr14n6ihsL-HWr*lH!*cT|RqiI(pmjExgKwB#J=(NurpC2l;WnEq-flhy!E7!~V^phOW*Mob?AJzC$%e){?m_i;JP1qERNktCv!NRU#xb&7sNUIw!W!!pR(R#_f+23T39?!|Oz?#5>Mi*{xfFWkFE2$6Ms=bI09K^9V)4Kb;zrdf21XQz?t6)*Q<fKM=%tI}>m~J5ESzQZyy)i0>2v!2GlBx$<f>wYSX8Y4D5gk5UM#nUe;n?|VpI!B5^OtZ6M&zQmceG~@gygH!BIQD-)uasLG_|dSL4s>Q5ji1~)4@CSR#T9K48xO7xB~cssN_kyIU;as41T#*I<~Y&UD9v3!zNtwQXBMJW_`spGXn`%%Llq)ayu2}4~ei)?Bpv3fIVj_5-DaYFoZlNo+!139(WfeY4?Wt(m>%(3WO<Z(+zFG7Dh&)qdrv-{^tcyRDgU~'
_0e61da2ec080e5='XRDdRXSPDgg9@=;?PP(Tg!<8hh(6RJ8HM72<gQ#vcWZ(|%sUsMzFehf7IT6uY9MvkU(?Hx>8<vtJ0cD)bVrjei;htGL{D&jYf<~QKuh8u*2ik<jYFS)pwI3*AZChQHGa{s8}zrXG4X_6x1gZP@jE)+t2ZRes;Th%yy=<l5Qk6JsnU<7=ac!~Y4H{KNSrNE1KGFyMHlDSQI<s`GYlt!aEJ_(=D%ov_Q7vljNwf6kWMgJpnnmlruP+_X}4E??cj$~JjpY=<nW(r1Oz4%cJq`zwsoxlQ)BEG@ZR5|3ieh?K9QEhm~YmpR$V;6l_UULX7Am#JxYgBeF8U{_jR&|2BhkyZv(5vsH&1EHHqN)gHms{F_jum-!IiZT#tqC*{Nrk5e7J<A!bF{uHze<uLF@LBw=`SA;sUNpGVu2SX;do;Ql#8yQXyG{sQlkT?fI|=}yAycqS<f$!=l*Q}~>Oir*o8`VWW+5*xW|vaKmmH7zXL3a*<<lyCgMe_U;b<!_?To_7|EWoD_6T(tlKqQ_Vl9c%#wKc_p#2feBpv#8b5>2wOoe0CnT!}HDx1;+dMN36dU>-tt=8z$W(6pgebqN^>%%}C<l)5!GSY*g6_G}-4n|IvRJ^<6R~2Bng1<}hAZ?0*P9ywk^eXnO(^ov3*xTGrR3BU6ij+p6lYg|A!#7x;N2hE4(v_uoT^Zmc)FHY4CJBNXN>10$@d$VS9O<H)M#Ac(vHX}&4G=BMgPr{)9miaZ2LXOo#`J!RjR39x`}t;U}kH}K?%0n2rh?s#K*?FBjmRo@1S_O714-s}t)Q2C$*G>OtPfLV*R!>Dq}%*'
while 773563914151260636 < 0:
    break
_def2894a53e534='0~X4M5cGO_^|yzreYcp>>GOo*4>lTKzbCBXqg-O$AsElrJ3Iyi+|R236vxRq~+Q0yL~bOS!+C5Q-tHt6j7DOgNjiyDpVP4<H>~Z1O0yiNTB}<8IcmVW?YCaYNS#4-`s`M!z~$1Nf;ylUU{YH7qY$<%N=YogpV40Zq$mcA}Lu`?1Og^i@Y}xK<$q0T1H?|Q+}lY2a7gV*wqb`T9L!I`S;82EdK~wsv~4D&3@JBvm+zki|B66?aiBA#>$qSpT!LDVAhc%%-(>z$(R@M5`4(iifFS-yf%w=&if<{>?&CT)68p7=jNrQ;JrU>JIYZAy50AWz{7ohS>5JDqpK;<D*CsX|7ZC!{<5(qOG3wjY!yFU?e2u5-Dw^vbs=F-=W96RyjM$#1aptiThWRK5#v=I@FSrG36b~K2bqP_8AOa)goO?vd2epcm)Y=9Hh2-(7o6Ad0%un`09ejwrbj^O-EGJtyVZNtt2@UcxGH9yCmFXH$c)G}G5A3Zon&?n0Ss$08I(?~so%HJ%D$5N39l$Lxk3&GZ^LfQ0*DqK1O<F!<TY2>|0hgSz}9wHZyl=}3ONW3>f20<qzf7h@>(34aSZw=e~Ps0?NE-S1lZ;6dVYJlho0p7yjTp0g-$0O1+z;eM<|NWofBvy-gg`asrBm<tR<)sqw#P|)K(1e$Nit$DnPHXjp}V<<`sFt*HXydWvyihVO0fi%Ll`~+Q(sy9&d_Zu`$k#%Y+Nz>?$cCPsBEqeZ8%mKvJ9N@ml2b{vjttjmxJ`hWb33x1hre#<Wz3UB%l=269V9NFK8=o|JrENWK5FWYWb8??V{69f&rHz*m'
_fc988e5fef0082='Hq~px~CiAVQ&gQ|^*^t4zs7swct5CmMe2_vs7T~EQ1?FkQS)96RgvjCIdF)!w<CraSW4<#vR`?LOl-<pXe0norbCEO8Et*z^pj!O40-pCz*1Rr?-GAmhx)>(g{~UAv+gY)oBH^f2PFdYMbPa<PY^dQI!YmA#0yC|sK`g_1ZhQk8OA9SOd${xCOx?{r+YDz*{oryRq^q;S?WcqrxS#SWHh3@&Y{OCRU<-W)qrR9(TXRz>bU(DO6!RLn*{JH(9niHq8yNvcx;jXM=r=m?^DknRgi2yPL6>JXGlE-Er@w5J*QT6ZM^#<=ogj#if8YeGHp|+GN-REUVWV-?m1adQ!D_gKUo06)eTUjD<!?{UyL}$r_NCy2d_xw;e^+_PMA4w@alxkdKQ?45C10=TA1m%Shdy@xZ(KmaS(?A-d-DVzY|7=eW^fZ0gGQiuABbgCcdWVGB7%HbOeHvmcDEBjoCS#NZ0~HHuuKnEzZ@!~TX?eWG@fz3n&@{afEkS)*bZC2aK{D*^E)XLjM#f?EFE_W2dWLtUWaoIF;(ezO^j$C;j%x2&=(J;s(=}^oq>CI?JpT8v{yrXi{4IDBSX~O3aE53H^5@FZST)rYJi&~(;jP1ieDIyN|$~#GWM0JX(Oda9aMZD$#`I=hSbs<dZw5E(nHBPtK$R*6|xFZlbDaQQ3pvqXa|D8O|ZAEi_ZP8GnI%PhYX}<JmHd;`DC$Qz@I|czIz7|_fB;>$-|Y^A??+R?^E7^QPz<zrr8BON1vrds5CDw)_rv$(*e<s1iy2~Bsq!uVAOoZZs3L=K`fH_+E-VnOx#mnp$M)u`|8}C`'
if False:
    _7e1a83e5f0c3 = [46, 44, 151, 188, 72, 52, 150, 137]
    del _7e1a83e5f0c3
_c773d6d1e6f58a='SZ4y%jxwz8K49fpW<Z^=k^^rWN*2;;BQ5P58)$G3#7N+d+UZgvlJ+*o=7PeKxwVgQf-Z22~fmpW>w?Mdl_=zIT;7^rF&l)+st|Lx*ih(D5&E!%Ret3+$h@87b+|J-`wHme)|Y9hl!B7v@EHRUd%$d=Z$GP^kU)6=0-CK^+X=UZ1|^D7!5R-3Q~?S%6bQV?O2zZDbZcsybNK3d8MKMsRPJb5WYln>eHQ@=b`rxcpjM`bumm@N0}`Zd0ez0H#q%0vXTLw=9Z!?8dBLT-1RwnSCNFCBH<?Ks)H$xf+=`gBmf`+|EGfBW^J)Jg~qD13F~Yzz?u--{RYuxUrh+y+`ftHb(|m=gK`ZzTrElQ3A(a6A)fK&4CJay>Qc1w>A;QPXCt^N+`@E>13MVI-=xS<vN_+vyuiDGRlfUre>lE>u=o8u%S55@G#lv?Ewx8z06X7RZ*v;E&ajKs`Qfdb@u9i7R_S{crVMdUI&?n|5(#Q-)eLYV*CjAs}P8!HOyzk?TQFEKerRoC3}1A#1bB0#Brp~o}T?TBkM81T87jjOWSsNgjV9)+r}XF1c-*bpVZ%GH3+_H%qT~2p>9_LG8Ao)T`)a@a{=l9?|1#OLcTrI_|58mR7!w#iEt1@u>f?9&<d%~PSM5Zoh)?}+4#_w>IlZO3gI6H$Gaovr?<u*+;5crIvBn5k*=HR9cPhbuA6vo5D!q&X+r2o!Nti1B(X4}@ba|$^(V0!iT!9C$ob?(AEk?-Xx4V<xdyE2M;R+1h@$7~wcIqGiRBbx=G`FNqfr8}9;rO*!;qJ2!g?_wbV%b0H6?IsjXRDjLPl6@_}`@'

_d36195dc3ea7=lambda: None
_47c4a0fadea7=[138,167,241,88]
_d38bcb2abc49=lambda: None
_4c6c19b737c2=lambda: None

# keys
_3e1a2a16bae888=b'\x01(1\xad\xb7\x82\xc8\x00+\xd6\xdfX^EC\x13\x8a\xe9\xdbcD\x9b\x7f\xad\x1c\x8e\x07\xb1\x8c\xf5\x1dB'
_d9dc4c50ee7e2d=b'\xf2\xf4\xe4-\xa7\x99\x1fD\xef\xa0nW\x904\x00\xe4\xa3:\xc9\x1c\xf6\xa1\xae\x01\xc9\xa1nn\xc8\xc3p\xbd'
_66eaf3bd6c3b4b=b'(\x18\x9b\xf3\x9b\xac\x06a|r\xef\xc2`cB\x1b\xc1*6ts+\xc0\xb4\x1b\x0fB\x18\xfd\\\xe9\x88'
_82dc15a2b7eaa4=b'\x98\xfeq\xd1\x8e\xdf\xb3\xee\t\xf1\xad\xa2\xaf\xadg\x95\t\x00M\x1e\xe4\xd0%\xb4\x83\nY\x1ep\x1b\x80\xf7'
_10979a395c27ff=b'\xa7\xfc\x81\x18\xa9\xccv\xdfM\x0b\xc3\xc9\xe1\xe5\xb5[\xaf\xa97\x96<\x98\xa2\xe8\xd4Td\x02\xfeO\xe9\x1f'
_806140cd9d1a=bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(_3e1a2a16bae888,_d9dc4c50ee7e2d)),_66eaf3bd6c3b4b)),_82dc15a2b7eaa4)),_10979a395c27ff))
del _3e1a2a16bae888,_d9dc4c50ee7e2d,_66eaf3bd6c3b4b,_82dc15a2b7eaa4,_10979a395c27ff

_985061a3fb7c27=b'5Q\xe1\xbeMW\x0c{@f\x02\xa1\x14?\x96:\xb7\x89^\xf7_\xb15\xc4\x06F8\xb5\xf1s2\xad'
_bca24ab80bddc7=b'B\xf3M,\xa7\x1a\x18?hj\x15wi\xbf\x89\x00\x8c\xd94\xd0\xbc\xd1X\x18\xd5v\x96T\xbcr"\xbc'
_3d9a9a14a5b912=b'\x9d{\x00\xc9\x86\xff\xff\xfcO_\\\x88~{B\xd8Q1\xd6\xcb\x1dV\xb9\x97\xc4t\x7f)\x11\xd8\xd9\xa2'
_868102ff8158=bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(_985061a3fb7c27,_bca24ab80bddc7)),_3d9a9a14a5b912))
del _985061a3fb7c27,_bca24ab80bddc7,_3d9a9a14a5b912

if _2e0fe378ff6b.gettrace() is not None:_2e0fe378ff6b.exit(1)

_758ecfb8405e=_6f1618cd4ccb.b85decode(_0e61da2ec080e5+_51d9d64cca595a+_fc988e5fef0082+_def2894a53e534+_f19e95b942ce7e+_dbc422d5b16124+_c773d6d1e6f58a)

try:
    _0d72238adc2f=__hydra_aes_decrypt(_806140cd9d1a,_868102ff8158,_758ecfb8405e)
except Exception as __e:
    _2e0fe378ff6b.exit(2)
del _758ecfb8405e,_806140cd9d1a,_868102ff8158

_415f19f999ac=8286117
_726f4eceee2b='EXiyVcqm'
_0a312f8e07eb='ntPFdNKaa'
_36e0899d3e1c='MqTnXSQjPcKeNqA'

_0d72238adc2f=_267b0e29ff51.decompress(_0d72238adc2f)
_0d72238adc2f=__unscramble_bytecode(_0d72238adc2f)
exec(_ce20053e862d.loads(_0d72238adc2f))
del _0d72238adc2f
