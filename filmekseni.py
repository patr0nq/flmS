# PATR0N
#! 9633a3aba9ac55c2e2d748465075464c59f0d8944aa190e0a579583d358e0653



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


_1777f28b9401='GUYvUY'
_30f0bd654c07=6365855
_fa040a1114d1=lambda: None
_e32c36486253='YxBPmZbsdiDbpUM'
_95eb3f7ab086=8366188
_a8d6fff36a4b=526892

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

_45dcbe08e330=__import__('hashlib')
_cda72a35fc4c=__import__('hmac')
_7cfc7c081b95=__import__('zlib')
_fe42d53778ad=__import__('marshal')
_82836d13003e=__import__('base64')
_26dd4f204e73=__import__('sys')

_e439f38a87b3=lambda: None
_224a6963fd76='irElkWKIDaenNZib'
_35977774011b=lambda: None
_3f00be99e7b8=lambda: None
_c6c3e060cca0=[71,83,195,197,41]

if False:
    _22703cfcb81b = [89, 64, 211, 198, 118, 230, 205, 53]
    del _22703cfcb81b
if False:
    _e3ce4f4afbbc = [111, 97, 63, 236, 151, 32, 106, 38]
    del _e3ce4f4afbbc
if False:
    _7b2a590d8c76 = [250, 216, 40, 133, 81, 40, 138, 181]
    del _7b2a590d8c76

_e62594b3382cda='x}3m1`FI{q=P0kn{XT-dUr2LwOt7}m@kpXGXb)86cHqkL~v{#nmAZ$cmE)B<nZoE%S+f_ftcH9*A~)1i&@|mGn_dLLp2dtZd80t7lCGF2%KY(n!`^0V_%bybN7;PRxI7{B4Yvpf)326oSz5jTUf40qzDo3unPB(BA*`~E4@=cn)r-_#Ee}4Ke4qLn^KKt_?t|>g5hXT-!;e5o*GLFx2xX{sRfx@-t!ah!p%5v1CQhKx^lf9N#Z^dbXCFpDuh%DS%K2clpt?u{6b-1*ilai`+{j^EB6;yX)vs$ATYnAFoKxA=91JSERY^KI>3UFzVyKTxTvVfyVRc3b?)St7-$Wy{KNv<=<z1-6OwovtXO;GpAFCVq!K2=A*c@~3d#u@%_8jS9R7+R;N)%nlG~kOQRsN?6f=(Aa#VyH&V%H#2~8#M;BElwYFk=l4>`!{P2sb-RotPruAF7$^CM<1_*5so&0DA;ScC7NBL=Nq4$kfTJ^I5b+5Su@p#B?1Vd-6pw5@tE3Lsc2sW`b22j8I13QE4c5JI>$rAmNmF5QY_XC4~>gR+#Uijhe$26GYptw~Gw&T>d*;XAW}vJ#UnXwjm4dFBGVT7h({R(;_qI~osAG!_t?!GzJuzw!5sUvbDC3eY}<Rm<GdNjqH0&%u&*%-PZ(>?pb7lCiI0BX=9Kp@fZH9n((Sv=J8L*-xcWs!HWmV)6=i*Sdt_{gKDhF^72S=i?o*nrvL_G&N1k^(p5}soa8Ju0B7}(7P7#6POsbEW3NlFC|!A1zjx)QZhvKxm>i>Q8oX;eQ4%7jLd@b!e=zfe-q=I3<;%13Y66|&ceG!b`lNCv38dEHc|g4ZEy@!ZPGOL7I>IK8d6oX`WG|&R3Jw2(YJ9AMOLrW`!QC#>@ftL%|h|c4>sInMsjJ?Q@SI^94iQjQfYPRW?bSP4FALITB}_bwj_*amnR(T*|D8x&Vv7#X&pg}lIe<+F#^?DsTh=)ixi9niH6`U{u>1pSnlJ`b?dq2Be&g8whcDLFG{?3E_xDDK2%1PMvDbxzuWIo!(O_2Hu7TK-G6gUs@C_cOuR<=;E&;{na*;pI3l(N^ex|^k!&@0av}<fP1GZ+(%o2=IOjFz&<N&&5uICRvgMC9DJFOgQv%PJ=+68t#&yJH0}dqI<}}*`e9)zQ7sQDb?Y>RCaESk6PatV+ZZ#vrbMZkJl{5If6+L|yKu5--4cOWLQ<JjP4}i^j*~~`j_644d9d^C4Y)xLwtuA3#I4cA@BuhCmyZX=GTa$=x=lF_dI7lbTUHnl^>(;1=vLDyX4t)RwBsHV8oNi18aNFk?vM8d*ttPm-#yPn-*sCO;Z;=hBAH`DY;7Guiw9gF=je-tHZes%M9l%s>Ml~Z*t1*6y`IlI{20w>WB4r<4PnFs<+uyp_id*8c+95@7`gIk6+why1d`{Wi$NhP6H%fli4A9JI#&VnSbXZHa!DT!HHzxPy3|<>~m$b$XM`LR88UW{rgXK}1+FYG{o~a1}6S9zJtT^4+1%0pjP0!nay*VE0be&L|fvjsLAH+>p+&+e!7T#AWmp@)+93-C!1tvTk109Oaku^NI;Gb|*HT4c&;iwx24F~+#uO1k|B^4xJ4LwPWsk-u*_V<<=npqR=tEdF9MKO?mGfQ1CUo@01&uZSqtU*ZmLz{?ZjkII$e5>*SOJTVh22BsH{=ovXQ<ct<*mj7BMNwa;CwO9KohBYaz;RoyAyItN$R%4eBD-o|De0k>(}e_*32DwMi)o<5=NoKfe4yl;hE0k`sMAT99=%JA>t}9RgS>{7%ns}`Kr6i|JKNkuxd|d3l6cViy^}$y@?Dg=j{Z^@UfGPeNemQqz^|@zIT}WjL^eDK46s|>EhRktU0|6v*S6P(kSjC%^t#D<VEOfW)B+J-O{KYytR4!mS%fI8HzPxTF%;O?SY5?`$y6Wz4y~~h<UuRrZ?_Bs*Vw=s%YkS)+&3;h?Q5s9N8BX=-sw!+j4A87Q5$2PU+H%;Pg2~nj`Z5Pf?`R@7ei4rJ#7U_aUv29EWjFIFxs~M?jO1Ot%Xt|`NZtqeV7BgYrIf`OFQ7ACUcu`P=LB^RoSaAXNYO0uTBhTg88+P7SD_kUw=3*-4<JTEv>vCBEG{Q0y_#f`<~$EMlmi=;>6v1tiLKl8_CR_Yptj@uD|bjK@5dq#dW-<DAZgo)Dc}Q+oP1{cmXO#4{^Qnw{zj0c3oaHm~0QTfjr3ugMcUC?9o$)gaEo9``)?|*#}Jsy7R-+;^KEi|3H5I`sb-Abq#I0;GGh!tHsc~oi2ywR1)&hPu(jY*_eCfcd6@@rl_eahuhl02*dOutxnAH$jG+NLy0k_f<6(NO9#0u23lha7cGgCDT~t_9@wvPM&I`}C}aNB!(DysZGIl#meBF|Cd6g_k|a4va&wBXSXUV&x(?Cs>#e&5K0+^RZbmumo;fAKKxZVY^7pnwg7!R^K5SQtCTmRx>R$Hw02V{pFWPs*et|Jr*(#fczw(Z~LGV>C2<cJgmlDwfXf*OQnN=w4H$7Rs*2W!fN1s)w@{MIRnm0q~3C29_tn}^X_MVVEHfW$5;Wm5lhd=kUsIgQ*ZLQ&0*hmM)x18tl<GOH6R$3?DT#ey8v2@pbpvZ~PPahzzOLvy{MgZ*z#Df_3c$uKN$}8!?G4l%R*2#Ja9g+1PQxgQfik*fuHoWt@0l4u^*Y$5Cvy}g|VbB>&{tf_Xh2~%!QG}#zp?Qhx{f)^$Mpt6AiXJr;HsuR>!0~@B%OOd;d<xC_^=I;MklK@VAtzDGD99g8FE~)h5?owD<AnQ|NcFkz!0jgiMH;L&GFmF4lgR{CXj**;L-u+{AWxdK-fhkguC@=pc(mtgVSg%@0Xp%GmZll%Rib2=JcUr!X+xZA4+ueq51F1$pGV5vkS0VlNaEaOT3>e7Ah}r2vG9#jiGfct`o%4po6@TBz#wn<y>2lcxL3t}i)RfAbU?5gUY!Y|GW@F`Pzs8<6&?xSpAOqMx)LS<;vgoRC2WqeMcO7>P{vSMqTI_w==fV0%VpUbIxFRryu@7g(N2_dnYI`2<a{r6rST>5Du|PsBt2STXu|4%O_w+W7n&hv)vtDv%AU}gUi~+V*Yr1gobJL4MOgMhx$#3E5_1T_-X17(*98393Jp^PO>I98jJx4sR?PNzc#P1f8$;=GlYyDX9Zdl!gqozi5kIdIyzskltYPb3Ldq(K;~5*vZDV?QX@SAsRMP|5*)5aguJKFI|MmJ>n%biek%Y-F{&a;#=V&hUi>d|=cZnXH_yVU5Od)HJg01o{F<Q^$7%%CjBGFyA**7n+GEDlKQ6NYoj8@vVf5R4^$AlW$y<5X-1OIt{f+utL8^`QXn>CPl'
_3fc1feb3e3209d='zt=CGr+XD9g>%QsQ@@OSCh3^q%QoT%h19Z3gz9aR4&NeqWv5@}Zc3KD$Id7hYmB&vgY+s+nBNgZBzqwvRcEI$u<BPEtNN26fwYAXR8Q(bFUwW%9YBv*<^ECFR`=cvGtqxSlG9T?_BHU|oPO$|f9Bsfb$BEJjniuMGDiG@3B;e)_`1rvqT%a8s_;t|Q_q&x9_8sCJaj9bD*6iSuCh2QY!>gn*JK0mB(dWi3EUdJpnQ*RRmTp`}(gDo`i*$T~+*yR1IUD}BkvzEd$e*h&4T6PU(f;x?L`t~=A={+!9t$>XpTrWg`u_|k38lQ+mA*e~oWcuM+&7y!*-7agBKe%5X{<fE4LU`ILuU;ced(t;QS;MKKcAR%)E^`3f^B>4MnLSpiC6OfofV~IZ8G^uE`cJlNxDxU@v)LRY?-|st65(?rA0Wv^uktL9%Gl=L;0(QA)JH^61O|E;yFWq#IHQe(xz}!ir+Q2eWBT$$mD|m1B=uKT#T!^Y{X1lDlj?Dxm80<8uj}9ZE<YJ=R7pjVD(gcE|Bf!ynclP!`K!-M1J&=xZ?%ZA*$0SPgCfOIH5gFn<xsu~^I2OFCyT<!tV&7X0|2Y|hD5H$H>=7=-}(OI2Nir8=W_`GENs|(PcISTfu;E{z7~xtRsa?8V`#yTi#xv>!cvyEQpXZ&iQO3xSEPPni{;UpDa!;a>C4^7wQBBN5GW2BWfkrf^HAJZJqd3jXFVobzd4{v0P$ZdE^2KQ@*VtltH7^N<1d~pX@^hHBqrO&dw7B%NgI{^GoZarM%uNiL{fQ3F>~6(?r+sMAZ5s4Z)rzU5G$;?k2-+T*j6dztbXz23I@GQV+|d-xO#a~7n8&%DXi+KM6~0>o*6bHeM5A*+8!V*WZ78%h>=A{y@adnl>X@B&}5Ygccij^=}xW(1Lr4?sM~|(4Nh%OBgU~~h2Gq%Zt&cEK+h_|CLvoPUmqwDmpJt=OaDq`pdHMEuVoLtfORy;K3+ib#s2#iYlmklZz&L|clH{rf$tq8ZWGys?wybM-wR0}tR4@mPQA}ALds-Tw8YW26m;^xh)K}^c5MbZP6p{TWrc<=Hla4EJy$2ZFf6Sy98*BlHDGEt(!OOv>`x{sy-3I4r;m@18(1cI%BX9}T7B3;TE#5fSO54qvK4LCd4Pi%^p{x*9#n~7!~$bqJ5<awU4ehaA~u-+QE875|8k<#=S(d6woiQ=JGh~TaY7ioNPP{(rfj&Flvz=)aWgAA9i5~VwmEP!IdVubDj@Yd<Ub0aGhHS*%?>v!Hb=I^GlbdCeABacV;ihjuB;HCt<tKZY=sF&Z@~miiyP7PD%{JV{*u8r|Aa&|Lh2f1%qneP`HTd|Z$L!Y<wK;s!iDb&dg7Xn?-^Y8e{8C9DAb@9vd$?QVdZxz8fv1hgvbZ*3GC)@w6NO5)E_b2l2rL-2hZ{?oSj;?yy3aN1xz6SF8|NE*svc+`S2s^7=s~3v_bp)(AEMxU{rg_;bQEi@cW6K9~CX;Hn>c_2!CmvxLp!}0s!vD-Tcc}SuZaBy^gh8L|?|`N1v8^TbHv~BIU;HmiB9_0;E9f(qQ<*Z(2Nd;i~u){rmovY`m$vsd7CrE~zLsL{OC$SG<{!GsR{);Wunk?j&w(<u1V!ytJ!nbP*>RsO9|xZ||5(qG*NjgX7>Dx3!Q4HZdGpxJFpwU;jHht8e%$?rzrp<kyBSGkh^<&I)NL>}J@(g8l|&)mU?G-ZW#sG-va&ioSA;aK@q$Lh)x){K<Cv!sC=<kP)N>Vjxo#&KL;=Ce}u>g{+@SV+0$VZ9Fb%ifNS_K)x=%+gS4*=%%tCm@Hsrd?U06pj5Q-5%?F#V9+cUvo39H)-ZMI!SSrVK?wFVMf(hBMb}dYC^wvw(b@OiqzO*TJnE2(Zvsr*^wi0_(Nev>XQr8%)}!HOc+UBT`x%v|kYUH`_$;>Mr^(VtT%N?Bq#pn?5URE%g}hMLSZFm>n%3z({;3MHk~RapsP<fuuaqB6g1{WZVT$WMn#Koa)aW5#>ouXxFQ>PIReix=m<`oI;6kfeYZ6%Kt$x)(Mf$`=p|VB2K7m?CqC+$t0QHAAn3l&03Khr{F0CUER}>)0Ww%?^RW#`{vI`4|1w!(;Z6ZcVV2>idL5%v#H?jDbrv(49D+j}^Nr$w}=CdggSPu>Qa8=Vo<!|>`T*Ji~&u#+6o5sQJp=46~mG!)W+h831Pv6E@vSW7Mb8EzMqbem~4?8Ga0!F^agX3{81;pbF;6`By#_Eb73Y6ZZ%_z3>sWg3(xenHUh3!-Bq%$li|E3FMI#gKkUrN1ptHClzGqT7IKcotyuoZYUvlncr)z~#Z?v(L0b1e3mM7!xr7I#Rxnr;Lbng@7SapajBxZU)SAt4AD@P!NHrVttVM2_FKGV26pk(Mhfl}FjfW~)XD+_iEd7(J!d5JdOat8P6H=z=@w6W1-mW~Q@y>W>&y#~;`vZVH&(W0PpB7l)Gqef~qU^~%&U0FjQ2<e`FoPG%-DWJx83vp<y;J5V=!f|Rgt%6{|8!KwIX$%gOH`Ka{dFiqLo71=}SbaCw2TRn6*kLe8}N9Ss%@xIG*^UT9Os-mY>=>c&>Cu?d}b$3IySG_d<PgpPp$Rhcs%m9jRoOiLde}X2%_XOw<A0FQa*Y0<<(Ekyja%{93Q`MW65-Mok2;VwwHTGwPMa>&DiZ&jX1k%t%NC&_1x*fA5V4S;5^SlpS+6;Y#EjHJ}p@7m#Hy(NEJE?<D%PO}xqayK3ShfoeY+=vd{jsZNFv!F9ub3GbHcv@y=l0hjOW`U~%<<HR-qCelRB?f7#{m8GGEhX(NGlnGIsw68lk+$Eh&{(LYp}}hfOK9qJ9EyaIsQUK!}ul&F#zE8h`l4I{z`ix%$uHynzKIGwSWcb6JuhiBhYhR{VH$Z1THQxrJ6z=!4Ax>wBw_ticHrsIj{R?hva#|1{X;9-@f}0$QeFMJ9q(GLS*dUyRkFKh~g;HS#?C29HKZp0T@$Q>TdUmi)qcT3*jU}Lt*Mi<#||lOr_a^&KmQ@Y$)DFnCmGCg_#-V>7sd7dX<g$KM+NZOCO%^Ga|;jD6QY&M>ePitdO^u@Lkl9k8{LoJ#T7mrB|}YA3&9`MPNI@Zfybji6-)qbRXIdDtsi@;szsZGzXzLX44(Cte4t%CSk*S$|;EZ7gx_VLXwnL3N|KMI%P^Exv{*v2X#bYc$P{h>n<@k-nx?qO);3Bn@dDZKy~u7*>atr_|G+b>VsUkiBCkoU$YRHD;@TAINvJdF&$}(^vdW8l7wBMFmnOc;cBkyutNA;Zda=UJ1m!=>B$$8JXhctD)6eZs|pb5B^|s7wu975j28qN0?Wf~YRQT3;7=(DxYs7LKr'
_bdfcf3ad6fb1d7='~>4h4A*##t-?g-i;f6Z#~_bwG4FT9%aj@lBIl^G^;V!3Wgs@+++mh5M5ZWK7pB>wq)bk9lC3q)@uim<XvzqV+kJ|xw$2z6!(9Z8eA8-J+`k)87FYwBQv1QE4=bgs#qcL1c(BU|jPt(u*y&Vq~X%KX8%JuYZ0pbLg*;DwfvcwBtDV9Y|*>hm5ABswaUOA3+tc7>j#m4q@wSi^~M??Q}u@n)$BiH~}6nkN?18+)RE@%DmSbv3Z*jJ6%8VuBE^ntm6QqfII}AES=5q_wiE!dpfRd<#F!JJ3<fw9t}j$j`FAwthv97H4PULR2}d8AkSj$_ekb`|N?%RnaEf;AwI2?rk{UV_q#ZTo*Xl=C97lYaO4;M!y8~Ea8}2;ivsTzt`3|3Z`HuD3xE^PBwo`sDIs;gI~3$^ViCj5|U*tF;ZLRt_BB>$8*3v1*v_fWxNc~cz0HJX2qHIuA>5plEvH^35&euZQoclVcDkK??wa6kzW{2=GTwYOxpT#<wE=OvX3t$lO?pk`S>%WXA=9R$ToU4)Y#;t<-X)bbn0m0{2Gv&%7;kk8N6$WDD4UE<(L<pdob?wB{v4}OSCFzeA7>MJ6W&6^~_=Vl3Rem5W;WBI+`Y>U%hKh=B2H|5&l>?TrQN^7j>n=zv6$)pYIP<PoQ)}=+}?j9ImJ9!noXXV2QLRkv{gOdtj@~X@1yR@ZxSqTSXHf*4-PK{7feROIH;2m}A%BOV1tsQjzQ4(Po#o+Oy*8CV@|en44Hi;LY?-l(-2#NPvJA8}@xj&M21}pj_--#UBfZ;Xv!DxASRK52pP6^<R0q<sA#ux=f#$rC@8nRP>MSjjQy02<aN`an9#>cRvphA%psAh;}!-3bUHzgBQ!NbXCI!cfKqI>Jt7Px`J9VhiM|kHs_81;V!xEIHozJ9rjw(8}a_z2i^6h@=H(|D=e4v?F(D_{(96Z1pEDe4NR;Nf&cq=#d1ihx%Xa3f!XbKtT-|@Am0lx^f-am*E<F<`{dI^&~2SW*;7_g>zY9?(t3y{&QBJQJa)b>MNvGy9t(f)QepfVmXeWZvaV{+x&xutD+c=jNQwR&UVwsW|9*rtR5?Aln^n1wL7;~;$h}IIpkydqWlu}=6|0(8l{vr8Vt(|ZRU%8(UR)6~dv&9}7V6zwbOD^2YSq%7nG7U7WnT+XDQJ8=P)&a+i+64T0DWYO<fo+kBOCO|Ya=M{+c$?XHD5BTpnIMnfmZ<kXio^(7F+@;^~fD*>VOM3E%yQ9q`ni`l7;nu9%pK%STmhopOdoR7@a8zEzF{-6xh)l9p!Co!CvZDFet;GX*NsTLqQ#lueCOTiN?K4Vp2rOse%{9<sWRZ6P>}}cn?e&fhE^wFZb2Y1G?{2Ld*&}^h1+}i}3okaN5M}lgQ#B;;Vla4ay21IOK^mHLB*ir9pE|Of;pv<uro3TZ+GCYAh~^8f~1peqTZAv2cS#LrzAVOtToV8TIOv#j`CMYU^KazwNNAt#@gCzQtjni+e$QkVnou7T$M;l+i%Jfb$kgInyfuzDmHoh&%NE601ExxB>ov)?HZAPwt@KqX^FhQhw<e4C)N%+Q2^x>1|~#2YI9uO1&!vyTPQi>uMm63hI>Vw2fNguy?5}R_pxbZyB(g9x?`mcmbur^~ZXi#cYMWtSjdd^zgLYx8B>#{qY?B38jb+sM@+cm-IK-_kV)f(=j+Y?bG6onK$q}MK|^%yqOyx3qo?e&v`6%`gwYR(X@sMNHNt>=!bsFF1f-D1o~q$4oVEvjv!3BM+<J|(QNg$vzD*{@Zz;AJ|xG@BZ%@+w-v&~&E{fgnKkGk(Y`E?PsV;}W7iu%ENo!T%beNi=%U6o{Wo<Xq4`Fw7J3)$l}2<kjpDb9%~4}hUL|-p)nXq!GI@KE3Rbzq1f(6-0;>nH$q!0F;kRE$kwZQs)j@VdIgbQv9`Nnf^=_CyAtb)L)%-~_&prh-tFbiazmC}PmU$nnqU)nXAuvN|J0XW^rk}#QgXU8Ud+b|h1)=1@w;|FRi?`siuF3Ta-~dvMP<0$vDMt`iQ>GWf=0=Wy+fBDt6))5EtT#5J(<k>Zh=+waMIF}e8)_xquWWKHCj-@+H_tg9C|x48>Hh59t!}UyS~MC1OjLN5sJy{ybErk=)Ixiw5Tuj^t<lFh{Gd2w(gYi<q8Z%gCQf!fGS~8^lr#UDsH7+W7nUC5NKMO;W{Gj6syNZ(X45rA_{WgS2f2%j>YmV}yV^{2^?3_BrF5*HA|b*YC$*m$HHK_%jzWuaD6Rrr^38ewg?C~5cl8>+;s&r>kGvsfD!D2Y8koLMVPhtT_Jt97^;TLNG2GJ-7DDf11-=+jP6vH+rlfK+=;uW&Q`IgvI+5mh0KPo0a~RLpL6Hd9LELYC4W~6uo477P2&Ed$L=fdj)SUy6z3w0xkc0cR?F=N7g1B6Du_Mgo2D*Y89}75)8WX1kq4N>H`Z!ll(heIN69F(OVpg<r_pIaEnaF#gMwuZrX%Gxp^8e*LLO>;XOUQJZ3IAkU9#Um@C=Yk_*55^JBL@`Do<GShIZ9;)o0zw*j*XYk`39z3s^@~ydG<g8wq!Eu2Sb!kAXEc%lUGp7RG%%gj>-X)zatN7MOy&qf<=W?nh%3}jF}A=Y<ulw!s#Yoag&IT(D^z^M}wogj~etGLLb;s6;hsf4j?eifHOe%jcWkkq-enSRV>PGv*f%a1NGVO#J>g^)Sv%zSW-Y5v)=w`c@4?sg;hY~>jEgpDUz<Oh^VYC{arKpREu-LB505@gQt#tOi_Tl{Nz-7_8&Gc;XmQ>ws?m=Tpx;R8lB(JOnGMl?5u&YkcM&!p-J533t!>N(x3Z8;%X^JIUETUZH4wu9^J?Q8u0)#&M>Gem}rwflE|N|s&ki-doaH;6qw<*D>;(R4^!Vp+pvU*bph~+@2(B!7AvY=DeVAcGFoEvLDJ=NP(Px2pSPM~@K#0C20|TicG;9GcLjED5~L<-DFKHh0zM$pa{b!#1T0a`EuyYwrR2bzM{Q{@5~2gO{&04JXLz@L8RABv7_QZ=9h5rr&K~%9&cU}%i+~0Ewi7=A!BNYnEZoP^80y-!w4kS1^M*z*HZ=34mw=C%r3{0-N7_Tc_r!WBBjU;1#yi9~!JzfMtZ{-%F4Jp)Gs8qj6gbPQ`0=d%T2z|zX<}akSLJ|-c=ueLKTa9Trdj@oa>8RFj5im7&AHV)q7r2u5|l_s-09zR@0?T^<+3Sg{j9-<$6Td_CRJB+?Xi4>T$h(SdY!_<fsn(RVB}x3Zp5|{2OAD=I6UIG#b<|r1=!tI3)R4N>cv8NKdHtXb^5zdS+N4zTE<?*(!!M6eW26qRm)C2+L;wU<Zq??_66Uw^RQ+Ht|39U!H$'
_7af639c6edcf72='KNyi|z(_d}Z-u9${RG&CP@Tj;W21x&O^(z2G$NO_;;RchZz3S}u)6^oGB@Q1_~AU)Q26-kQ^XOfp?L>Y0!r30}pb3(8ucC{?z<CTLBYv@svgX1vS1p7j~$98;O{;u4%?`T;6#y-sD6Bsb+dKD`ei14f*ng5bb(-CC32?0>=enVEhWtP3lOSbK>oCQ0#zM9K80Z;7eX&~N`V!GIvfn1iSw7#=dq_0{(^2vRrdhqtrL@bc?<eFiBegb~<-g4E9+Wexlwww2^Y3*St)=7f8ES1L-P1Bx<|X2HJUM>b6<GQ$%ysS>_{$<AFP?q+NlA(N$saFZms6@)Y<#F)Ksq$${1SDaJ#jIK@<I``C-q@xWsUo77rtUKfFq-#p|JsbVabQM11_2B+F*5Xz4Ig#PJij<d;^6dYt6}(&a?d_~Be{am4Atj<d;+?au<vzbY+t*UMg2vs4@NXYWF`zW8xF5NyS!xw7?F#lFv^0C^W0;61DQ($EZ@s>3$QSZIGuin;L30wBnN+q^HN3ZuW~nQOm6s9Qhk}d^F!Lv*+=8b#;_(CN+kT7unS)_O*8{PI$+JvdN5z#Wo$vg@&^g${6wC1h<1EGTzx6&tu;4E#pjji5GKzi7vfHnkWVkCv|8Q?HxsQhMF8#hWV2jC(vbeKX%KdBx+p#(Ox~KzTRn(RP=mFu0obOK=_G2i0)>WGw=NH4@jH4|R?}OfiPD?`(yx9TYeCEc}d}TaG;A`OU?lx^LbG(68%q-V|Q+MGp>7&nF$o&@^RsHw3V)c)&NLY<qt6N{a7nGfWIXXpGoPg)LbNGAdZ_L5g=bgqr0TY-FEN+KX2ex9RE;--mpD|3b`Lyp!hR+bViKll)*iB4^@?chhP6%+4TNeO;O=AHU*6PsmqL6a7cD12NR0n%_MN#9s=SOZY9gNZ26oIq^p#V%l7DtbcGstUD-J=}C#mv#hze&^uM^Q}~(Yz2At+V^OS(mV|__w|J36=o8(=JRCr(tUq{%d*Uh-6q+6~}Y*5`eVzxAv>e?_0|~cSySQ-Q0r3_Uc<3ojsL(Tbe8~&(M>Cs|&WmjQ>&EYZnq`Q)+N#a7#IbXz+&5jWplz?`~qSIy~28sE?I6yGw!^c4!ffV5P;VlW7}|@(xfumNy2PEowp2?1e^CS8e;PTL&quGlEJv6#-gRZlAu>d2LE7#MX4kIVtHC{`z4o_()GqZZZu~jxS)=74<5i4?)xYz8~N+ubL(YwW1yBm#ZY-0Dz$qY=}$)E9(Bgxm~0(h$M%7qSu9>ntu&vE)Sv!!iTPdj9P2J-)<>h(f@HLCZ#JkiRqZx3Rd;*QWK4=`y@+glgXzsWB<XYw_~XQp=*{3DSm24|Nj6-c{PQdx?X5`*fWwjDTIe-|6-b$JT5vIp5thuK(499{y8+DYa4M;EE<ffIt4#J7tjt|HMBOXBqHG;<&2F18C*V6K7^iG9!5wi>Qj|f+?^nzM#7X4ISmA?Za_Xxi<4|P9*AKKJrC9@<}CT^cnV5*-ibk_!{L#jObaAr!I6T9nafy|a-|068LAVS`lRr~QARb7%T!N<+Q1Hm7Cwq%;}~Tt+aTO-ZO}pMB^>Rmzx9r-2N*E3Vz@4J2%a4KDXk)0%mE}2fm$)IO|UVIU&P&qPZ;NhLgqRq5(E=x@)<hed4V=lN^@LTgj}ZM{<ks}#=9|cSc#_Xooy~su|^(J`Vw!M8o74Xf&isq;c?z~j5TLfbA5P4_6}Dc4ie`?^{}XpL)}8KynA-eM)MMEVQ^n4^)gZkm(4{P5S8oqspF?bRB8^gsPEP3E8*5ViS}>SHMQ^TIoH@!l!wh2!GQ=K5OSCNlvrHh9Q!m#acayuW1oK^1txZBj9&>Nj#xqD-D3|kJF>e0=VhQM{A+16A{N8p$^+$2?`>S~2Cd~guvA~>-WtKq8gRJ@Se-PQud0*66kNPU8Oje$7O3*<8z?|h#e_EH9f);bE=cHxQE6b;Px_zt%BS5;QxZd*cknm53tIYtgNx2eO?P`IlC8a$B8$>~_LV#QyRB?yVj*5%^Oe`c#Y#Hae)mU~_sLp{s1_r3#u$(c_qD79d^c92nuha7nmW7RP@L1&-g`VgRa-`!Y)e&QPL1SsY{gi@BdT>MI58*Y{B3k!vvJMl%exg4XT>(U7lhw^Ffh+6uazoj=1T{;!=`Lqrcz&U<p&4;S(_GykNYzPqx~f(xPQ#a6H`EXJU$<b^!}Ire&r3l(UgsVp+K&$x1#gV$xs^Tvct4WO6ypE`I^kHd%_h@$OiCY?pnI;(V*ErFLAx)=23Y0N1BC0@;;kN@Mvae9wGVMiNE9~|5$M?@YYw5MMrpCEi+M66hwhWfKJ4Xc)O2`w9rfB$bE$k+o9lqk5e;lOVscx4~~wAWboMjV2(bK&r^$u|B}a5{%~_xoNzoGC|C3udR@pN(cL>5#pXUrGo0pm@ZViqkF+2LNfbl)=ikY7h8x-DNt^aBh>2ddxb13jyARJ<@<WNF=HgP-&-fKGWyO{DPmN;QR=UqFw*M+au*$lNV&VlA3a$q0Cj5Y8e*euPJHd{MHR|{~t@XqXJ}3cX+`=#egtln!kFK_wl<t>mmg0C;TZ+PG8Xxj7lIS7es<Zqt+SBVCCifQ8*$LkBp_OYp@vVqz6YN4{wd+gM?VxKn`7pN}@!u;0YXWj1jVEK=^F-ZjwsSioPH1x$EoIcC)-grSP1pZF2YV2lB;=QXMB&<y`)+ysiKsec_$5>I_-s=p2lj}S4r4g4GG;XW=Oo+|Z+)3v0-TPu)wo<a26G}<s4b>xwuD`>+4^#qTd29UBjsr%<0ia-D$3&kM5g4;-Ut;w2exjQ-dAOpdAYb;rmL6>;9OFNSiKOGq+VKlYS<l(!o;UWXIYyqOvy^@*5$Y$=%!0oe~j&^RRbYQ)2*!(X?2!({e9;)x=hH&2nGHXC%RGEekRpAMQzZRaIFt1#?wHQ%%Zg!iu)l&k*nyIGS2Yu$GRUqZNVh{7@>C`4IF+tyh5n-gq&Aj->9JsaA_1KXs@D>2KvmY6joiPQgM+QE1IQtQ3mBPL?43V>1(}2Z&Y?T4p57^!gJNVGmNegykPoAWFpDFKC{VO(8UQ<;|XsM!T}aX+xh6Z23X@6mYnc(-kP~I6wm-Xtc7=7X6X~M!w3I?%A<1y@>~QI9AKMg!g8wBGJA@z;kQ-HsJ$lcsa-93S6LebT>8tqo(+!Z<Fuz8RJgw)ZB9gb&EzQamp5zWRGD{a|Cqc!C`Wx;W(S6xS*nuB^q2#>nL1~M7C(`^t4&SuiNiFbwqwBt>5qld!E5veD>lt$Z2}QuuCZ;wcXF|>L%TnnBC>TBSoVcGtc|2=&8BLWB|lEmqQ$Kldc@)o(g*wsyW{)iB'
if False:
    _caad18b14291 = [130, 96, 208, 201, 93, 112, 10, 195]
    del _caad18b14291
_67474082423efb='j47Hn$dm#D^~F>X^s`55oB{I-fWVTwB;314u}h>>FN5)P(6Nfj(XFnPRDG>^$N|yg&|L@QhZ_!izri|q1nYw3mTO(DUN;r`e=%Y}b8Et1Hg{0Xy&p?2<N#xo$!fxmRpmh;(BzX}w4-KvLwv)dGHbH&XK+ZKN4WWWkQF%5ROEZg4S9xV9EtpjTFA617+p}2t2<l4>;L+PeK^k@VObUnP?9Q&W)*P#2hyMI@-pK4gl0D}{hWPci@3Q>jKScYp!-j3K=}v4;eAqAX?hr55iYV(Ioa`d+VVSULuGv3!@F#eK^yq#5|M7y$<#;sl=r#-4W$weRBt2O$GHuq;=6I8V=h;k)Y<w;Z>L;#fwHY#z6+8jfKk@5<lP+-W&o;CDowF<M6!O1!o=5R<+cY!z24KL`cG)JN>$4Vcp{DSx}~~P7^$pA=&D(~;aXysD#>4{5i1BFx2z_^2;0W^vM=G{GvpM(q<Sni51HlP9WLL6M31GzT9D6UgiS%sJJ1X6+xllO1Hy-Yud6ghw4}F2(DwsR!~0%hgW#SQoDL*PI{4}xC{GRc?)iwq7owCWNn3?p#e8hc^x?wG?(;G8YmP=px>lJ&;(f9y-0<NTjCR`P_nA9VH3z_%kRdiI$+3>mJETtkt+Z>p6eGKUN)F2so4rGugsTV<_a(g(6xVQ}61JYEJD#24i6iIXHxK$|BM=9q&9nMV&if+|anjdBwe`({M^=ce4Z)6idUNc=V?q00VQ2H8?ISA#x*{bqP@95*Nmu%;^%6%!dfWp#-<X-_T)KhqhQ{@i_HoOzo4Q`f`Wu~|>r=);o!pmphadF~ohhToR(D)qL~Y-{CCXkX@Y{h2T4eK!*GhU5E(%^Lv!;Xi^00J+KSI8tF&Y`9tbK{**}3BGM%+C{Fq9m7>>N^GKz`DX3UJEcKF~rw-XTj?fB*mf3~kK?<7IqZ(<lCAXB*!2P|Oh8BQhrD9vvx2=+~>rtVSrgU&?gg=w%Cms(1s5842;^P|Bh5FQ*Sw?N*0Qqaz`T-_7Rxbb$mmz_6kNz8%*VGboj=93m8f>6PDnbgQ+yoFja`+8t;VQ$NZo&~se?cXYRONWY<(oXD+|?5=|TGOe0yE1i5Qr{q^M*YzZIYb3F1n0y=M&_zk5;K(3p?J?JQezTUe8v_LS<vo(4+V;=9Fw6D9uYLVZ+Q9ngK9cvv;!+P>X<XPPFKyjh3>|hn@#1`rR?+6xf@C)4L^X~q(LL=*@=<`4OK`AiRwbdq^eJ*A%D>-Y)cZ2YCVp?ZHqOU%1+5x2^Ti`?&Gia#huv32v+JBhfs|B|+63{d?a9Rxdt2FL=MPRpX7WIQOT-<ZV(XGB+BXGokgU*G$~$}wT$jV_J;ZR|Th<VqHnT>CBH=&|m%v?n5G;l**1?yK+4(4q$1qxNCf{x2s^|&_zWK_KMee%}tm?1TakWdIb1D)Dbd&ynY&#mglTK|RhLTFt=Y~G9(SR~q?Xc{4!C#`a$Vt}wkB@y{GzL(zsFz2LWbMcO24$6~^S5pSI*E?+enb#2UxyebA0JSYTGUGvo#OAHt>;pzPHt?WD0npSS{kL6JJ5zevB;B=MZs&z&)DUeQL#=3hT~UBsjczrl|AL|pHL;v+cvaAD6Pq@b`~Zv3#`G9S$>6GL~{xf=C;R;EZ)Ly>(@{KT@hmG_k*FphK+hbqFyca2bST7jNx^xP;rOJcgfEKb^pMXspQ7PIwbVpQsR4Jw`YC<&z-A<GGDgH|Cq}xbXcK%rIdn4hHe?_w(=>`4p0Z|g_-+oKseM6<-fZy#wFus;5Pux9CKiOTEiV!sZfRg!;QF8;`IQkmFeH+RgMWs+Z{mXR48D2pb7Fq@z%i6SvuxeK*mP{%)pxukL?Qv$daQO<_2z31w4cx&jKPQDPDluPjiizKeae@BGm^K=w7)H^)^Ztsn93;s835WG0Tc4G|v!OJ_c&@ZPO&9y1h<Idp7U&Hy|+lN$aNk+3sAsU%*jb8i2^2x#~ZQhVB-yPHja^`5hZ=^<Rm05`_^B{}~WTnDCWlblb3yUp}60a8Xf#wd@x(#O3TnQ7lQ|SAV*yvo%-5K2n>f=j}xvW1jtkrmG;Q&f}H=6i1)nvzO!-Vn+)|_rgLgO|Kp}03~&)(M(mTwbvM;Jd87gEXv=^i3r>NiEj8Ytz};4K(*R~X6q4=?f{NmHH!mNRH??qHu|Q<qkw(I{<+8u^{k>@b?QMI8y`nu3;ZcNQ^{(&#LoxxZw|V%$+zY$M*uig)O!Gz7O(rRW4@%!Rh5FgiGUj_qhzgyeY+Au?Lw+6Py2sz25E1|(lLMD(?f@hd#rU#Vl`@n?q#g*XCyHvsZ7!{X2X=B0b&jEdnOQ)8nd4;^^@Kw`U|&b`ykKm{Wy-BVhaRPVQfWozM?M9jnxGp(q>E$xzYl8S4|glz62^1+`Vz$SzAOyxb=(p!h83`?IqQrr3rj=O$4hp9tZ^J@ArBRjk-ow)mwzLBZ1yiKY_f92=&I*F$+odhF2+-TD|T4T>!MC)R$pE@mR{jkxceEAi6s=6_-GmCxjTquXS%gr&i6r6t&Z4tc?4;Wj>i>M(s=VEA0s9CL-ImSq;?6RebYDUP>^2redG{S#QYAdl<ZNFzGi;7^&)*X%9KcLVQDpiQ2bOA|P#QQg(6=5kX&;uc+*VR%Ony@t75w+MYhFk@N<=ZYJ6e*ycCd{rk=<l;;x9d#(g{1!NqFG}OVC)ved69t`$oUR`S&C0j2z;1<e$;%!-anB|mw^oy{Ba$8AH3^wN4(`Dm)p~^hQ_2%4VrBMAqLBtCd_WV)ZWee!;1us)(@rFF<yi;r;{hp_Ve(h1uqkv`~0n}}g6{XQVQ~Ma&BE`Fz2jadR68(bpoMsL`3Q~K)oA0=bUCN%(@jDwoA06S`98Xz31<!Fk_nwHNbIEKl%7HzJy?;`*=mYWa>F`BEUUI0nT|_m9%r188&P)mf4{q5Qk1}5#Y0*oi4bi1K{uc+H8KlQb<^dT!AEo;IRAvX$O#h_>v^u)~a-!+vjL429*#}zdCgLuAI!9eDxdt+>$@3<OG7i*6l-ep}0q9lLM$lO5TV#p0VoI3J>IX$_hHp9(j62-A{v8s!ZM(@eyNes~OepG_QG07|;$1Y>bjT6-7J{BNex#j)&^MRf8rK(o-S2ao+tGH2vOvSyP2}1^%)g)r!+;Sb;lcM~Iq19o`}P$UfN^FS6Hhn!4);P@6*let=0_9`x%TVB$MEa2_cLxS_H+J?Mz5g-rU+Q_)wIrS<CaBgfV2hfiBV@MiFW*bl-iCxNmLo1^9o@?c|G8OpF?#BLKLSXsCMwW`Mti5u`uI!H!>KI*->j&S`e*$WQdnfMFr=_uf6qJMPI^Uax{R^^1Fuv'
_00c90379f21f2b='&Y0E<LC#RSqXbrrs1Q`djqswGEZx<^JwKUsNBmk67neJ>r*nE)^q0Jz@WXR?$;`Gk9cNCdcJgG$eBUn~8lfBLG}}BNWqwY(lDdpZ{|569ru};Kv$WAAyvAk^iR-(oAnn>})h5L0d~UAqNXDDn7Y`|M`A*$MhxfNz!6K^`y`s$b4#vV(Ccu!d`_JQGSeRu8c*S|kX2#l{Y>}zczcuoRmpimgO0n815zQUQwpEiew@Jb7s?7@`air&FNClTyt{j-m;#U`}J>O9;-_|f`W&{<z`37vK7x^${i!2!8%|=Yq=iHdR=a{`EkY@x(B`d*l;%U$%GYhhg&-8^GUsK*JuBo|WXn3<zd}O$!!6=bBx+Y9O4*WzV@6O>kf%5;jh+eOq#8Hlui0ij@h3TlazR@v^{wv^Cg1u(5u@M+Iv=kY4Rna{!N-1*gK82VKT5yvNe)Pwf{LiD?QAkrxF#}_yy)e-0B@0zfOoe%w(w#=DBx6Z#N%{AzHjLV)rVY>VA|t^-OBNFO!AeGV@}z5C3)Uk1Q9dNu0x;+AS}&;7cv(EJvWubJ=+`(h`3A{@9L8i8hv*iaKDSGisK$gX+ae^8j9*+AMpdqGXBZXHG-TILIf|0Y5R;KHXGFXGHiyBTU(|u#`T>yaTQHZNQjycw`TAa!9Y~mKzl-aWi8kf^RRqdq^~eb6fGT>HjnTFx;rDIooTVS1T6hY{TdaLe+eyc(2IzB7#<v8rnT$IDH%L%)@u32SryCQ1`Zolw;($I2tnZdY#pJkmj{~5e77>}99yEwhB}kK7Zt7XUB3;0ux4e^YvR>QuM3z0&+h!65*>v5t9nd>CO1<${C9d5FC&yXVX#7!ot{d6APGU~(gVL94_RphS&Ud3ewAwphFV`z#kfc9B?X1bOvPpRL!hH|Vr4l@I2svdgGN$H>t8(CfZI66&xHZNUEIPGvTWwJQ`GnRjMr@GF(K-_E=h}kKYp7CF)4ROCDwU1rM7pz<$^kE@_ZN#TmmZ}b#3c;9*S7-1*fHzdc2gX~NZ=vkZ^<q9%o#NP;Jh^2t&p(x)3pIod!gTp3X29<QQN0|mzh3m#RYcVrB7q3cz%}H=x~k>j6u!QWWCy+1L@z<Kk*+ZaW@&;oXmGdKOIwtAKNQ-DU!Jl>fx*_X0Ez#_qca0*6Ded`8Ag^jpq<cA!`@dO#iZ1%ELgp=!2BNtY35K2|$Os-;oPo_cgRrFo?SVu|V%01Xtp(0yT+`sHS8Oc10HlN!vVR_4H7m^!A=-MI?+PVeSW8U87`hG6++gf*O)qQVj?Sy?Ez2hKG&c=03Y7FE$w^;cV-hs8FIBE?Qp;<0Z)nM8gEib|$11wo`ux*VB)eKbh9@eDFfwSlX0b;wOrw@~}$ZQ^c-)bAkwO#|`)J2UJ#^7*x6*%qS1bk};?M(&WQ-A?vF?;?&FlxpN`MHV7P#WKRQdf6(IdCeiLyv*%o)jrz}x9T>XvDu;RKXWxP%?F|$$`s~A+2X6dO^Vvk*tcC93mNE!7Oj;6`zxLaHt4mu@aNri_$0ePhgP`}|?U%$ggrRpT{&q1V9_aOFM2l~4?>?fqq1q3Kq*p=CWYW*;*$;3SH+75-<ys}u=WOB?6nXp~eJcDGQ$e>5AN&=E%Rq3JU)V>NB+zYWf(j-czMEGBolCo#J~%-0yV$eux)Mzl89?%Hw%wS?YqX?~bt*8*AYGwNy{&iub(!jKpt9#&>ly`v0^t;8_0KX8zEwQDXEdQi5Y^cItl@KX`|vWT1wwj*fsHf^WtthOUN6E7*fZ+R(c$%SHz0e?Yc$N!mG~s<+ZZifCd7aMD1!CM%!K^IL$N<Mde*siGx+xjEKW-|BH9U}-fiMwJ9ea(F!mi2?`2z3HMahz(y^oWe!GMQ0g@^X<t_Q~z>0rEvygpbd~e;&*inXsxvz`x-dO#Rx+CCg)sE5WJOeJWyVNf4xM4HuL+L5B_wmMu+058CE@EOw#Nj<IyskIkR|$$o5T?ED#pE3-&_;DX`Rf-bg+yq-HvwSvcG+0~>+zJQ6<tWXhVbB)q3^zpS`V!UL$SlCcaZw3HgUDaO+l;)B^f&`BTlv@yTB(R*TtVrOJ}O516|Q>39o&>Yz@DLtb1r*uPFB@w53k~CEV7dn1AG>&PkdrCdp>$8I;`VBHtqgyM6_XyZ6Z`&r*PNkX7vRxJfT%(-EG;GeTdf0@IQz@>p*Z^nrUbJxz-T?KHk&8E`wOtBm2KUhwhS4iA%euEvEX?2612uYzz_6V9o9spksFX{V(-OS4Qcz|yqw%y0evsz217`8uwN=23f)B@IN8YZ2I@-#QhGiDnKl1*K;ese)(PY}<ew37G`Fz&}El6KPL)e<;;&<tfRtNj9`dT$u97`gimoj1JF^h9G*VHOY6t6|iBv`T)7DBkJgvBp2T12n79v$l@!Lzlt4GU;}YA@Pj^04-EnI&fzksn)H7&su8(pO1Tnp)e^m^910^FbZ$!jYAx1?yoVdA#t207c9`A`o+3rX8{c6ma8U`#?kv<x2bQ*Jj78!sT)YI+{)<gze=~$LZmAZ|;CD9?Sf<^YzWm-ZnM0`+4d!~q(REYyV<?5LfZ^Btpl)=|;aGS45h#>m=LK>!JyV%UULx*SgB0W1e7)BdA1}h$jNusE*(=Maef&gmHo!|Ki@J{!KybL`G4mm&Zj82<<ecps%R2PVMdi2TYtI}lo@LgP5;m)ttXTnJ4qJX^6PUC;W|E_~lKe^qoQ)QFV0gVKE1T<{FX?mt^4*Mbcv3Xn7N!^E-@vQ<tx;0TD<(VY<4_8*bhW%u``qfd{GS9rU;fcALBgTOSP4t*&Zs_6BFT%@<2=<#r{3J3PXUr&;@rb~L`utGWk1=R2=LBW@f}GY4L!I|t`jxcyFve`;wJt^vcXpC0C6!=YtCwRPizZ3oMTt03-hbn8Wb_e$qkY|SKZ-Z>R6f`-w;5vr7M1p^)%PKEce|)7gU3)XF|Z8#V$x?{dSDt)ove#m1<#Yn0}(8x^S{jD(`F^RdbSp?AI?3f&excTdZ_M5K4Lcjla2aC2deg0R8(6Hb8B6*Ub>_Is?q{_U7XI=0Lmlk(CDO;@pGC5qv27kg(s8@b&8eP0(^ysn$b=O(~e^iMEGI`Gfmu^t-1#0jn?yiDkbcmVxD2X?iqt&)MLy6cz#c!TkDzJ-|m9v=~j6<M@wl@uqp+%g2nVkk<%^r>h+kCylZ*2??oFU71&u4#L|^7^%>;N40>56pNJxlp8&sDy@&>BbV<C2I)q1$|I8a6Y<gbcIiKoKTO+j`$R{pqev>=L_O<#mjyJ<-vGSmF)ljB6ONi3TYcIMp)fe@)j!5FcGkMnE6L8h9yop&5<*aQAN=)a1RzG?=0+&Q|MOI'
if False:
    _e5757d97ed75 = [232, 60, 31, 45, 59, 104, 196, 28]
    del _e5757d97ed75

_0d64e9d2df79='IQXNynqlI'
_4559547d6976=[153,62,54]
_36124c0717a7='lcNGxidEHSfkjKXw'
_1974b04e1c0c=8699566

# keys
_f24bc1643632ff=b'p\xa8\xdc\xf0\x15~\x96\xdc\x91\xc0\x07]=)\xbbvQ\x1d\xb3\xae\x87\xe8\x90\xe9\x1bm\xd3\xff\x1f\xac:i'
_08dba5e468ca8e=b'\x10\xd1CL\xd7\x8c\x8b\xfb{\xe1\xf9g\xb26\n\xa0\x96\xb9<\xa7\x99\x93\xd5%\xf7\xb6\x96\xac%B\xad\xbd'
_72a5e53f6dfc68=b'i\xbaB@\x9f\xa07\x99u\xa1\xeb\x94\xc3\xe2\x84I{\xba>q\xb4\xc8!z\xaa/K?\xe2\x93\x0f\\'
_f4eb644484ae1a=b'C&\x05\xa8&bf\x07\xd4Z\xd2\xa1\xd7\x14\xd9\xd7\xa0\x12\xbc,\xcb\xa5\xd9W\xe6\xb8\x95C\xd3\x87\xdd\xb1'
_6e44ebbcfbbf21=b'\xdf|\\\xaaLW\xef4\xf8\xfd\x06\x1cf\x05\xca!`Y~\xf1\xf6\xab\x89vU\xfa\xab\xaa\xf9\xd6\xf4\xdc'
_16e8a8ba243c=bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(_f24bc1643632ff,_08dba5e468ca8e)),_72a5e53f6dfc68)),_f4eb644484ae1a)),_6e44ebbcfbbf21))
del _f24bc1643632ff,_08dba5e468ca8e,_72a5e53f6dfc68,_f4eb644484ae1a,_6e44ebbcfbbf21

_82b461d7158daf=b'\xae \xb9\xf1\x1d\xdc\xb0\xafp\xc7yii\x85\x85Z\x06\x99\xe5{\x92bo\x10\xcb\x9d\x1f\xfe\xde\x84\xfd\xfb'
_a1b0187a6a32a1=b'>x`\x8f2\xd0\xc3_\t\xa5qu9\x19"\x89\xb7\r\xdf\x8e\xb6\xb27\x9f\xbdN\xb9_\x17:\xe8b'
_e4fcaf5aad7c32=b'\xcc\x14r\x1b\x1f\x07\xe5\xf1+\x01\x89f\xaf\xa04\xe4\xe7+q\xa9W\xe8\xc0Ys\xbbY\xd2\x1e\xbe\xa2\x90'
_59f61e29ccf41d=b'\xe1\xe6\xf1u\xd6\x0f\xe5\xf5\xa7&&tU\x8aC\xb4a\xcd\xea\xaf\x80=\xcbp\x04\x18?Hf\xfc\xe6\xb7'
_82b96f84b178=bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(bytes(a^b for a,b in zip(_82b461d7158daf,_a1b0187a6a32a1)),_e4fcaf5aad7c32)),_59f61e29ccf41d))
del _82b461d7158daf,_a1b0187a6a32a1,_e4fcaf5aad7c32,_59f61e29ccf41d

if _26dd4f204e73.gettrace() is not None:_26dd4f204e73.exit(1)

_a0db649456af=_82836d13003e.b85decode(_00c90379f21f2b+_bdfcf3ad6fb1d7+_3fc1feb3e3209d+_7af639c6edcf72+_e62594b3382cda+_67474082423efb)

try:
    _7d6b20333dcb=__hydra_aes_decrypt(_16e8a8ba243c,_82b96f84b178,_a0db649456af)
except Exception as __e:
    _26dd4f204e73.exit(2)
del _a0db649456af,_16e8a8ba243c,_82b96f84b178

_077a76b38741=lambda: None
_80ac74358d68=9131077
_af600f83d5d5='nlLxcInQDTNwYBU'
_e1f04856a835=lambda: None

_7d6b20333dcb=_7cfc7c081b95.decompress(_7d6b20333dcb)
_7d6b20333dcb=__unscramble_bytecode(_7d6b20333dcb)
exec(_fe42d53778ad.loads(_7d6b20333dcb))
del _7d6b20333dcb
