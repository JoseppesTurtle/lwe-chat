
#Encryption try
from Crypto.Random import get_random_bytes
import hashlib 
from sympy import ntt, intt



#Parameters
n=256
q=3329
eta_1=2
eta_2=2
k=3
d_u=10
d_v=4   

def getbytes(bits):
    k=len(bits)
    byte=[]
    for i in range(int(k/8)):
        p=0
        for n in range (8):
            p+=int(bits[i*8+n])*2**(7-n)
        byte.append(p)
    return bytes(bytearray(byte))

def Decode(B,l):
    b=[bin(B[i])[2:] for i in range(len(B))]
    for i in range(32*l):
        if len(b[i])<8:
            b[i]=(8-len(b[i]))*'0'+b[i]
    b=''.join(b)
    c=[None for _ in range(256)]
    for i in range (256):
        c[i]=0
        for j in range (l):
            c[i]+=int(b[i*l+l-j-1])*2**j
    return c

def Encode(f,l):
    fc=f.copy()
    Bits=''
    for i in range(256):
        for j in range (l-1,-1,-1):
            if fc[i]-2**j>=0:
                Bits+='1'
                fc[i]-=2**j
            else:
                Bits+='0'
    Bytes=getbytes(Bits)
    return Bytes
                

def Compress (x,d):
    x=(round((2**d/q)*x)+2**d)%2**d
    return x

def Decompress(x,d):
    x= round((q/2**d)*x)
    return x




def mod(n):
    n=(n+q)%q
    return n

def polyadd(a,b):
    p=[None for l in range(n)]
    for i in range(256):
        p[i]=mod(a[i]+b[i])
    return p

def polysub(a,b):
    p=[None for l in range(n)]
    for i in range(256):
        p[i]=mod(a[i]-b[i])
    return p

def vectoraddition(a,b):
    v=[None for l in range(k)]
    for i in range(3):
        v[i]=polyadd(a[i],b[i])
    return v

def polymul (a,b):
    c=[None for _ in range(len(a))]
    for i in range(len(a)):
        c[i]=a[i]*b[i]
    return c

def Adotproduct(a,b):
    v=[None for l in range(k)]
    for i in range(3):
        v[i]=polyadd(polyadd(polymul(a[i][0],b[0]),polymul(a[i][1],b[1])),polymul(a[i][2],b[2]))
    return v

def vdotproduct(a,b):
    v=[None for l in range(k)]
    for j in range(3):
        v[j]=polymul(a[j],b[j])
    v=polyadd(polyadd(v[0],v[1]),v[2])
    return v

#Sample random polynomial from b so a bytestream
def Parse (b):
    i=0
    j=0
    a=[None for l in range(n)]
    while j<n:
        d_1=b[i]+256*(b[i+1]%16)
        d_2=int(round(b[i+1]/16,0))+16*b[i+2]
        if d_1<q:
            a[j]=d_1
            j+=1
        if d_2<q and j<n:
            a[j]=d_2
            j+=1
        i+=3
    return(a)


#sample random key and error term from B a Bytestream
def CBD(B,eta):
    b=[bin(B[i])[2:] for i in range(len(B))]
    for i in range(128):
        if len(b[i])<8:
            b[i]=(8-len(b[i]))*'0'+b[i]
    b=''.join(b)

    f=[None for l in range(n)]
    for i in range(n):
        a =sum(( int(b[2*i*eta+j]) for j in range (eta)))
        c =sum(( int(b[2*i*eta+j+eta]) for j in range (eta)))
        f[i]=a-c
    return(f)



def key_gen():
    d=hashlib.sha3_512(get_random_bytes(32)).hexdigest()
    rho = d[:64]
    rho=str.encode(rho)
    sigma = d[64:]
    N=0

    nA = [[None for l in range(k)] for l in range(k)]
    for i in range(k):
        for j in range(k):
            c=Parse(hashlib.shake_128((str(rho)+str(i)+str(j)).encode("utf-8")).digest(3*256))
            nA[i][j]=c

    s=[None for l in range(k)]
    nsk=[None for l in range(k)]
    for i in range(k):
        s[i]=CBD(hashlib.shake_256(str(sigma).encode("utf-8")+str(N).encode("utf-8")).digest(256),3)
        nsk[i]=ntt(s[i],prime=13*2**8 + 1)
        N+=1

    e=[None for l in range(k)]
    ne=[None for l in range(k)]
    for i in range(k):
        e[i]=CBD(hashlib.shake_256(str(sigma).encode("utf-8")+str(N).encode()).digest(256),3)
        ne[i]=ntt(e[i],prime=13*2**8 + 1)
        N+=1

    t=Adotproduct(nA,nsk)
    t=vectoraddition(t,ne)
    pk=b''
    sk=b''
    for i in range(k):
        pk+=Encode(t[i],12)
        sk+=Encode(nsk[i],12)
    pk+=rho
    return pk,sk

#until now all good
   
def encrypt(pk,m,rc):
    N=0
    rho=pk[len(pk)-64:]
    nt=[None for l in range(k)]
    for i in range(k):
        nt[i]=Decode(pk[i*384:i*384+384],12)
    nA=[[None for l in range(k)] for l in range(k)]
    
    for i in range(k):
        for j in range(k):
            c=Parse(hashlib.shake_128((str(rho)+str(i)+str(j)).encode("utf-8")).digest(3*256))
            nA[j][i]=c


    r=[None for l in range(k)]
    nr=[None for l in range(k)]
    for i in range(k):
        r[i]=CBD(hashlib.shake_256((str(rc)+str(N)).encode("utf-8")).digest(256),eta_1)
        nr[i]=ntt(r[i],prime=13*2**8 + 1)
        N+=1

    e=[None for l in range(k)]
    for i in range(k):
        e[i]=CBD(hashlib.shake_256((str(rc)+str(N)).encode("utf-8")).digest(256),eta_2)
        N+=1
    e_2=CBD(hashlib.shake_256((str(rc)+str(N)).encode("utf-8")).digest(256),eta_2)

    q=[None for l in range(k)]
    u=[None for l in range(k)]
    for i in range(k):
        q[i]=intt((Adotproduct(nA,nr))[i],prime=13*2**8+1)
        u[i]=polyadd(q[i],e[i])
    v=polyadd(intt(vdotproduct(nt,nr),prime=13*2**8+1),e_2)
    m=Decode(m,1)
    m_2=[None for l in range(n)]
    for i in range(256):
        m_2[i]=Decompress(m[i],1)
    v=polyadd(v,m_2)
    c1=[[None for l in range(n)]for l in range(k)]
    c_1=b''
    for i in range(3):
        for j in range(256):
            c1[i][j] = Compress(u[i][j],d_u)
        c_1+=Encode(c1[i],d_u)
    c_2=[None for l in range(n)]
    for i in range(256):
        c_2[i] = Compress(v[i],d_v)   
    c_2=Encode(c_2,d_v)
    c=c_1+c_2
    return c


def decrypt(sk,c):
    #check the numbers c fits sk also fits
    u=[None for l in range(k)]
    nu=[None for l in range(k)]
    for i in range(3):
        u[i]=Decode(c[i*320:i*320+320],d_u)
        for j in range(256):
            u[i][j] = Decompress(u[i][j],d_u)
        nu[i]=ntt(u[i],prime=13*2**8+1)
    v=Decode(c[960:],d_v)
    for i in range(256):
        v[i] = Decompress(v[i],d_v) 
    nsk=[None for l in range(k)]
    for i in range(k):
        nsk[i]=Decode(sk[i*384:i*384+384],12)
    #print(nsk) funktioniert mit test case
    t=intt(vdotproduct(nsk,nu),prime=13*2**8+1)
    t=polysub(v,t)
    for j in range (256):
        t[j]=Compress(t[j],1)
    m=Encode(t,1)
    return m

def CAKEkeygen():
    z=get_random_bytes(32)
    pk,sk = key_gen()
    print(len(sk),len(pk),len(z))
    sk = sk+pk+hashlib.sha3_256(pk).digest()+z
    return pk,sk,z

def CAKEenc(pk):
    m=get_random_bytes(32)
    m=hashlib.sha3_256(m).digest()
    K=hashlib.sha3_512(m+hashlib.sha3_256(pk).digest()).digest()
    r=K[len(K)//2:]
    K=K[:len(K)//2]
    c=encrypt(pk,m,r)
    K=hashlib.shake_256(K+hashlib.sha3_256(c).digest()).digest(32)
    return c,K

def CAKEdec(c,sk):
    pk=sk[1152:1216+1152]
    h=sk[1152+1216:1152+1216+32]
    z=sk[1152+1216+32:1152+1216+64]
    m=decrypt(sk,c)
    K=hashlib.sha3_512(m+h).digest()
    r=K[len(K)//2:]
    K=K[:len(K)//2]
    c_=encrypt(pk,m,r)
    if c==c_:
        K=hashlib.shake_256(K+hashlib.sha3_256(c).digest()).digest(32)
        return K
    else:
        K=hashlib.shake_256(z+hashlib.sha3_256(c).digest()).digest(32)
        return K

def getBits(B):
    b=[bin(B[i])[2:] for i in range(len(B))]
    for i in range(len(B)):
        if len(b[i])<8:
            b[i]=(8-len(b[i]))*'0'+b[i]
    b=''.join(b)
    return b


pk,sk,z=CAKEkeygen()

d,K=CAKEenc(pk)
f=CAKEdec(d,sk)
print(f==K)
l=getBits(pk)
print(type(l))
print(getbytes(l)==pk)
d,K=CAKEenc(getbytes(getBits(pk)))
f=CAKEdec(d,sk)
print(f==K)
#einziges Problem sollte sein, dass encode nicht dasselbe ergibt