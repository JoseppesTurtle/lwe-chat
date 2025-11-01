#from Encrypt import Parse
q=3329

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


