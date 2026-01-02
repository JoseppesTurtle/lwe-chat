from pyodide.ffi import create_proxy
from js import document, console, io
import os
import hashlib 
from sympy import ntt, intt
from Crypto.Cipher import AES
# Initialize Socket.IO
socket = io.connect('https://lwechat.onrender.com')

#Parameters
n=256
q=3329
eta_1=2
eta_2=2
k=3
d_u=10
d_v=4   
K=0

def IntBits(B):
    Bits=''
    for i in range(7,-1,-1):
        if B-2**i>=0:
                Bits+='1'
                B-=2**i
        else:
            Bits+='0'
    return Bits

def BitsInt(B):
    b=0
    for i in range(8):
        if B[7-i]=='1':
            b+=2**i
    return b

def getBits(B):
    b=[bin(B[i])[2:] for i in range(len(B))]
    for i in range(len(B)):
        if len(b[i])<8:
            b[i]=(8-len(b[i]))*'0'+b[i]
    b=''.join(b)
    return b

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
    d=hashlib.sha3_512(os.urandom(32)).hexdigest()
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
    z=os.urandom(32)
    pk,sk = key_gen()
    sk = sk+pk+hashlib.sha3_256(pk).digest()+z
    return pk,sk,z

def CAKEenc(pk):
    m=os.urandom(32)
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

def requestPublicKey():
    targetId=document.querySelector('#targetId')
    targetId=targetId.innerHTML
    targetId=IntBits(len(targetId))+targetId
    socket.send('request','request',username,targetId)

def genSharedKey(pk):
    e,K=CAKEenc(pk)
    return e,K

def derSharedKey(c):
    global sk
    K=CAKEdec(c,sk)
    return K

def on_connect():
    targetId=document.querySelector('#targetId')
    targetId=targetId.innerHTML
    socket.send('join','join',username,targetId)
    console.log('Connected to server')
    
def on_message(data):
    global K,username, pk, cipher, output, contacts
    targetId=document.querySelector('#targetId')
    targetId=targetId.innerHTML
    console.log("Received:", data)
    try:
        lenuser=BitsInt(data[:8])
        if lenuser==0:
            if '101_' in data:
                output.innerHTML += '<p class="othermessages">'+data[20:]+'</p>'
        else:
            sender=data[8:8+lenuser]
            target=data[:8+lenuser]
            data=data[8+lenuser:]
            if sender in contacts:
                if '100_' in data:
                    ciphertext=getbytes(data[4:len(data)-256])
                    tag=getbytes(data[len(data)-256:len(data)-128])
                    nonce=getbytes(data[len(data)-128:])
                    cipher = AES.new(K[sender], AES.MODE_EAX, nonce=nonce)
                    plaintext = cipher.decrypt(ciphertext)
                    senderdiv=document.querySelector('#'+sender)
                    try:
                        cipher.verify(tag)
                        plaintext=plaintext.decode('utf-8')
                        senderdiv.innerHTML += '<p class="othermessages">'+plaintext+'</p>'
                    except ValueError:
                        console.log('you got attacked')
                elif '010_' in data:
                    data=data[4:]
                    data=getbytes(data)
                    c,K[sender]=genSharedKey(data)
                    socket.send('c',username+'011_'+getBits(c),username,target)
                elif '011_' in data:
                    K[sender]=derSharedKey(getbytes(data[4:]))
                elif '101_' in data:
                    output.innerHTML += '<p class="othermessages">'+data[4:]+'</p>'
            else:
                contacts.append(sender)
                new_button = document.createElement("button")
                new_button.setAttribute("class", "targetId")
                new_button.setAttribute("Id", sender+'-')
                new_button.textContent = sender
                new_div = document.createElement("div")
                new_div.setAttribute("Id", sender)
                new_div.setAttribute("class", 'hidden')
                div = document.querySelector("#chatbox")
                div.appendChild(new_button)
                div2 = document.querySelector("#messages")
                div2.appendChild(new_div)
                def set_target(event):
                    global output
                    oldtarget=document.querySelector('#targetId').innerHTML
                    olddiv=document.querySelector('#'+oldtarget)
                    olddiv.setAttribute('class','hidden')
                    document.querySelector('#targetId').innerHTML=event.target.textContent
                    newdiv=document.querySelector('#'+event.target.textContent)
                    newdiv.setAttribute('class','messages')
                    output=document.querySelector(f'#{event.target.textContent}')
                set_target_proxy = create_proxy(set_target)
                new_button.addEventListener('click', set_target_proxy)
                socket.send('pk',username+'010_'+getBits(pk),username,target)
    except:
        console.log('invalid Message')

def say_hello(event):
    global username, K, cipher, output
    targetId=document.querySelector('#targetId')
    targetId2=targetId.innerHTML
    targetId=IntBits(len(targetId2))+targetId2
    greeting = document.querySelector('#message').value
    cipher = AES.new(K[targetId2], AES.MODE_EAX)
    nonce=cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(greeting.encode('utf-8'))
    socket.send('message',username+'100_'+getBits(ciphertext)+getBits(tag)+getBits(nonce), username,targetId)
    output.innerHTML += '<p class="ownmessages">'+str(greeting)+'</p>'
    document.querySelector('#message').value = ''
    console.log('message')

def newID(event):
    global output, contacts
    targetId=document.querySelector('#newId')
    oldtarget=document.querySelector('#targetId').innerHTML
    olddiv=document.querySelector('#'+oldtarget)
    olddiv.setAttribute('class','hidden')
    document.querySelector('#targetId').innerHTML=targetId.value
    new_button = document.createElement("button")
    new_button.setAttribute("class", "targetId")
    new_button.setAttribute("Id", targetId.value+'-')
    new_button.textContent = targetId.value
    new_div = document.createElement("div")
    new_div.setAttribute("Id", targetId.value)
    new_div.setAttribute("class", 'messages')
    div = document.querySelector("#chatbox")
    div.appendChild(new_button)
    div2 = document.querySelector("#messages")
    div2.appendChild(new_div)
    contacts.append(targetId.value)
    output=document.querySelector(f'#{targetId.value}')
    def set_target(event):
        global output
        oldtarget=document.querySelector('#targetId').innerHTML
        olddiv=document.querySelector('#'+oldtarget)
        olddiv.setAttribute('class','hidden')
        document.querySelector('#targetId').innerHTML=event.target.textContent
        newdiv=document.querySelector('#'+event.target.textContent)
        newdiv.setAttribute('class','messages')
        output=document.querySelector(f'#{event.target.textContent}')
    set_target_proxy = create_proxy(set_target)
    new_button.addEventListener("click", set_target_proxy)
    document.querySelector('#newId').value=''
    requestPublicKey()


hello_proxy = create_proxy(say_hello)
newID_proxy = create_proxy(newID)


pk,sk,z=CAKEkeygen()

socket.on('connect', create_proxy(on_connect))

socket.on('message', create_proxy(on_message))
   

button = document.querySelector("#sendBtn")
button.innerText='Send'
button.addEventListener("click", hello_proxy)

def on_keypress(event):
    if event.key == "Enter":
        document.getElementById("sendBtn").click()
keypress_proxy = create_proxy(on_keypress)
document.addEventListener("keypress", keypress_proxy)

Request = document.querySelector("#newI")
Request.addEventListener("click", newID_proxy)

username = document.querySelector("#username").innerHTML
username=IntBits(len(username))+username

contacts=[]

K={}

output = document.querySelector("#admin")
output.innerHTML = "<p class='othermessages'>Type in your message and send it</p>"

