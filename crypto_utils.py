import subprocess
import base64
import json
from hashlib import sha256
import sympy #https://docs.sympy.org/latest/modules/ntheory.html
import math
import gmpy2
from Crypto.PublicKey import DSA

# in case of problem, this exception is raised
class OpensslError(Exception):
    pass


def encrypt(plaintext, passphrase, cipher='aes-128-cbc'):
    """invoke the OpenSSL library (though the openssl executable which must be
       present on your system) to encrypt content using a symmetric cipher.

       The passphrase is an str object (a unicode string)
       The plaintext is str() or bytes()
       The output is bytes()

       # encryption use
       >>> message = "texte avec caractères accentués"
       >>> c = encrypt(message, 'foobar')
       
    """
        
    # prepare arguments to send to openssl
    pass_arg = 'pass:{0}'.format(passphrase)
    args = ['openssl', 'enc', '-' + cipher, '-base64', '-pass', pass_arg, '-pbkdf2']
    
    #if the clear message is a unicode string, we have to encode it in bytes() 
    # to be able to send it in the pipeline to openssl
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    # # send the plaintext in the stdin of openssl, recover stdout and stderr
    #    To print the invoked command
    #    print('debug : {0}'.format(' '.join(args)))
    result = subprocess.run(args, input=plaintext, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # if an error message is present on stderr, we stop
    # attention, in stderr we recover bytes(), so we have to convert
    error_message = result.stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    # OK, openssl sent the cipher in stdout, in base64.
    # We recover bytes, we have to conert it in an unicode string
    return result.stdout.decode()


def decrypt(ciphertext, passphrase, cipher='aes-128-cbc'):
        
    pass_arg = 'pass:{0}'.format(passphrase)
    args = ['openssl', 'enc', '-d', '-' + cipher, '-base64', '-pass', pass_arg, '-pbkdf2']
    
    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode('utf-8')

    result = subprocess.run(args, input=ciphertext, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    error_message = result.stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    return result.stdout.decode()

def pkeyencrypt(filetext, keyfile, isFiletext):
    """invoke the OpenSSL library (though the openssl executable which must be
       present on your system) to encrypt content using an asymmetric cipher with public key.

       The plaintext is str() or bytes()
       The key is a file that contains the public key (in base64)
       isFiletext is a bool to know if filetext is a file that contains the key or a string
       The output is bytes()

       # encryption use
       >>> message = mdg.txt
       >>> key = "./key.txt"
       >>> c = encrypt(msg.txt, key, true)
       
    """
    
    if isFiletext :
        with open(filetext) as f:
            plaintext = f.read()
            f.closed
            
    else :
        plaintext=filetext
        
    args = ['openssl', 'pkeyutl', '-encrypt', '-pubin', '-inkey', keyfile]
    
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
        
    result = subprocess.run(args, input=plaintext, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    error_message = result.stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    return base64.b64encode(result.stdout).decode()


def pkeydecrypt(filetext, keyfile, isFiletext):
    """invoke the OpenSSL library (though the openssl executable which must be
       present on your system) to decrypt content using an asymmetric cipher with private key.

       The ciphertext is in base64
       The key is a file that contains the private key (in base64)
       isFiletext is a bool to know if filetext is a file that contains the key or a string
       The output is bytes()

       # encryption use
       >>> message = msg.txt
       >>> key = "./key.txt"
       >>> c =decrypt(msg.txt, key, true)
       
    """
    
    if isFiletext :
        with open(filetext) as f:
            ciphertext = f.read()
            f.closed
    else :
        ciphertext=filetext

    args = ['openssl', 'pkeyutl', '-decrypt', '-inkey', keyfile]

    ciphertext = base64.b64decode(ciphertext)
    
    result = subprocess.run(args, input=ciphertext, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    error_message = result.stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    return result.stdout.decode()


def hybrid(filetext, keyfile, passphrase):
    """ cipher a message using the hybrid method
        invoke the encrypt method to encrypt the message with passphrase
        then invoke the pkeyencrypt function to encrypt the passphrase with the
        public key contained in keyfile.
        
        filetext is the message in plain text
        keyfile is the public key in base64
        passphrase is in ascii
        
        the output is a serialized dictionary in JSON
    """
    
    with open(filetext) as f:
        plaintext = f.read()
        f.closed

    passphrase=passphrase.encode()
    
    try :
        ciphertext=encrypt(plaintext, passphrase)
    except OpensslError :
        raise
    
    try :
        passphrase=pkeyencrypt(passphrase, keyfile, False)
    except OpensslError :
        raise
    
    dict={"session_key" : passphrase, "payload" : ciphertext}
    
    return json.dumps(dict)

def hybridDecrypt(file_enc, keyfile):
    """ Decrypt a dictionary serialized in json and encrypted with the hybrid method
        file_enc.txt is the dictionary serialized in json
        keyfile is the private key of the user
        
        the output is the plaintext
    """
    
    with open(file_enc) as f:
        dic = f.read()
        f.closed

    dic = json.loads(dic)
        
    try :
        passphrase = pkeydecrypt(dic["session_key"].encode(), keyfile, False)
    except OpensslError :
        raise
           
    return decrypt(dic["payload"], passphrase)


def myhash(doc) :
    """Hash the content of a file with sha256"""
    with open(doc) as f:
        plaintext = f.read()
        f.closed

    result=sha256(plaintext.encode())
    return result.hexdigest()


def sign(doc, filekey) :
    """Sign the content of a file invoking openssl
        @param doc : The file to sign
        @param filekey : file containing the key
    """

    args = ['openssl', 'dgst', '-sign', filekey,'-sha256', doc]

    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    error_message = result.stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    return base64.b64encode(result.stdout).decode()


def sign2(msg, filekey) :
    """Sign a message invoking openssl
        @param msg : The message to sign
        @param filekey : file containing the key
    """

    args = ['openssl', 'dgst', '-sign', filekey,'-sha256']

    result = subprocess.run(args, input=msg.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    error_message = result.stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    return base64.b64encode(result.stdout).decode()


def verify_sign(filekey, signature, msg) :
    """Verify a Signature of a message invoking openssl
        @param filekey : file containing the key
        @param signature : signature to verify
        @param msg : The message that was signed
    """
    
    with open('/tmp/sign.txt', 'wb') as f :
        f.write(base64.b64decode(signature))
        
    args = ['openssl', 'dgst', '-sha256', '-verify', filekey, '-signature', '/tmp/sign.txt']

    result = subprocess.run(args, input=msg.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    error_message = result.stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    return result.stdout.decode()=='Verified OK\n'
    

def hexdeugtoint(hexdeg, isFile) :
    """Convert an hexa number returning by openssl in string with some ':' to int"""
    if isFile:
        with open(hexdeg) as f:
            texthex = f.read()
            f.closed
    else :
        texthex=hexdeg

    strhex=""
    for c in texthex :
        if(c!=':' and c!='\n') :
            strhex+=c
            
    return int(strhex, base=16)


def pollardrho(n):
    """Factorization of a decomposable integer using the rho pollard method"""
    f = lambda z: z*z+1
    x, y, d = 2, 2, 1
    while d==1:
        x = f(x) % n
        y = f(f(y)) % n
        d = math.gcd(x-y, n)
    return d


def euclideE(a,N):
    "return the modular inverse of a mod N : c like a*c=1 mod N"
    r0, r1 = a, N
    u0, u1 = 1, 0
    v0, v1 = 0, 1
    while(not(r1==0)):
        q = int(r0//r1)
        r, u, v = r1, u1, v1
        r1 = r0 - q * r1
        u1 = u0 - q * u1
        v1 = v0 - q * v1
        r0, u0, v0= r, u, v
    if (r0 == 1): 
        return u0%N
    raise ValueError('the number is not inversible')



def integralPowerOf2(z) :
    """is z a integral power of 2?"""
    return (z & (z-1))==0

def brentWithBatchGCD(N):
    """ Find the cycle of pollard rho with brent method applaying the batch gcd :
        instead of computing gcd(xi-xm) in all iterations, wait the cpt-th iteration
        and compute gcd of (x0-x1)...(xcpt-1 - xcpt) with N.
    """
    xi=1
    xm=1
    s=1
    cpt=0
    i=1
    while True :
        #print(i)
        cpt+=1
        xi=(xi*xi + 1) % N # f(x) = x^2 + c (pas de bébé)
        # normaly,s = math.gcd(xi-xm, N), we accumulate cpt values of xi-xm then compute the gcd
        s = (s*(xi-xm)) % N # f(f(y)) -> pas de géant
        if cpt==10 :
            s=math.gcd(s, N) # we compute gcd of accumulated values
            if s!= 1 and s != N : # (x=y) ?
                print(s)
                return s, N//s
            s=1
            cpt=0
        if integralPowerOf2(i) :
            xm=xi
            print(i)
        i+=1

def brentMultipleFactors(N) :
    """ Find all the prime factors of N (more than 2) by the brent's cycle finding with batch gcd
    """
    res=[]
    facts=0,0
    while(not(gmpy2.is_prime(facts[1]))) :
        facts=brentWithBatchGCD(N)
        res+=[facts[0]]
        N=facts[1]
    res+=[facts[1]]
    return res

        
def pollard_p1(N, B, maxB=1) :
    """Factorize N with pollard's p-1 method with p-1 1e7 smooth"""
    B=int(B)
    maxB=int(maxB)
    if maxB<B :
        maxB=B
    a=2
    q=2
    while B <= maxB :
        print('----------re-executing with new B...-----------')
        while q <= B :
            print(q)
            e=int(math.log(N)//math.log(q)) #floor(log(N)/log(q))
            a=pow(a, pow(q, e), N) #compute a^M (=(a^q)^e)
            q=gmpy2.next_prime(q)
            g=math.gcd(a-1, N)
        if g != 1 and g != N :
            print('a**M=', a)
            return g
        if g==1 :
            B=gmpy2.next_prime(B)
            

def pollard_p1_stage2(N, B1, B2) :
    """Implemention of the stage 2 of Pollard p-1 when p-1 has all but one of its factors less than some B1, 
       and the remaining factor less than some B2 ≫ B1        
    """
    B2=int(B2)
    a=2
    q=2
    
    #first stage
    print('----------Execution of FIRST STAGE...')
    #compute a**M(N, B) incrementaly
    while q <= B1 :
        print(q)
        e=int(math.log(N)//math.log(q))
        a=pow(a, pow(q, e), N)
        q=gmpy2.next_prime(q)
        g=math.gcd(a-1, N)
    if g != 1 and g != N :
    	return g

    # At this step, the value of a is a**M(N, B)
    print('a**M=', a)

    #second stage
    print('----------Execution of SECOND STAGE...')
    q=B1    
    while q <= B2 :
        print(q)
        x=pow(a, q, N) - 1 #X <- X**q' - 1 mod N (by modular expo)
        B1=int(B1)
        g=math.gcd(x, N)
        if g!= 1 and g!=N :
            return g
        q=gmpy2.next_prime(q)
                
    raise OpensslError('Factorization not found')


def shanks(p, h, g) :
    """Baby-step Giant-step algo to resolve the Discret Logarithm
    >>> h : element of the group
    >>> g : generator of the group
    >>> p : the modulus
    >>> out : x such that h = g^x mod p
    """
    print('Running Shanks algorithm')
    hashtable={}
    T=int(math.sqrt(p)/2)+1
    S=pow(g, -T, p)
    u, i = h, 0
    while True :
        if u in hashtable :
            return i*T+hashtable[u]
        hashtable[u]=i
        u=(u*S) % p
    raise OpensslError('Log not found')    
"""
    #[OR]
    gpow=1
    #Baby-step
    for j in range(m) :
        if not(j in hashtable) :
            hashtable[gpow]=j
            gpow=(gpow*g)%N
    #Giant-step
    inv=euclideE(gpow, N) #we compute g^-m mod N; après baby-step, gpow vaut g^m
    y=h
    for i in range(m) :
        if y in hashtable :
            return i*m+hashtable[y]
        y=(y*inv)%N
    
    raise OpensslError('Log not found')
"""    


def F(N, h, g, x) :
    mod=x%3
    if mod==0 :
        return (x*x) % N
    if mod==1 :
        return (x*g) % N    
    return (x*h) % N

def G(x, a, q) :
    mod=x%3
    if mod==0 :
        return (a+a) % q
    if mod==1 :
        return (a+1) % q    
    return a%q

def H(x, b, q) :
    mod=x%3
    if mod==0 :
        return (b+b) % q
    if mod==1 :
        return b%q    
    return (b+1)%q
    
def pollardrhobrent(h, g, q, N) :
    """ Polllard rho algorithm for discrete log
        >>> h : element of the group
        >>> g : generator of the group
        >>> q : a prime number, q is the order of the group
        >>> N : the modulus
        >>> out : x such that h = g^x mod p
    """
    print('Execution of pollard rho for discrete log...')
    a=A=0
    b=B=0
    x=X=2
    while True :
        prec=x
        x=F(N, h, g, x)
        a=G(prec, a, q)
        b=H(prec, b, q)
        
        prec=X
        X=F(N, h, g, X)
        A=G(prec, A, q)
        B=H(prec, B, q)
        
        prec=X
        X=F(N, h, g, X)
        A=G(prec, A, q)
        B=H(prec, B, q)
        
        if x==X :
            print('Detected!!!')
            subB = (B-b) % q
            if subB==0:
                raise OpensslError('Failure with r=0!!!')
#            gc = gmpy2.gcd(subB, q)
#            if(gc != 1):
#                print("gcd is different than 1")
#                print(subB)
            res=(gmpy2.invert(subB, q) * (a-A)) % q
            print('Discrete Log found : ', res)
            return res

def crt(modulus, reminds, N) :
    """compute the crt of x=reminds_i mod modulus_i
        N := prod(modulus[i])
    """
    _sum=0
    for i in range(len(modulus)) :
        bi=N//modulus[i]
        ai=euclideE(bi, modulus[i])
        _sum=(_sum+reminds[i]*bi*ai)%N
    return _sum

def fullcrt(modulus, reminds, N) :
    """compute the full crt of x=reminds_i mod modulus_i^ei
        N := prod(modulus[i]^ei)
    """
    _sum=0
    for i in range(len(modulus)) :
        mod=pow(modulus[i][0], modulus[i][1], N)
        bi=N//mod
        ai=euclideE(bi, mod)
        _sum=(_sum+reminds[i]*bi*ai)%N
    return _sum

def rho_crtForDSA(y, q, g, p) :
    """ rho Pohlig–Hellman algorithm for log discrete. 
        Only for when all factors of the prime number (q) are distincts
    >>> y : element of the group
    >>> g : generator of the group
    >>> q : a prime number, q is the order of the group
    >>> p : the modulus
    >>> out : xi such that yi = gi^xi mod qi
    """
    #factorisation of q
    print('-------------Finding all prime factors of q with Brent...')
    facts=brentMultipleFactors(q)
    print('Factors of q:', facts)
   
    #for test
    res = 1
    for x in facts:
        res *= x
    assert(res == q)
    
    #finding xi such as x=xi mod qi
    xi=[0] * len(facts)
#    xi[0]=98699490457#xi[1]=5765645707541#xi[2]=4726762747214#xi[3]=3364793818732#xi[4]=4967610363304#xi[5]=12389327632936
    
    for i in range(len(facts)) :
        print('-------------Finding x'+str(i)+' with Pollard rho for DL...')
        #prod of qj without qi
        prod=q//facts[i]
        _y= pow(y, prod, p)
        _g= pow(g, prod, p)
        xi[i]=pollardrhobrent(_y, _g, facts[i], p)
        
        assert(pow(_g, xi[i], p) == _y)

    
    #crt to reconstruct x
    #x = x0 mod q0
    #x = x1 mod q1
    #...
    #x = xn mod qn
    #with q0*q1*...*qn=q
    # -> crt to find x mod q0*q1*q2*...*qn = x mod q (qi are coprimes)
    print('-------------Finding x with CRT...')
    res=crt(facts, xi, q)
    return res

def subpohligprimepower(h , g, p, e, mod) :
    """Pohlig–Hellman algorithm applied to the specific case for groups whose order is a prime power
    >>> h : element of the group
    >>> g : generator of the group
    >>> p : a prime power, p^e is the order of the group
    >>> mod : the modulus
    >>> out : x such that h = g^x mod p^e
    """
    n=pow(p, e, mod)
    xk=0
    gamma=pow(g, pow(p, e-1, n), mod)
    for k in range(e) :
        gpow=pow(g, xk, mod)
        hk=pow(gmpy2.invert(gpow, mod)*h, pow(p, e-1-k, n), mod) #hk <- ((g^-x_k)*h)^(p^(e-1-k))
        dk=pollardrhobrent(hk, gamma, p, mod)
        xk=(xk+pow(p, k, mod)*dk)%n
    return xk


def dlg_fullpohlighellman(y, q, g, p) :
    """Full Pohlig–Hellman algorithm applied for discrete log when q can have multiple identique factors
    >>> y : element of the group
    >>> q : order of the group
    >>> g : generator of the group
    >>> p : a prime number, the modulus
    >>> out : x such that y = g^x mod p
    """
    print('-------------Finding all prime factors of q with Brent...')
    facts=brentMultipleFactors(q)
    dis_facts=[] #distincts factors of q
    e=1
    i=0
    while i<len(facts)-1 :
        while(i<len(facts)-1 and facts[i]==facts[i+1]) :
            e+=1
            i+=1
        dis_facts+=[(facts[i], e)]
        e=1
        i+=1
    if i<len(facts) :
       dis_facts+=[(facts[i], 1)]
    print('Factors of q:', dis_facts)
    
    xi=[0] * len(dis_facts)
    
    for i in range(len(dis_facts)) :
        print('-------------Finding x'+str(i)+' with Pollard rho for DL...')
        #prod of qj without qi^ei
        prod=q//pow(dis_facts[i][0], dis_facts[i][1], p)
        _y= pow(y, prod, p)
        _g= pow(g, prod, p)

        xi[i]=subpohligprimepower(_y, _g, dis_facts[i][0], dis_facts[i][1], p)
        
        assert(pow(_g, xi[i], p) == _y)
    
    
    print('-------------Finding x with CRT...')
    res=fullcrt(dis_facts, xi, q)
    return res


def cf_expansion(n, d):
    """This algorithm calculates the continued fraction expansion 
        of a rational number with nominator n and denominator d
        The return is [a0, a1, ..., an] such that n/d = a0 + 1 / (a1 + 1 / (a2 + 1 / (... + 1 / (an-1 + an)...)))
    """
    e = []
    q = n // d
    r = n % d
    e.append(q)

    while r != 0:
        n, d = d, r
        q = n // d
        r = n % d
        e.append(q)

    return e

def convergents(e):
    """This algorithm calculates the convergents of a continued fraction expansion 
        e=[a0,a1,…,an]
    """
    n = [] # Nominators
    d = [] # Denominators

    for i in range(len(e)):
        if i == 0:
            ni = e[i]
            di = 1
        elif i == 1:
            ni = e[i]*e[i-1] + 1
            di = e[i]
        else: # i > 1
            ni = e[i]*n[i-1] + n[i-2]
            di = e[i]*d[i-1] + d[i-2]
        n.append(ni)
        d.append(di)
        yield (ni, di)
    #return n,dverify_sign('police/hush/dillonlambert_pk.pem','pLvYvgpez+9wXC797rPL2rSwYNrxt4HL8XE+91lxmrMUiAjq0TckCCt/PJ5lqtW+8Vc6SRDkefJm2eqeYSNvMq3FBt3XDA9VzZ7qUjiN2xXIRcvXbrc7kKk+Tc/D/rreciyKuZut8gW0a/gpyM2cVD7UqGzljoEBnXyN/rioelT/P5Bg5f61U3LikdZvsP64bpa0nosTD3q9ZHdyhPZ6e7Wxi51jp+twEu6WD5D+3WMEYCwJqdyIFMh9fFQBiW2IxkTOI3ofheN4PyEZO7bXOl9t0EHocFqTzzF4i4LNn10RoQfy7iwk9R5poOyWfwS/qys3OIyrtjCRuCl4pggodw==', 'manger')

def wienerAttack(e, N) :
    print('[-] Finding the continued fractions expansion convergents of e/N...')
    cf_exp= cf_expansion(e, N)
    cvgts= convergents(cf_exp)
    print('[+] continued fractions expansion convergents found')
    print(cf_exp)

    print('[-] Iterating over convergents; '
            'Testing correctness through factorization.')
    for pk, pd in cvgts: # pk - possible k, pd - possible d
        if pk == 0:
            continue;
        possible_phi = (e*pd - 1)//pk
        p = sympy.Symbol('p', integer=True)
        roots = sympy.solve(p**2 + (possible_phi - N - 1)*p + N, p)

        if len(roots) == 2:
            pp, pq = roots # pp - possible p, pq - possible q
            if pp*pq == N:
                print('[+] Factoriisation of N found : p,q = (', pp, ',', pq, ')')
                return pp,pq

    print('[-] Wiener\'s Attack failed; Factoriisation not found :(')
    

"""------------------------------BEGIN TRAINING------------------------------"""
    
def train_eqlin(a, b, n) :
    """return X such that a * X + b  ==  0  [modulo n]
        and X is known existed
    """
    # aX + b = 0 mod n => aX = -b mod n
    return gmpy2.divm(-b, a, n)

def train_generator(q, a, b) :
    """find G such taht G must be a generator of order q modulo P.
        P must be prime, and such that a <= P < b.
    """
    k= math.ceil(a//q) #for q multiple > a
    p = a
    while p < b-1 :
        qm = q*k #multiple of q between a and b
        p = qm + 1
        if gmpy2.is_prime(p) :
            print('[+] p-1 multiple of q found...')
            #rs = gmpy2.random_state(hash(gmpy2.random_state()))
            h = 2#+int(gmpy2.mpz_random(rs, p-4)) # random g in [2, p-2]
            g = pow(h, (p-1)//q, p)
            if pow(g, q, p)==1 :
                print('[+] Generator G =', g, 'with P =', p, 'found')
                return g,p
            
        print('[-] Failed ! Trying with next multiple of q...')
        k+=1
    
    print('[-] Failed to find generator')
    raise ValueError()
    
def train_sqrt_modp(x, p) :
    """Find the two square roots of x modulo p,
        convert them to bytes and print them.
    """
    roots=sympy.sqrt_mod(x, p, all_roots=True)
    return (base64.b16decode(hex(roots[0])[2:], casefold=True), 
            base64.b16decode(hex(roots[1])[2:], casefold=True))
    
def train_rsa_reduction(n, e, d) :
    """You are given an RSA secret key.
        Find p and q and convert them to bytes
        
        code from : https://gist.github.com/ddddavidee/b34c2b67757a54ce75cb
    """
    k = d * e - 1
    if gmpy2.is_odd(k) :
        raise ValueError('Prime factors p and q not found')
    else:
        t = 0
        r = k
        while(not gmpy2.is_odd(r)):
            r = int(r // 2)
            t += 1
        for i in range(1, 101):
            rs = gmpy2.random_state(hash(gmpy2.random_state()))
            g = int(gmpy2.mpz_random(rs, n)) # random g in [0, n-1]
            y = pow(g, r, n)
            if y == 1 or y == n - 1:
                continue
            else:
                for j in range(1, t): # j \in [1, t-1]
                    x = pow(y, 2, n)
                    if x == 1:
                        p, q = outputPrimes(y - 1, n)
                        return (base64.b16decode(hex(p)[2:], casefold=True), 
                                base64.b16decode(hex(q)[2:], casefold=True))
                    elif x == n - 1:
                        continue
                    y = x
                    x = pow(y, 2, n)
                    if  x == 1:
                        p, q = outputPrimes(y - 1, n)
                        return (base64.b16decode(hex(p)[2:], casefold=True), 
                                base64.b16decode(hex(q)[2:], casefold=True))

def outputPrimes(a, n):
    p = int(gmpy2.gcd(a, n))
    q = int(n // p)
    if p > q:
        p, q = q, p
    return p,q    

def train_rsa_malleability(n, e, C, Ci, Ma) :
    """ Algo description on https://crypto.stackexchange.com/questions/2323/how-does-a-chosen-plaintext-attack-on-rsa-work
        
        You are given an RSA public-key (n, e) and a ciphertext (C).
        If you provide a **different** ciphertext (Ca =! C), it will be decrypted.
        You must decrypt, convert to bytes and print the original text
        
        This is an Chosen-plaintext attack
        
        >>> n, e : public Key (modulus and exponent)
        >>> C : the ciphertext to break
        >>> Ci : The chosen ciphertext (without the pow 2) by attacker sent to Alice
            exple : if the ciphertext sent is 2^e, Ci=2
        >>> Ma : The plaintext corresponding to Ca (decrypted by Alice)
        
        Output : the plaintext corresponding to C
    """
    #We know C = t^e mod n
    #we chose Ci=2^e and send Ca = Ci*C = 2^e * t^e = (2*t)^e
    #Alice will decrypt and will send us Ma = ((2*t)^e)^d = 2*t
    return (base64.b16decode(hex(Ma//Ci)[2:], casefold=True))

def train_rsa_msb(LB) :
    """Obtain and print the plaintext with given an RSA public-key 
        (the modulus n, the exponent e) and a ciphertext c.
        An oracle is available :
        If you provide a ciphertext, you will be given the MSB
        of the plaintext (i.e. True when plaintext >= n/2)
    """
    #Let c the ciphertext and P the corresponding plaintext
    # rsa_msb c -> 0 => P < n/2
    # rsa_msb 2^e * c -> 0 => 2*P < n/2 => P < n/4
    #...
    #(applying successive dichotomie log2n * 2 time, we find LB<=P<=UB and LB==UB)
    #See train_rsa_msb/msb_client.py and train_rsa_msb/msb_netringsEncrypt.py
    #and execute :
    #>>> python3 train_rsa_msb/msb_client.py
    print(base64.b16decode(hex(LB)[2:], casefold=True))

"""------------------------------END TRAINING------------------------------"""


def DSAregenK(p, q, g, y, r, s1, s2, file_msg1, file_msg2) :
    """Recover the private key (x) of signed DSA messages with weak random k : k is not unique for all message
        Here, k is the same for the both message so r1 = r2 = r
        >>> p, q, g, y : the DSA public Key of the signed messages param
        >>> r, s1 : DSA signature of the message m1
        >>> r, s2 : DSA signature of the message m2
        >>> file_msg1, file_msg2 : files to message m1 and m2
        
        #exec : DSAregenK(int('BDADCF08B14F1D0F2916BAF99BFE906C83F3CAACC8438ED19DCAB0E2B802AE720638E51084B3DE6A7971F397A996BA8ECF7D8304EA7BE78EFFD526B14AE6C38BE169D185AB5AAD5BFADCDDECB2901F6E1B6579254FBDC259FB06FAF6CED8A9AA77F26447C816EA66C39282186291BB53DF42AC4218945C1ABCEFD6C007C8CA5FD39F72D1409E0680E2F82CE95C0EC350A0C6AE78E531F24388783591E51620B91215F5A9E1544AACE24A9223DAFF437CEF375372A408F8091835AD55DDE1877A9AF30B6E625319C262105B62296FDB47238DDC08F3BC8B089BDB3AA528D6A52DC2323E18B9A6B9821CE81C3010BA3CE02DEF6E44CEF5529F20BF1C63004D9251', base=16), 
        int('B44525D1BEBCD9D5DDB7FE84EE71A9117DC312173D3C96645A534E397F7BA395', base=16), 
        int('4A9F9831BAE9D9E5A2FF813D1D69DEC22609A2C81F46057562D20DD15C4B398EC80C45AEB801021BD9CC2F3DE3EB59C556ADC6C83C791053EA4256FB44ECA40CD0F870F39B07CB973AED2348082B16347929892A7E80ED5E1DB6D55250B5A6BE245BC9F89431EBC79C0FF1FEDFAFC157CD12380F5FCBF34F1A64A59954CA1F8EE08F6E128E732297A481399A95C3F2540D40185AFB81816D727F39DF922DF2F6CEEB9FF35E1BC177B2009B6776D14EB9C2CF62B595925ED76C5545FD1968F76DCF25D9C80E0F319282407A499352AB9FE2D04A1323CE18B54C17998F3B851FCDAA9DE59CD0AD6350474BA4A6A6F591E069AE39A3068291D1486B7C6B0D14FB5A', base=16), 
        int('04527386FE97790AAD1E70016010CF096022656AE7A36232D257DBE97267189DF8C8FC7D0237E34CAB3747D66AF095384FF6C8D2F9337B99359F27A8FD194DA6B21AE5292010D30D6711215EDC9FD95DD47506A6584AEE4CE519248BC02F4F0AFE61B5C96C340D5F2B3B39B2FEF5BD40365DA8E6767793C0486C141CDE0A01397EF5848E11408CADB96B7248916295967FA515ACC4BC48DD35913B8D3F2C0CE117EFC153557C022AC89A219BE5EDE1ECA847D63C23E35A225D4ACF18E5896E8F6181B501F738A902F4EE7529080E327D05106A498E87212CABCA4DDB69F48DA04EDBE7C9B7E69D97A12E341EC88F7A1BDEB118E31C1CB296674C4488282F1BB9', base=16), 
        int('268F889EA93CD3DC56B69FB5CBDF2C486F8886B0647928B685C52DEAF30A6A0F', base=16), 
        int('71059E7D7464D41121BB55F5E918CC985F3E1AB9CFDA971FA08A30BD9C069184', base=16), 
        int('6F64140C9A928461FA74EE7EF9312ECFDAE5B1589DA835E04BF11200FCAA2E8A', base=16), 
        'inHushTodo/murphykimberly_m1.txt', 'inHushTodo/murphykimberly_m2.txt')
    """
    #loading message from files
    with open(file_msg1) as f:
        msg1 = f.read()
        f.closed
    with open(file_msg2) as f:
        msg2 = f.read()
        f.closed
        
    h1 = int(sha256(msg1.encode()).hexdigest(), base=16)
    h2 = int(sha256(msg2.encode()).hexdigest(), base=16)
    #we have : r1 = (g^k1 mod p) mod q and r2 = (g^k2 mod p) mod q
    #if r1 == r2 -> (g^k1 mod p) mod q == (g^k2 mod p) mod q -> k1 == k2
    #so r1 = r2 = k and k1 = k2 = k
    
    #we also have : s1 = k^(-1)*h1 + xr  ->  s1*k = h1 + xr (1.1)
    #and s2 = k^(-1)*h2 + xr  ->  s2*k = h2 + xr (1.2)
    #GAUSSIAN ELIMINATION
    # s1*k/r = h1/r + x mod q (dividing 1.1 by r) (2.1)
    # s2*k - s1*k = h2 - h1 mod q (Subtract 2.1 times r2 from 1.2) (2.2)

    #NEXT step
    # k = (h2 - h1) / (s2 - s1) (dividing 2.2 by (s2 - s1))
    k = ((h2 - h1) * euclideE(s2 - s1, q)) % q

    # x = s1*k/r - h1/r mod q (Swap terms of 2.1)
    inv_r=euclideE(r, q)
    x = ((s1 * k) * inv_r  -  h1 * inv_r) % q
    
    assert(y == pow(g, x, p))
    
#    print(p, q, g)   
    return x