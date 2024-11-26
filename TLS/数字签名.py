from Crypto.PublicKey import DSA, ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import os

def generate_dsa_keys():
    dsa_key = DSA.generate(1024)
    return dsa_key, dsa_key.publickey()

def dsa_sign(message, private_key):
    hash_obj = SHA256.new(message)
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(hash_obj)
    return signature

def dsa_verify(message, signature, public_key):
    hash_obj = SHA256.new(message)
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(hash_obj, signature)
        return True
    except ValueError:
        return False

def generate_ecdsa_keys():
    ecdsa_key = ECC.generate(curve='P-256')
    return ecdsa_key, ecdsa_key.public_key()

def ecdsa_sign(message, private_key):
    hash_obj = SHA256.new(message)
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(hash_obj)
    return signature

def ecdsa_verify(message, signature, public_key):
    hash_obj = SHA256.new(message)
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(hash_obj, signature)
        return True
    except ValueError:
        return False

def main():
    message = b"Let's learn Crypto together!"


    dsa_private_key, dsa_public_key = generate_dsa_keys()
    dsa_signature = dsa_sign(message, dsa_private_key)
    print("DSA 签名:", dsa_signature.hex())

    dsa_valid = dsa_verify(message, dsa_signature, dsa_public_key)
    print("DSA 验证结果:", dsa_valid)


    ecdsa_private_key, ecdsa_public_key = generate_ecdsa_keys()
    ecdsa_signature = ecdsa_sign(message, ecdsa_private_key)
    print("ECDSA 签名:", ecdsa_signature.hex())

    ecdsa_valid = ecdsa_verify(message, ecdsa_signature, ecdsa_public_key)
    print("ECDSA 验证结果:", ecdsa_valid)


    if dsa_valid and ecdsa_valid:
        print("消息通过 DSA 和 ECDSA 双重验证！")
    else:
        print("消息验证失败！")

if __name__ == "__main__":
    main()



    #Crypto.PublicKey
#RSA
'''import random


def gcd(a, b):
    while b!= 0:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)


def mod_inverse(a, m):
    g, x, y = extended_gcd(a, m)
    if g!= 1:
        raise Exception('No modular inverse')
    return x % m


def generate_prime(bits):
    while True:
        candidate = random.getrandbits(bits)
        if candidate % 2 == 0:
            candidate += 1
        if is_prime(candidate):
            return candidate


def is_prime(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_rsa_keys(bits=1024):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = random.randint(1, phi_n)
    while gcd(e, phi_n)!= 1:
        e = random.randint(1, phi_n)
    d = mod_inverse(e, phi_n)
    return ((e, n), (d, n))


def rsa_encrypt(public_key, plaintext):
    e, n = public_key
    ciphertext = [pow(ord(char), e, n) for char in plaintext]
    return ciphertext


def rsa_decrypt(private_key, ciphertext):
    d, n = private_key
    plaintext = [chr(pow(char, d, n)) for char in ciphertext]
    return ''.join(plaintext)'''



#DSA
'''import hashlib
import random



def is_prime(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    while True:
        candidate = random.getrandbits(bits)
        if candidate % 2 == 0:
            candidate += 1
        if is_prime(candidate):
            return candidate
        

def generate_dsa_parameters():
    q = generate_prime(160)
    p = generate_prime(1024)
    g = find_generator(p, q)
    return p, q, g


def find_generator(p, q):
    while True:
        h = random.randint(2, p - 1)
        g = pow(h, (p - 1) // q, p)
        if g > 1:
            return g


def generate_dsa_keys(p, q, g):
    x = random.randint(1, q - 1)
    y = pow(g, x, p)
    return (x, (y, p, q, g))


def dsa_sign(private_key, message,public_key):
    x = private_key
    y, p, q, g = public_key
    k = random.randint(1, q - 1)
    r = pow(g, k, p) % q
    hash_m = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    s = (pow(k, -1, q) * (hash_m + x * r)) % q
    return (r, s)

def mod_inverse(a, m):
    g, x, y = extended_gcd(a, m)
    if g!= 1:
        raise Exception('No modular inverse')
    return x % m

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def dsa_verify(public_key, message, signature):
    y, p, q, g = public_key
    r, s = signature
    hash_m = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    w = mod_inverse(s, q)
    u1 = (hash_m * w) % q
    u2 = (r * w) % q
    v = (pow(g, u1, p) * pow(y, u2, p)) % p % q
    return v == r'''

#ECDSA
'''import random
import hashlib

def mod_inverse(a, m):
    g, x, y = extended_gcd(a, m)
    if g!= 1:
        raise Exception('No modular inverse')
    return x % m

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def point_addition(P, Q, a, p):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 == -y2:
        return None
    if P == Q:
        lam = (3 * (x1 ** 2)+a) * mod_inverse(2 * y1, p)
    else:
        lam = (y2 - y1) * mod_inverse(x2 - x1, p)
    x3 = (lam ** 2 - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def scalar_multiplication(k, P, a, p):
    Q = None
    while k > 0:
        if k % 2 == 1:
            Q = point_addition(Q, P, a, p)
        P = point_addition(P, P, a, p)
        k //= 2
    return Q


def generate_ecc_keys(a, b, p, n, G):
    d = random.randint(1, n - 1)
    Q = scalar_multiplication(d, G, a, p)
    return (d, (Q, a, b, p, n, G))


def ecc_sign(private_key, message, a, b, p, n, G):
    d = private_key
    k = random.randint(1, n - 1)
    R = scalar_multiplication(k, G, a, p)
    r = R[0] % n
    hash_m = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    s = (mod_inverse(k, n) * (hash_m + d * r)) % n
    return (r, s)


def ecc_verify(public_key, message, signature, a, b, p, n, G):
    Q, a, b, p, n, G = public_key
    r, s = signature
    hash_m = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    w = mod_inverse(s, n)
    u1 = (hash_m * w) % n
    u2 = (r * w) % n
    X = point_addition(scalar_multiplication(u1, G, a, p),
                       scalar_multiplication(u2, Q, a, p), a, p)
    v = X[0] % n
    return v == r'''


#ECC
'''
#生成ECC 密钥对
import random


def generate_ecc_keys(a, b, p, n, G):
    d = random.randint(1, n - 1)
    Q = scalar_multiplication(d, G, a, p)
    return (d, (Q, a, b, p, n, G))

#定义椭圆曲线上的点和运算
def point_addition(P, Q, a, p):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 == (-y2):
        return None
    if P == Q:
        lam = ((3 * (x1 ** 2)+a) * pow(2 * y1, -1, p)) % p
    else:
        lam = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
    x3 = (lam ** 2 - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def scalar_multiplication(k, P, a, p):
    Q = None
    while k > 0:
        if k % 2 == 1:
            Q = point_addition(Q, P, a, p)
        P = point_addition(P, P, a, p)
        k //= 2
    return Q

    #ECDSA签名
    import hashlib


def ecc_sign(private_key, message, a, b, p, n, G):
    d = private_key
    k = random.randint(1, n - 1)
    R = scalar_multiplication(k, G, a, p)
    r = R[0] % n
    hash_m = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    s = (pow(k, -1, n) * (hash_m + d * r)) % n
    return (r, s)
    

   # ECDSA 验证
    def ecc_verify(public_key, message, signature, a, b, p, n, G):
    Q, a, b, p, n, G = public_key
    r, s = signature
    hash_m = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    w = pow(s, -1, n)
    u1 = (hash_m * w) % n
    u2 = (r * w) % n
    X = point_addition(scalar_multiplication(u1, G, a, p),
                       scalar_multiplication(u2, Q, a, p), a, p)
    v = X[0] % n
    return v == r

    '''

     #Crypto.Signature
#DSS

'''
1.生成 DSA 参数
import random


def generate_prime(bits):
    while True:
        candidate = random.getrandbits(bits)
        if candidate % 2 == 0:
            candidate += 1
        if is_prime(candidate):
            return candidate


def is_prime(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_dsa_parameters():
    q = generate_prime(160)
    while True:
        p = generate_prime(1024)
        if (p - 1) % q == 0:
            break
    h = random.randint(2, p - 2)
    g = pow(h, (p - 1) // q, p)
    return p, q, g

    
    2.生成 DSA 密钥对
    def generate_dsa_keys(p, q, g):
    x = random.randint(1, q - 1)
    y = pow(g, x, p)
    return (x, (y, p, q, g))


    3.DSA 签名
    import hashlib


    def dsa_sign(private_key, message, p, q, g):
        x = private_key
        k = random.randint(1, q - 1)
        r = pow(g, k, p) % q
        hash_m = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        s = (pow(k, -1, q) * (hash_m + x * r)) % q
        return (r, s)


4.DSA 验证
def dsa_verify(public_key, message, signature, p, q, g):
    y, p, q, g = public_key
    r, s = signature
    hash_m = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    w = pow(s, -1, q)
    u1 = (hash_m * w) % q
    u2 = (r * w) % q
    v = (pow(g, u1, p) * pow(y, u2, p)) % p % q
    return v == r

    '''


  #Crypto.Hash
# SHA256
'''
#1.定义常量和辅助函数
initial_hash_values = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

def ch(x, y, z):
    return (x & y) ^ ((~x) & z)


def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def sigma0(x):
    return ((x >> 2) | (x << 30)) ^ ((x >> 13) | (x << 19)) ^ ((x >> 22) | (x << 10))


def sigma1(x):
    return ((x >> 6) | (x << 26)) ^ ((x >> 11) | (x << 21)) ^ ((x >> 25) | (x << 7))


def gamma0(x):
    return ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3)


def gamma1(x):
    return ((x >> 17) | (x << 15)) ^ ((x >> 19) | (x << 13)) ^ (x >> 10)


#2.数据填充函数

def pad_data(data):
    bit_length = len(data) * 8
    data += b'\x80'
    while (len(data) * 8) % 512!= 448:
        data += b'\x00'
    data += bit_length.to_bytes(8, 'big')
    return data

#3.压缩函数

def compress(block, hash_values):
    a, b, c, d, e, f, g, h = hash_values
    w = []
    for i in range(16):
        w.append(int.from_bytes(block[i * 4:(i + 1) * 4], 'big'))
    for i in range(16, 64):
        w.append((gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16]) & 0xFFFFFFFF)

    for i in range(64):
        t1 = (h + sigma1(e) + ch(e, f, g) + [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ][i] + sigma0(a) + maj(a, b, c)) & 0xFFFFFFFF
        t2 = (sigma1(e) + ch(e, f, g)) & 0xFFFFFFFF
        h = g
        g = f
        f = e
        e = (d + t1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (t1 + t2) & 0xFFFFFFFF

    hash_values[0] = (hash_values[0] + a) & 0xFFFFFFFF
    hash_values[1] = (hash_values[1] + b) & 0xFFFFFFFF
    hash_values[2] = (hash_values[2] + c) & 0xFFFFFFFF
    hash_values[3] = (hash_values[3] + d) & 0xFFFFFFFF
    hash_values[4] = (hash_values[4] + e) & 0xFFFFFFFF
    hash_values[5] = (hash_values[5] + f) & 0xFFFFFFFF
    hash_values[6] = (hash_values[6] + g) & 0xFFFFFFFF
    hash_values[7] = (hash_values[7] + h) & 0xFFFFFFFF

    return hash_values


#4.主函数

def sha256(data):
    data = pad_data(data)
    hash_values = initial_hash_values[:]
    for i in range(0, len(data), 64):
        block = data[i:i + 64]
        hash_values = compress(block, hash_values)
    hash_result = b''
    for hash_value in hash_values:
        hash_result += hash_value.to_bytes(4, 'big')
    return hash_result'''