import os
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import  padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as padding_module
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend

def load_private_key(filename):
    with open(filename, "rb") as f:
        return load_pem_private_key(f.read(), password=None, backend=default_backend())

def load_public_key(filename):
    with open(filename, "rb") as f:
        return load_pem_public_key(f.read(), backend=default_backend())

def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding_module.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding_module.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

def generate_hash(message):
    return sha256(message).digest()

def sign_message(private_key, message):
    return private_key.sign(
        message,
        padding.PKCS1v15(),
        SHA256())

def verify_signature(public_key, message, signature):
    try:
        public_key.verify(signature, message, SHA256())
        return True
    except Exception:
        return False


def secure_transfer():
    sender_private_key = load_private_key("ca_rsa_key.pem")
    sender_public_key = sender_private_key.public_key()

    message = b"Let's learn Crypto together!"

    print("[Sender] Encrypting the message using AES...")
    aes_key = os.urandom(32)
    ciphertext = aes_encrypt(aes_key, message)
    print(f"Ciphertext (AES Encrypted): {ciphertext.hex()}")

    print("[Sender] Generating hash of the message...")
    message_hash = generate_hash(message)
    print(f"Message Hash: {message_hash.hex()}")

    print("[Sender] Signing the hash using DSA...")
    signature = sign_message(sender_private_key, message_hash)
    print(f"Signature: {signature.hex()}")

    transmitted_data = {
        "ciphertext": ciphertext,
        "aes_key": aes_key,
        "signature": signature,
        "hash": message_hash,
        "public_key": sender_public_key,
    }

    print("\n[Receiver] Verifying and decrypting the received data...")
    receiver_public_key = transmitted_data["public_key"]
    received_ciphertext = transmitted_data["ciphertext"]
    received_aes_key = transmitted_data["aes_key"]
    received_signature = transmitted_data["signature"]
    received_hash = transmitted_data["hash"]

    decrypted_message = aes_decrypt(received_aes_key, received_ciphertext)
    print(f"Decrypted Message: {decrypted_message.decode()}")


if __name__ == "__main__":
    secure_transfer()




     #hashlib
#sha256
'''
#1. 定义常量

# 初始哈希值，共8个32位整数，对应算法中的H0 - H7
initial_hash_values = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

# 每轮使用的64个常量K
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

#2. 定义辅助函数
def right_rotate(x, n):
    """
    循环右移函数，将整数x向右循环移动n位
    """
    return (x >> n) | (x << (32 - n))


def sigma0(x):
    """
    对应算法中的sigma0函数，进行特定的位运算组合
    """
    return right_rotate(x, 2) ^ right_rotate(x, 13) ^ right_rotate(x, 22)


def sigma1(x):
    """
    对应算法中的sigma1函数，进行特定的位运算组合
    """
    return right_rotate(x, 6) ^ right_rotate(x, 11) ^ right_rotate(x, 25)


def gamma0(x):
    """
    对应算法中的gamma0函数，进行特定的位运算组合
    """
    return right_rotate(x, 7) ^ right_rotate(x, 18) ^ (x >> 3)


def gamma1(x):
    """
    对应算法中的gamma1函数，进行特定的位运算组合
    """
    return right_rotate(x, 17) ^ right_rotate(x, 19) ^ (x >> 10)


def ch(x, y, z):
    """
    选择函数，用于根据条件选择不同的值
    """
    return (x & y) ^ ((~x) & z)


def maj(x, y, z):
    """
    多数函数，进行特定的位逻辑运算组合
    """
    return (x & y) ^ (x & z) ^ (y & z)


#3. 数据填充函数

def pad_message(message):
    """
    对输入消息进行填充，使其长度符合SHA256算法要求
    """
    # 将消息转换为字节串（如果不是字节串的话）
    if isinstance(message, str):
        message = message.encode('utf-8')

    # 记录原始消息长度（单位：位）
    message_length = len(message) * 8
    # 先添加一个1位，再添加若干个0位，直到消息长度对512取模余数为448
    message += b'\x80'
    while (len(message) * 8) % 512!= 448:
        message += b'\x00'
    # 添加64位表示原始消息长度的二进制值
    message += message_length.to_bytes(8, 'big')
    return message


#4. 消息处理函数（分块处理及压缩）

def process_blocks(message):
    """
    将填充后的消息划分成块，对每块进行处理并更新哈希值
    """
    hash_values = initial_hash_values.copy()
    for i in range(0, len(message), 64):
        block = message[i:i + 64]
        w = [int.from_bytes(block[j:j + 4], 'big') for j in range(0, 64, 4)]

        # 扩展消息字数组，从16个扩展到64个
        for j in range(16, 64):
            w.append((gamma1(w[j - 2]) + w[j - 7] + gamma0(w[j - 15]) + w[j - 16]) & 0xFFFFFFFF)

        a, b, c, d, e, f, g, h = hash_values

        # 进行64轮的压缩运算
        for j in range(64):
            t1 = (h + sigma1(e) + ch(e, f, g) + K[j] + w[j]) & 0xFFFFFFFF
            t2 = (sigma0(a) + maj(a, b, c)) & 0xFFFFFFFF
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


#5. 主函数（对外提供的 SHA256 计算接口）

def my_sha256(message):
    """
    模拟计算消息的SHA256哈希值的主函数
    """
    padded_message = pad_message(message)
    hash_result = process_blocks(padded_message)
    # 将最终的哈希值转换为字节串输出，共32字节
    return b''.join([i.to_bytes(4, 'big') for i in hash_result])
'''