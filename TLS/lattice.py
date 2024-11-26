from pqcrypto.kem import kyber, generate_keypair, encrypt, decrypt
import os

# ----------------------------
# 客户端：生成自己的格基密钥对
# ----------------------------
def client_generate_keys():
    client_public_key, client_private_key = generate_keypair()
    print("客户端密钥生成完成")
    return client_public_key, client_private_key

# ----------------------------
# 服务器：生成自己的格基密钥对
# ----------------------------
def server_generate_keys():
    server_public_key, server_private_key = generate_keypair()
    print("服务器密钥生成完成")
    return server_public_key, server_private_key

# ----------------------------
# 测试流程：客户端和服务器共享密钥
# ----------------------------
def test_lattice_key_exchange():
    # 客户端生成密钥对
    client_public_key, client_private_key = client_generate_keys()

    # 服务器生成密钥对
    server_public_key, server_private_key = server_generate_keys()

    # 服务器加密一个随机的会话密钥，发送给客户端
    shared_secret = os.urandom(32)  # 模拟会话密钥
    ciphertext, server_shared_secret = encrypt(client_public_key)

    # 客户端解密服务器发送的密钥
    client_shared_secret = decrypt(client_private_key, ciphertext)

    # 验证密钥是否一致
    assert server_shared_secret == client_shared_secret, "密钥不匹配！"

    print("密钥协商成功，生成的共享密钥为：", server_shared_secret.hex())


# 执行测试
test_lattice_key_exchange()
