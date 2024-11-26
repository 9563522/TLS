import os
from Crypto.Util.number import getPrime
import gmpy2
import oqs
from AES import AESUtils
from GM import GoldwasserMicali

def lattice_key_exchange():
    alice_kem =oqs.KeyEncapsulation ("Kyber512")
    alice_public_key = alice_kem.generate_keypair()

    bob_kem = oqs.KeyEncapsulation("Kyber512")
    ciphertext, shared_secret_bob = bob_kem.encapsulate(alice_public_key)


    shared_secret_alice = alice_kem.decapsulate(ciphertext)

    assert shared_secret_alice == shared_secret_bob, "密钥协商失败！"

    print("密钥协商成功！共享密钥为：", shared_secret_alice.hex())
    return shared_secret_alice

def communicate():
    shared_key = lattice_key_exchange()

    aes = AESUtils(shared_key[:32])  

    plaintext = "Let's learn Crypto together, this is A!"
    aes_encrypted = aes.encrypt(plaintext)
    print(f"A sends AES encrypted message: {aes_encrypted}")

    decrypted_text = aes.decrypt(aes_encrypted)
    print(f"B decrypts AES message: {decrypted_text}")

    p = getPrime(1024)
    q = gmpy2.next_prime(p)
    gm = GoldwasserMicali(p, q)

    bit_message = 1 
    gm_encrypted = gm.encrypt_bit(bit_message)
    print(f"B sends GM encrypted bit: {gm_encrypted}")

    decrypted_bit = gm.decrypt_bit(gm_encrypted)
    print(f"A decrypts GM bit: {decrypted_bit}")

if __name__ == "__main__":
    communicate()
