from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

class AESUtils:
    def __init__(self, key: bytes):
        self.key = key
        self.block_size = AES.block_size

    def encrypt(self, plaintext: str) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), self.block_size))
        return cipher.iv + ciphertext

    def decrypt(self, ciphertext: bytes) -> str:
        iv = ciphertext[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext[self.block_size:]), self.block_size)
        return plaintext.decode()
