from gmpy2 import mpz, powmod, isqrt, t_mod

class GoldwasserMicali:
    def __init__(self, p: int, q: int):
        self.p = mpz(p)
        self.q = mpz(q)
        self.n = self.p * self.q
        self.y = mpz(2)
        while powmod(self.y, (self.p - 1) * (self.q - 1) // 2, self.n) == 1:
            self.y += 1

    def encrypt_bit(self, bit: int) -> int:
        r = mpz.random_state().urandom(256)  # 随机数生成器
        r = t_mod(r, self.n)
        c = (powmod(r, 2, self.n) * powmod(self.y, bit, self.n)) % self.n
        return c

    def decrypt_bit(self, ciphertext: int) -> int:
        legendre_p = powmod(ciphertext, (self.p - 1) // 2, self.p)
        return 0 if legendre_p == 1 else 1
