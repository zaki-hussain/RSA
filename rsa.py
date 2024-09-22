import random
import math

class RSA:
    def __init__(self, key_size):
        while True:
            self.p = self.generate_prime(key_size // 2)
            self.q = self.generate_prime(key_size // 2)
            self.n = self.p * self.q
            self.phi_n = self.eulers_totient(self.p, self.q)
            self.e = 65537 #65537 is frequently used as the public key
            if math.gcd(self.e, self.phi_n) == 1:
                '''
                I hard coded a value for e, but e and phi_n need to be coprime
                As 65537 is prime, the chances of this are very rare
                In the case that it does happen, we can just generate new prime numbers, which will give a different value for phi_n
                '''
                break
        self.d = self.modular_inverse(self.e, self.phi_n)

    def generate_prime(self, length):
        number = int.from_bytes(random.randbytes(length))
        while self.miller_rabin(number) == False:
            number = int.from_bytes(random.randbytes(length))
        return number
    
    def miller_rabin(self, n, k=40):
        # even numbers won't be prime
        if n % 2 == 0:
            return False
        
        # d and s are chosen such that (2**s) * d = n - 1 and d is odd
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1

        # Loop is done k times as this primality test is based on probability
        for i in range(k):
            a = random.randrange(2, n-1)
            # a is the base and is picked at random
            x = pow(a, d, n)

            if x == 1 or x == n-1:
                # because d is a factor of n-1 and a**(n-1) ≡ 1 (mod n) when prime
                # n-1 is there because that's the same as -1 which squares to become 1
                continue

            for j in range(s-1):
                # 2 ** s goes into n-1
                x = pow(x, 2, n)
                if x == n-1:
                    break

            else:
                return False
        return True

    def eulers_totient(self, p, q):
        return (p - 1) * (q - 1)

    def modular_inverse(self, a, b):
        # ax + my = gcd(a,m) = 1
        # ax ≡ 1 - my (mod m)
        # my (mod m) ≡ 0
        # ax ≡ 1 (mod m)

        initial_b = b
        x0 = 1
        x1 = 0

        while a > 1:
            x0, x1 = x1 - (b // a) * x0, x0 # like last part when done by hand
            b, a = a, b % a # like first part when done by hand

        return x0 % initial_b
    
    def encrypt(self, m):
        c = pow(m, self.e, self.n)
        return c
    
    def decrypt(self, c):
        m = pow(c, self.d, self.n)
        return m


rsa = RSA(256)
original = int(input("Enter number to be encrypted: "))

ciphertext = rsa.encrypt(original)
print("Encrypted: " + str(ciphertext))

plaintext = rsa.decrypt(ciphertext)
print("Decrypted: " + str(plaintext))
