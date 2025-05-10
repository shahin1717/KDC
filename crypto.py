# crypto.py (Updated)
import math
import random
from typing import Tuple
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

def generate_prime(min_value: int, max_value: int) -> int:
    prime = random.randint(min_value, max_value)
    while not is_prime(prime):
        prime = random.randint(min_value, max_value)
    return prime

def mod_inverse(e: int, phi: int) -> int:
    for d in range(3, phi):
        if (d * e) % phi == 1:
            return d
    raise ValueError("Mod inverse does not exist")

def generate_keypair() -> Tuple[Tuple[int, int], Tuple[int, int]]:
    try:
        p = generate_prime(100, 1000)
        q = generate_prime(100, 1000)
        while p == q:
            q = generate_prime(100, 1000)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = random.randint(3, phi - 1)
        while math.gcd(e, phi) != 1:
            e = random.randint(3, phi - 1)
        d = mod_inverse(e, phi)
        logger.debug(f"Generated keypair: public=({e}, {n}), private=({d}, {n})")
        return ((e, n), (d, n))  # (public_key, private_key)
    except Exception as e:
        logger.error(f"Error in generate_keypair: {str(e)}")
        raise

def rsa_encrypt(plaintext: int, public_key: Tuple[int, int]) -> int:
    try:
        e, n = public_key
        ciphertext = pow(plaintext, e, n)
        logger.debug(f"RSA encrypt: plaintext={plaintext}, ciphertext={ciphertext}")
        return ciphertext
    except Exception as e:
        logger.error(f"Error in rsa_encrypt: {str(e)}")
        raise

def rsa_decrypt(ciphertext: int, private_key: Tuple[int, int]) -> int:
    try:
        d, n = private_key
        plaintext = pow(ciphertext, d, n)
        logger.debug(f"RSA decrypt: ciphertext={ciphertext}, plaintext={plaintext}")
        return plaintext
    except Exception as e:
        logger.error(f"Error in rsa_decrypt: {str(e)}")
        raise

def caesar_encrypt(message: str, key: int) -> str:
    try:
        encrypted = ""
        for char in message:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                encrypted += chr((ord(char) - base + key) % 26 + base)
            else:
                encrypted += char
        logger.debug(f"Caesar encrypt: message={message}, key={key}, encrypted={encrypted}")
        return encrypted
    except Exception as e:
        logger.error(f"Error in caesar_encrypt: {str(e)}")
        raise

def caesar_decrypt(encrypted: str, key: int) -> str:
    try:
        decrypted = caesar_encrypt(encrypted, -key)
        logger.debug(f"Caesar decrypt: encrypted={encrypted}, key={key}, decrypted={decrypted}")
        return decrypted
    except Exception as e:
        logger.error(f"Error in caesar_decrypt: {str(e)}")
        raise