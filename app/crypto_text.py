from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom

def xor_cipher(data: bytes, key: int) -> bytes:
    return bytes([b ^ key for b in data])

def aes_encrypt(plaintext: bytes, key: bytes):
    nonce = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce, ciphertext

def aes_decrypt(ciphertext: bytes, key: bytes, nonce: bytes):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext