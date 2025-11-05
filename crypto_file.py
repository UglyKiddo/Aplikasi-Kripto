from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt_file(input_file, output_file, key):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    with open(input_file, "rb") as f:
        data = f.read()
    enc = aesgcm.encrypt(nonce, data, None)
    with open(output_file, "wb") as f:
        f.write(nonce + enc)

def decrypt_file(input_file, output_file, key):
    aesgcm = AESGCM(key)
    with open(input_file, "rb") as f:
        data = f.read()
    nonce, ciphertext = data[:12], data[12:]
    dec = aesgcm.decrypt(nonce, ciphertext, None)
    with open(output_file, "wb") as f:
        f.write(dec)