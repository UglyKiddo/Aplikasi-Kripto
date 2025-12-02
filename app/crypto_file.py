from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt_file(input_file, output_file, key):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    with open(input_file, "rb") as f:
        data = f.read()

    encrypted = aesgcm.encrypt(nonce, data, None)

    with open(output_file, "wb") as f:
        f.write(nonce + encrypted)

def decrypt_file(input_path, output_path, key):
    with open(input_path, "rb") as f:
        data = f.read()

    nonce = data[:12]
    ciphertext = data[12:]

    aesgcm = AESGCM(key)

    decrypted = aesgcm.decrypt(nonce, ciphertext, None)

    with open(output_path, "wb") as f:
        f.write(decrypted)