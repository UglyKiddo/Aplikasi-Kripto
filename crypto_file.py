from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES
from database import aesgcm_encrypt, aesgcm_decrypt
import os

def encrypt_file(input_file, output_file, key):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    with open(input_file, "rb") as f:
        data = f.read()
    enc = aesgcm.encrypt(nonce, data, None)
    with open(output_file, "wb") as f:
        f.write(nonce + enc)

def decrypt_file(input_path, output_path, key):
    try:
        with open(input_path, "rb") as f:
            data = f.read()

        nonce = data[:12]
        ciphertext = data[12:]

        aes = AES.new(key, AES.MODE_GCM, nonce=nonce)

        decrypted = aes.decrypt(ciphertext)

        with open(output_path, "wb") as out:
            out.write(decrypted)

    except Exception as e:
        raise Exception(f"Decrypt error: {type(e).__name__}: {e}")