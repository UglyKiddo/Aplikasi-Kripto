import sqlite3
import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_key(password: str, salt: bytes = None, iterations: int = 200_000) -> tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(password.encode())
    return key, salt

def aesgcm_encrypt(plaintext: bytes, key: bytes) -> str:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit recommended for GCM
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    payload = nonce + ct
    return base64.b64encode(payload).decode()

def aesgcm_decrypt(b64_payload: str, key: bytes) -> bytes:
    payload = base64.b64decode(b64_payload)
    nonce = payload[:12]
    ct = payload[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, associated_data=None)

import sqlite3

def init_db(db_path="secure.db"):
    with sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data TEXT NOT NULL
            )
        """)
        conn.commit()
    print(f"📦 Database siap digunakan di: {db_path}")


def save_message_plain(db_path: str, plaintext: str, key: bytes):
    encrypted_b64 = aesgcm_encrypt(plaintext.encode(), key)
    with sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO messages (data) VALUES (?)", (encrypted_b64,))
        conn.commit()


def read_and_decrypt_messages(db_path: str, key: bytes) -> list[str]:
    results = []
    with sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        c.execute("SELECT data FROM messages ORDER BY id ASC")
        rows = c.fetchall()
    for (b64data,) in rows:
        try:
            pt = aesgcm_decrypt(b64data, key).decode()
            results.append(pt)
        except Exception as e:
            # Jika dekripsi gagal, tambahkan placeholder atau lewati
            results.append(f"[DECRYPTION_FAILED: {e}]")
    return results


if __name__ == "__main__":
    DB = "secure.db"
    init_db(DB)

    # Opsi: derive key dari password (lebih aman daripada menyimpan key mentah)
    password = "supersecretpassword"
    key, salt = derive_key(password)  # simpan salt jika ingin verifikasi/dekripsi nanti

    # Simpan pesan terenkripsi
    save_message_plain(DB, "Halo, ini pesan rahasia 1", key)
    save_message_plain(DB, "Pesan rahasia 2", key)

    # Baca & dekripsi
    messages = read_and_decrypt_messages(DB, key)
    for i, m in enumerate(messages, 1):
        print(f"{i}: {m}")