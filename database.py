import mysql.connector
import os
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# -------------------------------------------------
# MYSQL CONFIG
# -------------------------------------------------
MYSQL_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "kriptografi"
}

DB_NAME = "kriptografi"


# -------------------------------------------------
# KEY DERIVATION
# -------------------------------------------------
def derive_key(password: str, salt: bytes = None, iterations: int = 200_000):
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


# -------------------------------------------------
# AES-GCM
# -------------------------------------------------
def aesgcm_encrypt(plaintext: bytes, key: bytes) -> str:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ct).decode()


def aesgcm_decrypt(b64_payload: str, key: bytes) -> bytes:
    data = base64.b64decode(b64_payload)
    nonce = data[:12]
    ct = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


# -------------------------------------------------
# AUTO CREATE DATABASE + TABLE
# -------------------------------------------------
def init_db():
    conn = mysql.connector.connect(
        host=MYSQL_CONFIG["host"],
        user=MYSQL_CONFIG["user"],
        password=MYSQL_CONFIG["password"],
    )
    c = conn.cursor()
    c.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
    conn.commit()
    conn.close()

    conn = mysql.connector.connect(**MYSQL_CONFIG)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            data TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE,
            password_hash VARCHAR(128)
        )
    """)
    conn.commit()
    conn.close()


# -------------------------------------------------
# HELPER: SHA3-256 password hash
# -------------------------------------------------
def sha3_hash_password(password: str) -> str:
    return hashlib.sha3_256(password.encode()).hexdigest()


# -------------------------------------------------
# REGISTER USER (uses SHA3-256 for passwords)
# -------------------------------------------------
def register_user(username: str, password: str) -> bool:
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username=%s", (username,))
    if c.fetchone() is not None:
        conn.close()
        return False

    pw_hash = sha3_hash_password(password)
    c.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)",
              (username, pw_hash))
    conn.commit()
    conn.close()
    return True


# -------------------------------------------------
# LOGIN USER (verify SHA3-256)
# -------------------------------------------------
def login_user(username: str, password: str) -> bool:
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username=%s", (username,))
    row = c.fetchone()
    conn.close()
    if row is None:
        return False
    stored_hash = row[0]
    return sha3_hash_password(password) == stored_hash


# -------------------------------------------------
# INSERT - AES GCM (messages stored encrypted)
# -------------------------------------------------
def save_message_plain(plaintext_b64: str, key: bytes):
    encrypted = aesgcm_encrypt(plaintext_b64.encode(), key)
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    c = conn.cursor()
    c.execute("INSERT INTO messages (data) VALUES (%s)", (encrypted,))
    conn.commit()
    conn.close()


# -------------------------------------------------
# READ & DECRYPT
# -------------------------------------------------
def read_and_decrypt_messages(key: bytes):
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    c = conn.cursor()
    c.execute("SELECT data FROM messages ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()

    hasil = []
    for (ciphertext,) in rows:
        try:
            pt = aesgcm_decrypt(ciphertext, key)
            hasil.append(pt.decode())
        except Exception as e:
            hasil.append(f"[DECRYPTION_FAILED: {e}]")
    return hasil
