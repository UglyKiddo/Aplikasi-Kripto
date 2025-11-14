import os
import base64
from typing import Tuple, List, Dict, Any, Union

import mysql.connector
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MYSQL_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "kriptografi",
    "charset": "utf8mb4",
    "use_unicode": True,
}

DB_NAME = "kriptografi"


def derive_key(password: str, salt: bytes = None, iterations: int = 200_000) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(password.encode("utf-8"))
    return key, salt


def aesgcm_encrypt(plaintext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ct)


def aesgcm_decrypt(payload: Union[str, bytes], key: bytes) -> bytes:
    # pastikan payload dalam bentuk bytes
    if isinstance(payload, memoryview):
        payload = bytes(payload)
    if isinstance(payload, bytearray):
        payload = bytes(payload)
    if isinstance(payload, str):
        # ketika DB/driver mengembalikan string, gunakan latin1 untuk
        # menjaga nilai byte 0-255 tanpa perubahan
        payload = payload.encode("latin1")

    # payload sekarang adalah base64(nonce||ciphertext) dalam bentuk bytes
    try:
        raw = base64.b64decode(payload)
    except Exception as e:
        raise ValueError(f"payload bukan base64 valid: {e}")

    if len(raw) < 12:
        raise ValueError("payload terlalu pendek untuk berisi nonce")

    nonce = raw[:12]
    ct = raw[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


def init_db() -> None:
    conn = mysql.connector.connect(
        host=MYSQL_CONFIG["host"],
        user=MYSQL_CONFIG["user"],
        password=MYSQL_CONFIG["password"],
        charset=MYSQL_CONFIG.get("charset", "utf8mb4"),
    )
    try:
        c = conn.cursor()
        c.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        conn.commit()
    finally:
        try:
            c.close()
        except:
            pass
        conn.close()

    conn = mysql.connector.connect(**MYSQL_CONFIG)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(200) NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sender VARCHAR(50) NOT NULL,
                receiver VARCHAR(50) NOT NULL,
                message LONGBLOB NOT NULL,
                msg_type ENUM('text','file','image') DEFAULT 'text',
                filename VARCHAR(255) DEFAULT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS stego (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sender VARCHAR(100),
                receiver VARCHAR(100),
                filename VARCHAR(255),
                image_data LONGBLOB NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
    finally:
        try:
            c.close()
        except:
            pass
        conn.close()


def save_encrypted_message(sender: str, receiver: str, content: bytes, key: bytes,
                           msg_type: str = 'text', filename: str = None) -> None:
    encrypted_b64 = aesgcm_encrypt(content, key)  # bytes (base64)
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    try:
        c = conn.cursor()
        # pastikan kita menyimpan sebagai BLOB
        c.execute("""
            INSERT INTO messages (sender, receiver, message, msg_type, filename)
            VALUES (%s, %s, %s, %s, %s)
        """, (sender, receiver, mysql.connector.Binary(encrypted_b64), msg_type, filename))
        conn.commit()
    finally:
        try:
            c.close()
        except:
            pass
        conn.close()


def read_messages_for_user(username: str, key: bytes) -> List[Dict[str, Any]]:
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    rows = []
    try:
        c = conn.cursor()
        c.execute("""
            SELECT id, sender, msg_type, message, filename, timestamp
            FROM messages
            WHERE receiver=%s
            ORDER BY id ASC
        """, (username,))
        rows = c.fetchall()
    finally:
        try:
            c.close()
        except:
            pass
        conn.close()

    hasil: List[Dict[str, Any]] = []

    for msg_id, sender, msg_type, ciphertext, filename, timestamp in rows:
        try:
            # pastikan ciphertext adalah bytes, tidak memoryview/str
            if isinstance(ciphertext, memoryview):
                ciphertext = bytes(ciphertext)
            if isinstance(ciphertext, bytearray):
                ciphertext = bytes(ciphertext)
            # ciphertext may also be str (rare) — aesgcm_decrypt will handle str by encoding
            plaintext = aesgcm_decrypt(ciphertext, key)

            if msg_type == 'text':
                try:
                    content = plaintext.decode("utf-8")
                except UnicodeDecodeError:
                    content = plaintext.decode("latin1", errors="replace")
            else:
                content = plaintext

            hasil.append({
                "id": msg_id,
                "sender": sender,
                "msg_type": msg_type,
                "content": content,
                "filename": filename,
                "timestamp": timestamp
            })

        except Exception as e:
            err_text = f"[DECRYPTION_FAILED: {e}]"
            hasil.append({
                "id": msg_id,
                "sender": sender,
                "msg_type": msg_type,
                "content": err_text if msg_type == 'text' else err_text.encode(),
                "filename": filename,
                "timestamp": timestamp
            })

    return hasil