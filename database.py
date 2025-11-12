# database.py — perbaikan minimal (tambahan tabel `stego` + sedikit penanganan resources)
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
    """
    Derive a 32-byte key from a password using PBKDF2-HMAC-SHA256.
    Returns (key, salt). If salt is provided it will be reused.
    """
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
    """
    Encrypt plaintext (bytes) with AES-GCM and return base64-encoded payload as bytes.
    Payload format: base64(nonce || ciphertext)
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ct)


def aesgcm_decrypt(b64_payload: Union[str, bytes], key: bytes) -> bytes:
    """
    Decrypt base64 payload (bytes or str) produced by aesgcm_encrypt and return plaintext bytes.
    Raises exception if decryption/authentication fails.
    """
    if isinstance(b64_payload, str):
        b64_payload = b64_payload.encode("utf-8")
    payload = base64.b64decode(b64_payload)
    nonce = payload[:12]
    ct = payload[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


def init_db() -> None:
    """
    Create database (if missing) and required tables.
    """
    # create database if not exists
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

    # create tables inside the database
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
        # tambahan: tabel stego terpisah (opsional, tetapi aman jika ingin pemisahan)
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
    """
    Encrypt content (bytes) using AES-GCM and store into messages table.
    ciphertext is stored as base64 bytes (so it is portable).
    """
    encrypted_b64 = aesgcm_encrypt(content, key)  # returns bytes (base64-encoded)
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    try:
        c = conn.cursor()
        c.execute("""
            INSERT INTO messages (sender, receiver, message, msg_type, filename)
            VALUES (%s, %s, %s, %s, %s)
        """, (sender, receiver, encrypted_b64, msg_type, filename))
        conn.commit()
    finally:
        try:
            c.close()
        except:
            pass
        conn.close()


def read_messages_for_user(username: str, key: bytes) -> List[Dict[str, Any]]:
    """
    Read all messages for `username`, decrypt them with `key` and return list of dicts:
    {
        "sender": ...,
        "msg_type": 'text'|'file'|'image',
        "content": bytes (for file/image) or str (for text),
        "filename": optional,
        "timestamp": ...
    }
    If decryption fails, content will be bytes with an error message.
    """
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    rows = []
    try:
        c = conn.cursor()
        c.execute("SELECT sender, msg_type, message, filename, timestamp FROM messages WHERE receiver=%s ORDER BY id ASC", (username,))
        rows = c.fetchall()
    finally:
        try:
            c.close()
        except:
            pass
        conn.close()

    hasil: List[Dict[str, Any]] = []
    for sender, msg_type, ciphertext, filename, timestamp in rows:
        try:
            # ciphertext may be bytes or str from DB; aesgcm_decrypt accepts both
            plaintext = aesgcm_decrypt(ciphertext, key)
            # For text messages, try decode to utf-8 str; if fails, keep bytes
            if msg_type == 'text':
                try:
                    content = plaintext.decode("utf-8")
                except UnicodeDecodeError:
                    content = plaintext.decode("latin1", errors="replace")
            else:
                content = plaintext  # keep bytes for files/images
            hasil.append({
                "sender": sender,
                "msg_type": msg_type,
                "content": content,
                "filename": filename,
                "timestamp": timestamp
            })
        except Exception as e:
            # return an informative bytes payload for failed decryptions
            err_bytes = f"[DECRYPTION_FAILED: {e}]".encode("utf-8")
            if msg_type == 'text':
                # preserve the error as a string for text consumers
                hasil.append({
                    "sender": sender,
                    "msg_type": msg_type,
                    "content": err_bytes.decode("utf-8", errors="replace"),
                    "filename": filename,
                    "timestamp": timestamp
                })
            else:
                hasil.append({
                    "sender": sender,
                    "msg_type": msg_type,
                    "content": err_bytes,
                    "filename": filename,
                    "timestamp": timestamp
                })
    return hasil