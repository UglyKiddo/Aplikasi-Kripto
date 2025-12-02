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
    """Derive a 32-byte key from a passphrase using PBKDF2-HMAC-SHA256.

    Returns (key, salt). If salt is not provided a random 16-byte salt is generated.
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
    """Encrypt plaintext using AES-GCM and return raw bytes: nonce(12) || ciphertext || tag(16).

    plaintext must be bytes. Returned value is bytes and should be stored directly in a BLOB column.
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, bytes(plaintext), None)
    return nonce + ct


def aesgcm_decrypt(payload: Union[bytes, bytearray, memoryview, str], key: bytes) -> bytes:
    # Normalize to bytes if memoryview/bytearray
    if isinstance(payload, memoryview):
        payload = payload.tobytes()
    if isinstance(payload, bytearray):
        payload = bytes(payload)

    # If payload is str -> must be base64
    if isinstance(payload, str):
        try:
            raw = base64.b64decode(payload, validate=True)
        except Exception as e:
            raise ValueError(f"Provided payload is a str but not valid base64: {e}")
    elif isinstance(payload, (bytes, bytearray)):
        # try base64 detect: if payload is base64 bytes, decode; otherwise treat as raw bytes
        try:
            cand = base64.b64decode(payload, validate=True)
            # require minimum length for nonce+tag
            if len(cand) >= 12 + 16:
                raw = cand
            else:
                raw = bytes(payload)
        except Exception:
            raw = bytes(payload)
    else:
        raise TypeError("Unsupported payload type for aesgcm_decrypt")

    if len(raw) < 12 + 16:
        raise ValueError("Encrypted payload too short or truncated (need nonce+ct+tag)")

    nonce = raw[:12]
    ct = raw[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


def init_db() -> None:
    """Create database and required tables if they don't exist."""
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
        except Exception:
            pass
        conn.close()

    conn = mysql.connector.connect(**MYSQL_CONFIG)
    try:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(200) NOT NULL
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sender VARCHAR(50) NOT NULL,
                receiver VARCHAR(50) NOT NULL,
                message LONGBLOB NOT NULL,
                msg_type ENUM('text','file','image') DEFAULT 'text',
                filename VARCHAR(255) DEFAULT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS stego (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sender VARCHAR(100),
                receiver VARCHAR(100),
                filename VARCHAR(255),
                image_data LONGBLOB NOT NULL,
                message LONGBLOB,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
    finally:
        try:
            c.close()
        except Exception:
            pass
        conn.close()


def save_encrypted_message(sender: str, receiver: str, content: bytes, key: bytes,
                           msg_type: str = 'text', filename: str = None) -> None:
    """Encrypt `content` (raw bytes) with AES-GCM and store raw bytes (nonce+ct+tag) in the DB.

    This function will raise TypeError if content is not bytes.
    """
    if not isinstance(content, (bytes, bytearray)):
        raise TypeError("content must be bytes")

    encrypted = aesgcm_encrypt(bytes(content), key)  # raw bytes

    conn = mysql.connector.connect(**MYSQL_CONFIG)
    try:
        c = conn.cursor()
        c.execute("""
            INSERT INTO messages (sender, receiver, message, msg_type, filename)
            VALUES (%s, %s, %s, %s, %s)
        """, (sender, receiver, mysql.connector.Binary(encrypted), msg_type, filename))
        conn.commit()
    finally:
        try:
            c.close()
        except Exception:
            pass
        conn.close()


def read_messages_for_user(username: str, key: bytes) -> List[Dict[str, Any]]:
    """Read messages for a user and attempt to decrypt using provided key.

    If decryption fails the returned content will contain an error marker.
    """
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    rows = []
    try:
        c = conn.cursor()
        c.execute('''
            SELECT id, sender, msg_type, message, filename, timestamp
            FROM messages
            WHERE receiver=%s
            ORDER BY id ASC
        ''', (username,))
        rows = c.fetchall()
    finally:
        try:
            c.close()
        except Exception:
            pass
        conn.close()

    hasil: List[Dict[str, Any]] = []

    for msg_id, sender, msg_type, ciphertext, filename, timestamp in rows:
        try:
            # normalize ciphertext to bytes
            if isinstance(ciphertext, memoryview):
                ciphertext = ciphertext.tobytes()
            elif isinstance(ciphertext, bytearray):
                ciphertext = bytes(ciphertext)
            elif isinstance(ciphertext, bytes):
                pass
            elif isinstance(ciphertext, str):
                # legacy: if stored as base64 string we decode; otherwise mark as corrupted
                try:
                    ciphertext = base64.b64decode(ciphertext, validate=True)
                except Exception:
                    raise ValueError("Ciphertext in DB is a str but not valid base64 (corrupted)")
            else:
                ciphertext = bytes(ciphertext)

            plaintext = aesgcm_decrypt(ciphertext, key)

            if msg_type == 'text':
                try:
                    content = plaintext.decode("utf-8")
                except UnicodeDecodeError:
                    content = plaintext.decode("utf-8", errors="replace")
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


# helper: read raw encrypted payload (bytes) for a message id
def read_raw_message(msg_id: int) -> bytes:
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    try:
        c = conn.cursor()
        c.execute("SELECT message FROM messages WHERE id=%s", (msg_id,))
        row = c.fetchone()
        c.close()
    finally:
        conn.close()

    if not row:
        raise KeyError("message id not found")

    payload = row[0]
    if isinstance(payload, memoryview):
        return payload.tobytes()
    if isinstance(payload, bytearray):
        return bytes(payload)
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, str):
        # legacy base64 string
        try:
            return base64.b64decode(payload, validate=True)
        except Exception:
            raise ValueError("Stored message is str but not valid base64")
    raise TypeError("Unsupported stored payload type")