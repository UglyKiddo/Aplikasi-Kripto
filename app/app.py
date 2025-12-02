import streamlit as st
import mysql.connector
import hashlib, os, tempfile, base64
from PIL import Image

from database import (
    aesgcm_decrypt, aesgcm_encrypt, init_db, derive_key, MYSQL_CONFIG
)
from crypto_file import encrypt_file, decrypt_file
from crypto_text import xor_cipher, aes_encrypt, aes_decrypt
from stego import encode_lsb, decode_lsb

home_dir = os.path.expanduser("~")
base_dir = os.path.join(home_dir, "local_https_demo")
os.makedirs(base_dir, exist_ok=True)

init_db()

def hash_password_sha3(password):
    salt = os.urandom(16)
    hashed = hashlib.sha3_256(password.encode() + salt).digest()
    return base64.b64encode(salt + hashed).decode()

def check_password_sha3(password, stored):
    raw = base64.b64decode(stored)
    salt = raw[:16]
    stored_hash = raw[16:]
    new_hash = hashlib.sha3_256(password.encode() + salt).digest()
    return new_hash == stored_hash

def load_aes_key():
    password = "admin123"
    salt_path = os.path.join(base_dir, "salt.bin")
    if os.path.exists(salt_path):
        with open(salt_path, "rb") as f:
            salt = f.read()
        key, _ = derive_key(password, salt)
    else:
        key, salt = derive_key(password)
        with open(salt_path, "wb") as f:
            f.write(salt)
    return key

key = load_aes_key()

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user" not in st.session_state:
    st.session_state.user = None
if "page" not in st.session_state:
    st.session_state.page = "login"

def go(page):
    st.session_state.page = page

def logout():
    st.session_state.logged_in = False
    st.session_state.user = None
    go("login")
    st.rerun()

def login_page():
    st.title("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        c = conn.cursor()
        c.execute("SELECT password_hash FROM users WHERE username=%s", (username,))
        row = c.fetchone()
        c.close(); conn.close()
        if not row:
            st.error("Username tidak ditemukan")
            return
        if check_password_sha3(password, row[0]):
            st.session_state.logged_in = True
            st.session_state.user = username
            go("home")
            st.rerun()
        else:
            st.error("Password salah")
    if st.button("Register"):
        go("register")
        st.rerun()

def register_page():
    st.title("Register")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Submit"):
        if not username or not password:
            st.error("Semua field wajib diisi")
            return
        pw_hash = hash_password_sha3(password)
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                      (username, pw_hash))
            conn.commit()
            st.success("Akun berhasil dibuat. Silakan login.")
        except mysql.connector.errors.IntegrityError:
            st.error("Username sudah digunakan")
        finally:
            c.close(); conn.close()
    if st.button("Kembali ke Login"):
        go("login")
        st.rerun()

def home_page():
    st.title("Home")
    st.markdown(f"Selamat datang, **{st.session_state.user}** di CRYPTOGUARD")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("Pesan Teks")
        if st.button("Kirim Pesan Teks"):
            go("send_message"); st.rerun()
        if st.button("Inbox Pesan Teks"):
            go("inbox"); st.rerun()
        st.markdown("---")
        st.markdown("Steganografi")
        if st.button("Kirim Stego"):
            go("send_stego"); st.rerun()
        if st.button("Inbox Stego"):
            go("stego_inbox"); st.rerun()
    with col2:
        st.markdown("File Terenkripsi")
        if st.button("Kirim File"):
            go("send_file"); st.rerun()
        if st.button("Daftar File Masuk"):
            go("files"); st.rerun()
        st.markdown("---")
        if st.button("Logout"):
            logout()

def send_message_page():
    st.title("Kirim Pesan Teks")
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE username != %s", (st.session_state.user,))
    users = [u[0] for u in c.fetchall()]
    c.close(); conn.close()

    receiver = st.selectbox("Penerima", users)
    msg = st.text_area("Pesan")
    aes_pass = st.text_input("Masukkan Password AES (wajib)", type="password")
    xor_key_input = st.number_input("Masukkan XOR key (0-255)", min_value=0, max_value=255, value=0, step=1)

    if st.button("Kirim"):
        if not aes_pass:
            st.error("Password AES wajib diisi")
            return
        key_bytes, salt = derive_key(aes_pass)
        xor_key = int(xor_key_input) & 0xFF
        xored = xor_cipher(msg.encode("utf-8"), xor_key)
        nonce, ct = aes_encrypt(xored, key_bytes)
        combined = salt + nonce + ct
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        c = conn.cursor()
        c.execute("""
            INSERT INTO messages (sender, receiver, message, msg_type, filename)
            VALUES (%s, %s, %s, %s, %s)
        """, (st.session_state.user, receiver, mysql.connector.Binary(combined), "text", None))
        conn.commit(); c.close(); conn.close()
        st.success("Pesan terenkripsi dan terkirim")
        go("home"); st.rerun()

    if st.button("Kembali ke Home"):
        go("home"); st.rerun()

def inbox_page():
    st.title("Inbox Pesan Teks")
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    c = conn.cursor()
    c.execute("""
        SELECT id, sender, message, timestamp
        FROM messages
        WHERE receiver=%s AND msg_type='text'
        ORDER BY id DESC
    """, (st.session_state.user,))
    rows = c.fetchall()
    c.close(); conn.close()

    if not rows:
        st.info("Belum ada pesan masuk")
        if st.button("Kembali ke Home"):
            go("home"); st.rerun()
        return

    for msg_id, sender, content_blob, ts in rows:
        if isinstance(content_blob, memoryview):
            content_blob = content_blob.tobytes()
        st.write(f"**Dari:** {sender} — {ts}")
        if isinstance(content_blob, (bytes, bytearray)) and len(content_blob) >= 16 + 16:
            salt = content_blob[:16]
            rest = content_blob[16:]
            if len(rest) >= 16:
                st.write("Pesan terenkripsi (butuh Password AES dan XOR key untuk dekripsi)")
                pw = st.text_input("Masukkan Password AES", key=f"msg_pw_{msg_id}", type="password")
                xor_key_input = st.number_input("Masukkan XOR key (0-255)", min_value=0, max_value=255, value=0, key=f"msg_xor_{msg_id}")
                if st.button("Dekripsi", key=f"dec_{msg_id}"):
                    try:
                        key_bytes, _ = derive_key(pw, salt)
                        nonce = rest[:16]
                        ct = rest[16:]
                        xored = aes_decrypt(ct, key_bytes, nonce)
                        plain = xor_cipher(xored, int(xor_key_input) & 0xFF)
                        try:
                            text = plain.decode("utf-8")
                        except:
                            text = plain.decode("utf-8", errors="replace")
                        st.write(text)
                    except Exception:
                        st.error("KEY SALAH atau data rusak")
            else:
                st.write("[Format pesan tidak dikenali]")
        else:
            st.write("[Pesan tidak dalam format yang diharapkan]")
        st.write("---")

    if st.button("Kembali ke Home"):
        go("home"); st.rerun()

def send_file_page():
    st.title("Kirim File")
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE username != %s", (st.session_state.user,))
    users = [u[0] for u in c.fetchall()]
    c.close(); conn.close()

    receiver = st.selectbox("Penerima", users)
    upload = st.file_uploader("Pilih file")
    aes_pass = st.text_input("Masukkan Password AES (wajib)", type="password")

    if st.button("Kirim"):
        if not upload:
            st.error("Pilih file terlebih dahulu")
            return
        if not aes_pass:
            st.error("Password AES wajib diisi")
            return
        key_bytes, salt = derive_key(aes_pass)
        plaintext = upload.getvalue()
        ciphertext = aesgcm_encrypt(plaintext, key_bytes)
        combined = salt + ciphertext
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        c = conn.cursor()
        c.execute("""
            INSERT INTO messages (sender, receiver, message, msg_type, filename)
            VALUES (%s, %s, %s, %s, %s)
        """, (st.session_state.user, receiver, mysql.connector.Binary(combined), "file", upload.name))
        conn.commit(); c.close(); conn.close()
        st.success("File terenkripsi dan terkirim")
        go("home"); st.rerun()

    if st.button("Kembali ke Home"):
        go("home"); st.rerun()

def files_page():
    st.title("File Masuk")
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    c = conn.cursor()
    c.execute("""
        SELECT id, sender, filename, message, timestamp
        FROM messages
        WHERE receiver=%s AND msg_type='file'
        ORDER BY id DESC
    """, (st.session_state.user,))
    rows = c.fetchall()
    c.close(); conn.close()

    if not rows:
        st.info("Belum ada file masuk")
        if st.button("Kembali ke Home"):
            go("home"); st.rerun()
        return

    for msg_id, sender, filename, content_blob, ts in rows:
        if isinstance(content_blob, memoryview):
            content_blob = content_blob.tobytes()
        st.write(f"**Dari:** {sender} — {ts}")
        st.write(f"Nama File: {filename}")
        if isinstance(content_blob, (bytes, bytearray)) and len(content_blob) >= 16 + 12 + 16:
            salt = content_blob[:16]
            cipher = content_blob[16:]
            pw = st.text_input(f"Masukkan Password AES untuk file", key=f"file_pw_{msg_id}", type="password")
            if st.button(f"Download", key=f"dl_{msg_id}"):
                try:
                    key_bytes, _ = derive_key(pw, salt)
                    plaintext = aesgcm_decrypt(cipher, key_bytes)
                    st.download_button("Klik untuk download", data=plaintext, file_name=filename, mime="application/octet-stream")
                except Exception:
                    st.error("KEY SALAH atau data rusak")
        else:
            st.write("[File tidak dalam format yang diharapkan]")
        st.write("---")

    if st.button("Kembali ke Home"):
        go("home"); st.rerun()

def send_stego_page():
    st.title("Kirim Stego Image")
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE username != %s", (st.session_state.user,))
    users = [u[0] for u in c.fetchall()]
    c.close(); conn.close()

    receiver = st.selectbox("Penerima", users)
    message = st.text_area("Pesan")
    file = st.file_uploader("Gambar BMP", type=["bmp"])

    if st.button("Kirim"):
        if not file or not message:
            st.error("Lengkapi semua field")
            return
        encoded = base64.b64encode(message.encode("utf-8")).decode()
        fd, temp_path = tempfile.mkstemp(suffix=".bmp", dir=base_dir)
        os.close(fd)
        with open(temp_path, "wb") as f:
            f.write(file.getvalue())
        out_path = encode_lsb(temp_path, encoded)
        with open(out_path, "rb") as f:
            img = f.read()
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        c = conn.cursor()
        c.execute("""
            INSERT INTO stego (sender, receiver, filename, image_data, message)
            VALUES (%s, %s, %s, %s, %s)
        """, (st.session_state.user, receiver, os.path.basename(out_path), mysql.connector.Binary(img), None))
        conn.commit(); c.close(); conn.close()
        os.remove(temp_path); os.remove(out_path)
        st.success("Gambar berhasil dikirim")
        go("home"); st.rerun()

    if st.button("Kembali ke Home"):
        go("home"); st.rerun()

def stego_inbox_page():
    st.title("Inbox Stego")
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    c = conn.cursor()
    c.execute("SELECT id, sender, filename, image_data, message, timestamp FROM stego WHERE receiver=%s",
              (st.session_state.user,))
    rows = c.fetchall()
    c.close(); conn.close()

    if not rows:
        st.info("Belum ada pesan stego")
        if st.button("Kembali ke Home"):
            go("home"); st.rerun()
        return

    for sid, sender, filename, img_blob, msg_blob, ts in rows:
        if isinstance(img_blob, memoryview):
            img_blob = img_blob.tobytes()
        st.image(img_blob, caption=f"Dari {sender} — {ts}")
        try:
            fd, tmp_path = tempfile.mkstemp(suffix=".bmp", dir=base_dir)
            os.close(fd)
            with open(tmp_path, "wb") as f:
                f.write(img_blob)
            extracted = decode_lsb(tmp_path)
            os.remove(tmp_path)
            if extracted:
                try:
                    plain = base64.b64decode(extracted).decode("utf-8")
                    st.write(plain)
                except Exception:
                    st.write("[Gagal decode pesan LSB]")
            else:
                st.write("[Tidak ada pesan tersembunyi]")
        except Exception:
            st.write("[Gagal memproses gambar]")
        st.write("---")

    if st.button("Kembali ke Home"):
        go("home"); st.rerun()

if not st.session_state.logged_in:
    if st.session_state.page == "login":
        login_page()
    elif st.session_state.page == "register":
        register_page()
else:
    if st.session_state.page == "home":
        home_page()
    elif st.session_state.page == "send_message":
        send_message_page()
    elif st.session_state.page == "inbox":
        inbox_page()
    elif st.session_state.page == "send_file":
        send_file_page()
    elif st.session_state.page == "files":
        files_page()
    elif st.session_state.page == "send_stego":
        send_stego_page()
    elif st.session_state.page == "stego_inbox":
        stego_inbox_page()