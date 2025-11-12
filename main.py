from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
import os, tempfile, base64
import mysql.connector
from PIL import Image

from database import (
    init_db, derive_key, save_encrypted_message, read_messages_for_user, MYSQL_CONFIG
)
from login import hash_password, check_login
from crypto_text import xor_cipher
from crypto_file import encrypt_file, decrypt_file
from stego import encode_lsb, decode_lsb

# === Direktori dasar ===
home_dir = os.path.expanduser("~")
base_dir = os.path.join(home_dir, "local_https_demo")
os.makedirs(base_dir, exist_ok=True)

# === Inisialisasi database ===
init_db()

# === Load AES Key ===
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

# === Konfigurasi Flask ===
app = Flask(__name__)
app.secret_key = os.urandom(24)

# ================== ROUTES ==================

@app.route("/")
def home():
    if "user" not in session:
        return redirect(url_for("login"))
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE username != %s", (session["user"],))
        users = [u[0] for u in c.fetchall()]
        c.close(); conn.close()
    except:
        users = []
    return render_template("home.html", users=users, username=session["user"])

# === LOGIN ===
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()
        if not username or not password:
            flash("Isi username dan password")
            return redirect(url_for("login"))
        try:
            conn = mysql.connector.connect(**MYSQL_CONFIG)
            c = conn.cursor()
            c.execute("SELECT password_hash FROM users WHERE username=%s", (username,))
            row = c.fetchone()
            c.close(); conn.close()
        except Exception as e:
            flash(str(e))
            return redirect(url_for("login"))
        if not row:
            flash("Username tidak ditemukan")
            return redirect(url_for("login"))
        if check_login(password, row[0]):
            session["user"] = username
            return redirect(url_for("home"))
        else:
            flash("Password salah")
            return redirect(url_for("login"))
    return render_template("login.html")

# === REGISTER ===
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()
        if not username or not password:
            flash("Semua field wajib diisi")
            return redirect(url_for("register"))
        pw_hash = hash_password(password)
        try:
            conn = mysql.connector.connect(**MYSQL_CONFIG)
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, pw_hash))
            conn.commit(); c.close(); conn.close()
            flash("Akun berhasil dibuat, silakan login")
            return redirect(url_for("login"))
        except mysql.connector.errors.IntegrityError:
            flash("Username sudah digunakan")
            return redirect(url_for("register"))
    return render_template("register.html")

# === LOGOUT ===
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

# === KIRIM PESAN TEKS ===
@app.route("/send_message", methods=["POST"])
def send_message():
    if "user" not in session:
        return redirect(url_for("login"))
    receiver = (request.form.get("receiver") or "").strip()
    msg = (request.form.get("message") or "").strip()
    if not receiver or not msg:
        flash("Pesan tidak boleh kosong")
        return redirect(url_for("home"))
    try:
        save_encrypted_message(
            sender=session["user"],
            receiver=receiver,
            content=msg.encode("utf-8"),
            key=key,
            msg_type="text"
        )
        flash("Pesan teks terenkripsi dan terkirim ✅")
    except Exception as e:
        flash(f"Gagal mengirim pesan: {e}")
    return redirect(url_for("home"))

# === PESAN MASUK ===
@app.route("/inbox")
def inbox():
    if "user" not in session:
        return redirect(url_for("login"))
    try:
        messages = read_messages_for_user(session["user"], key)
        text_messages = [m for m in messages if m["msg_type"] == "text"]
    except Exception as e:
        flash(str(e))
        text_messages = []
    return render_template("inbox.html", messages=text_messages, username=session["user"])

# === KIRIM FILE ===
@app.route("/send_file", methods=["POST"])
def send_file_route():
    if "user" not in session:
        return redirect(url_for("login"))
    receiver = (request.form.get("receiver_file") or "").strip()
    f = request.files.get("file")
    if not f or not receiver:
        flash("File atau penerima kosong")
        return redirect(url_for("home"))
    tmp_in = tempfile.mktemp(dir=base_dir)
    tmp_enc = tmp_in + ".enc"
    try:
        f.save(tmp_in)
        encrypt_file(tmp_in, tmp_enc, key)
        with open(tmp_enc, "rb") as fh:
            file_data = fh.read()
        save_encrypted_message(
            sender=session["user"],
            receiver=receiver,
            content=file_data,
            key=key,
            msg_type="file",
            filename=f.filename
        )
        flash("File terenkripsi dan terkirim ✅")
    except Exception as e:
        flash(f"Gagal kirim file: {e}")
    finally:
        for p in (tmp_in, tmp_enc):
            if os.path.exists(p): os.remove(p)
    return redirect(url_for("home"))

# === FILE MASUK ===
@app.route("/files")
def files():
    if "user" not in session:
        return redirect(url_for("login"))
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    c = conn.cursor()
    c.execute("""
        SELECT sender, filename, timestamp
        FROM messages
        WHERE receiver=%s AND msg_type='file'
        ORDER BY id DESC
    """, (session["user"],))
    rows = c.fetchall()
    conn.close()
    return render_template("files.html", rows=rows, username=session["user"])

# === KIRIM STEGO ===
@app.route("/send_stego", methods=["POST"])
def send_stego():
    if "user" not in session:
        return redirect(url_for("login"))
    receiver = (request.form.get("receiver_stego") or "").strip()
    msg = (request.form.get("stego_msg") or "").strip()
    img_file = request.files.get("stego_img")
    if not receiver or not msg or not img_file:
        flash("Lengkapi semua field")
        return redirect(url_for("home"))
    try:
        tmp_path = tempfile.mktemp(dir=base_dir, suffix=".bmp")
        img_file.save(tmp_path)
        with Image.open(tmp_path) as im:
            if im.mode != "RGB":
                im = im.convert("RGB")
            im.save(tmp_path, format="BMP")
        out_path = tmp_path.replace(".bmp", "_stego.bmp")
        encode_lsb(tmp_path, msg, out_path)
        with open(out_path, "rb") as fh:
            stego_data = fh.read()
        save_encrypted_message(
            sender=session["user"],
            receiver=receiver,
            content=stego_data,
            key=key,
            msg_type="image",
            filename=os.path.basename(out_path)
        )
        flash("Gambar dengan pesan tersembunyi berhasil dikirim ✅")
    except Exception as e:
        flash(f"Gagal membuat/mengirim stego: {e}")
    finally:
        for p in (tmp_path, out_path):
            if os.path.exists(p): os.remove(p)
    return redirect(url_for("home"))

# === INBOX STEGO ===
@app.route("/stego_inbox")
def stego_inbox():
    if "user" not in session:
        return redirect(url_for("login"))
    stego_msgs = []
    try:
        msgs = read_messages_for_user(session["user"], key)
        for msg in msgs:
            if msg["msg_type"] == "image":
                data = msg["content"]
                filename = msg["filename"]
                tmp_path = tempfile.mktemp(dir=base_dir, suffix=".bmp")
                with open(tmp_path, "wb") as f:
                    f.write(data)
                try:
                    hidden_text = decode_lsb(tmp_path)
                except Exception as e:
                    hidden_text = f"[Gagal baca pesan: {e}]"
                img_b64 = base64.b64encode(data).decode("utf-8")
                stego_msgs.append({
                    "sender": msg["sender"],
                    "filename": filename,
                    "timestamp": msg["timestamp"],
                    "message": hidden_text,
                    "image_data": f"data:image/bmp;base64,{img_b64}"
                })
                os.remove(tmp_path)
    except Exception as e:
        flash(str(e))
    return render_template("stego.html", rows=stego_msgs, username=session["user"])

# === Jalankan Aplikasi ===
if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    cert_path = os.path.join(current_dir, "cert.pem")
    key_path = os.path.join(current_dir, "key.pem")

    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        raise FileNotFoundError(f"File sertifikat TLS tidak ditemukan di {current_dir}")

    app.run(
        host="127.0.0.1",
        port=5000,
        ssl_context=(cert_path, key_path),
        debug=True
    )