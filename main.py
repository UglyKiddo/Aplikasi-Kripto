from flask import Flask, render_template, request, redirect, send_from_directory, url_for, session, flash, send_file
import os, tempfile, base64
import mysql.connector
from PIL import Image

from database import aesgcm_decrypt, aesgcm_encrypt, init_db, derive_key, save_encrypted_message, read_messages_for_user, MYSQL_CONFIG
from login import hash_password, check_login
from crypto_file import encrypt_file, decrypt_file
from stego import encode_lsb, decode_lsb

home_dir = os.path.expanduser("~")
base_dir = os.path.join(home_dir, "local_https_demo")
os.makedirs(base_dir, exist_ok=True)

init_db()

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

app = Flask(__name__)
app.secret_key = os.urandom(24)


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
        except Exception as e:
            flash(str(e))
            return redirect(url_for("register"))
    return render_template("register.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


@app.route("/send_message_page")
def send_message_page():
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
    return render_template("send_message.html", users=users, username=session["user"])


@app.route("/send_message", methods=["POST"])
def send_message():
    if "user" not in session:
        return redirect(url_for("login"))
    receiver = (request.form.get("receiver") or "").strip()
    msg = (request.form.get("message") or "").strip()
    if not receiver or not msg:
        flash("Pesan tidak boleh kosong")
        return redirect(url_for("send_message_page"))
    try:
        save_encrypted_message(
            sender=session["user"],
            receiver=receiver,
            content=msg.encode("utf-8"),
            key=key,
            msg_type="text"
        )
        flash("Pesan teks terenkripsi dan terkirim")
    except Exception as e:
        flash(f"Gagal mengirim pesan: {e}")
    return redirect(url_for("home"))


@app.route("/inbox")
def inbox():
    if "user" not in session:
        return redirect(url_for("login"))
    all_msgs = read_messages_for_user(session["user"], key)
    text_msgs = [m for m in all_msgs if m["msg_type"] == "text"]
    senders = sorted(list({m["sender"] for m in all_msgs}))
    selected = request.args.get("from", "").strip()
    if selected:
        messages = [m for m in all_msgs if m["sender"] == selected]
    else:
        messages = text_msgs
    return render_template("inbox.html", messages=messages, username=session["user"], senders=senders)


@app.route("/send_file_page")
def send_file_page():
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
    return render_template("send_file.html", users=users, username=session["user"])


@app.route("/send_file", methods=["POST"])
def send_file():
    if "user" not in session:
        return redirect(url_for("login"))
    receiver = (request.form.get("receiver_file") or "").strip()
    f = request.files.get("file")
    if not f or not receiver:
        flash("File atau penerima kosong")
        return redirect(url_for("send_file_page"))
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
        flash("File terenkripsi dan terkirim")
    except Exception as e:
        flash(f"Gagal kirim file: {e}")
    finally:
        for p in (tmp_in, tmp_enc):
            if os.path.exists(p):
                try: os.remove(p)
                except: pass
    return redirect(url_for("home"))


@app.route("/files")
def files():
    if "user" not in session:
        return redirect(url_for("login"))
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    c = conn.cursor()
    c.execute("""
        SELECT id, sender, filename, timestamp
        FROM messages
        WHERE receiver=%s AND msg_type='file'
        ORDER BY id DESC
    """, (session["user"],))
    rows = c.fetchall()
    c.close(); conn.close()
    return render_template("files.html", rows=rows, username=session["user"])


@app.route("/send_stego_page")
def send_stego_page():
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
    return render_template("send_stego.html", users=users, username=session["user"])


@app.route("/send_stego", methods=["POST"])
def send_stego():
    if "user" not in session:
        return redirect(url_for("login"))

    receiver = request.form.get("receiver_stego")
    message = request.form.get("stego_msg")
    file = request.files.get("stego_img")

    if not file or not message:
        flash("Gambar dan pesan wajib diisi")
        return redirect(url_for("send_stego_form"))

    # simpan file sementara
    temp_path = tempfile.mktemp(suffix=".bmp")
    file.save(temp_path)

    encrypted = aesgcm_encrypt(message.encode("utf-8"), key)
    encrypted_str = encrypted.decode("latin1")

    stego_path = encode_lsb(temp_path, encrypted_str)


    # baca gambar stego
    with open(stego_path, "rb") as f:
        image_bytes = f.read()

    # --- SIMPAN GAMBAR + PESAN TERENKRIPSI KE DATABASE ---
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    c = conn.cursor()
    c.execute("""
        INSERT INTO stego (sender, receiver, filename, image_data, message)
        VALUES (%s, %s, %s, %s, %s)
    """, (
        session["user"],
        receiver,
        os.path.basename(stego_path),
        mysql.connector.Binary(image_bytes),
        encrypted_str
    ))
    conn.commit()
    c.close()
    conn.close()

    flash("Gambar berhasil dikirim")
    return redirect(url_for("home"))


@app.route("/stego_inbox")
def stego_inbox():
    if "user" not in session:
        return redirect(url_for("login"))

    rows = []
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    c = conn.cursor()
    c.execute("SELECT sender, filename, image_data, timestamp FROM stego WHERE receiver=%s", 
              (session["user"],))
    data = c.fetchall()
    c.close(); conn.close()

    for sender, filename, img_blob, timestamp in data:

        # Buat file BMP sementara
        tmp_path = tempfile.mktemp(suffix=".bmp")
        with open(tmp_path, "wb") as f:
            f.write(img_blob)

        # Decode pesan dari gambar
        try:
            ciphertext = decode_lsb(tmp_path)
        except Exception:
            ciphertext = ""

        # decrypt AES-GCM
        if ciphertext:
            try:
                cipher_bytes = ciphertext.encode("latin1")
                pesan = aesgcm_decrypt(cipher_bytes, key).decode("utf-8")
            except Exception:
                pesan = "[Gagal decrypt AES]"
        else:
            pesan = "[Gambar rusak atau gagal decode]"

        os.remove(tmp_path)

        rows.append({
            "sender": sender,
            "filename": filename,
            "timestamp": timestamp,
            "message": pesan,
            "image_data": "data:image/bmp;base64," + base64.b64encode(img_blob).decode()
        })

    return render_template("stego_inbox.html", rows=rows)


@app.route("/download_file/<int:msg_id>")
def download_file(msg_id):
    if "user" not in session:
        return redirect(url_for("login"))

    tmp_enc_path = None
    output_path = None
    try:
        print(f"[DOWNLOAD] mulai proses download untuk msg_id={msg_id}, user={session['user']}")
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        c = conn.cursor()
        c.execute("""
            SELECT id, filename, message, receiver, msg_type
            FROM messages
            WHERE id=%s
        """, (msg_id,))
        row = c.fetchone()
        c.close(); conn.close()

        if not row:
            msg = "Record pesan tidak ditemukan di database."
            print("[DOWNLOAD ERROR]", msg)
            flash(msg)
            return redirect(url_for("files"))

        # sesuaikan struktur row jika cursor bukan dict
        # row: (id, filename, message, receiver, msg_type)
        r_id, filename, encrypted_blob, receiver, msg_type = row
        print(f"[DOWNLOAD] db row id={r_id}, filename={filename}, receiver={receiver}, msg_type={msg_type}, blob_type={type(encrypted_blob)}")

        if msg_type != 'file':
            msg = f"Pesan ini bukan file (msg_type={msg_type})."
            print("[DOWNLOAD ERROR]", msg)
            flash(msg)
            return redirect(url_for("files"))

        if receiver != session["user"]:
            msg = "Anda tidak memiliki akses ke file ini."
            print("[DOWNLOAD ERROR]", msg)
            flash(msg)
            return redirect(url_for("files"))

        # Normalisasi menjadi bytes
        blob = encrypted_blob
        if isinstance(blob, memoryview):
            blob = bytes(blob)
            print("[DOWNLOAD] converted memoryview -> bytes")
        if isinstance(blob, bytearray):
            blob = bytes(blob)
            print("[DOWNLOAD] converted bytearray -> bytes")
        if isinstance(blob, str):
            # jika DB menyimpan raw bytes sebagai str, coba latin1
            try:
                blob = blob.encode("latin1")
                print("[DOWNLOAD] converted str -> bytes (latin1)")
            except Exception as e:
                print("[DOWNLOAD ERROR] gagal konversi str->bytes:", e)
                flash("Gagal memproses data file (konversi).")
                return redirect(url_for("files"))

        if not isinstance(blob, (bytes, bytearray)):
            print("[DOWNLOAD ERROR] blob bukan bytes setelah normalisasi:", type(blob))
            flash("Data file tidak dalam format yang diharapkan.")
            return redirect(url_for("files"))

        # Coba base64 decode; jika gagal, anggap sudah raw
        raw_cipher = None
        try:
            import base64, binascii
            # base64.b64decode menerima bytes
            raw_cipher = base64.b64decode(blob, validate=True)
            print("[DOWNLOAD] base64 decode berhasil")
        except Exception as e1:
            print("[DOWNLOAD] base64 decode gagal:", repr(e1))
            # coba perbaiki padding lalu decode
            try:
                padded = blob + b'=' * (-len(blob) % 4)
                raw_cipher = base64.b64decode(padded)
                print("[DOWNLOAD] base64 decode with padding succeeded")
            except Exception as e2:
                print("[DOWNLOAD] tetap gagal base64 decode (anggap data sudah raw). e2:", repr(e2))
                raw_cipher = blob

        # simpan .enc sementara
        tmp_enc_path = os.path.join(base_dir, f"tmp_{msg_id}.enc")
        with open(tmp_enc_path, "wb") as f:
            f.write(raw_cipher)
        print(f"[DOWNLOAD] tulis file sementara .enc -> {tmp_enc_path} (size={os.path.getsize(tmp_enc_path)})")

        # decrypt (tangkap exception spesifik)
        output_path = os.path.join(base_dir, f"tmp_{msg_id}_dec_{filename}")
        try:
            decrypt_file(tmp_enc_path, output_path, key)
            print(f"[DOWNLOAD] decrypt berhasil -> {output_path} (size={os.path.getsize(output_path)})")
        except Exception as ed:
            print("[DOWNLOAD ERROR] decrypt_file gagal:", repr(ed))
            flash(f"Gagal mendekripsi file: {ed}")
            # biarkan file .enc ada untuk debugging (tidak menghapusnya di sini)
            return redirect(url_for("files"))

        # Kirim file yang sudah didekripsi
        if not os.path.exists(output_path):
            print("[DOWNLOAD ERROR] file hasil dekripsi tidak ditemukan:", output_path)
            flash("File hasil dekripsi tidak ditemukan.")
            return redirect(url_for("files"))

        return send_from_directory(base_dir, os.path.basename(output_path), as_attachment=True)

    except Exception as e:
        print("[DOWNLOAD ERROR - unexpected]:", repr(e))
        flash(f"Gagal download file: {e}")
        return redirect(url_for("files"))
    finally:
        try:
            if tmp_enc_path and os.path.exists(tmp_enc_path):
                # simpan untuk debugging jika terjadi error, hapus hanya jika file sudah kecil/usang
                pass
        except Exception as e:
            print("DOWNLOAD ERROR:", repr(e))
            flash(f"Gagal download file: {e}")
            return redirect(url_for("files"))




if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    cert_path = os.path.join(current_dir, "cert.pem")
    key_path = os.path.join(current_dir, "key.pem")
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        raise FileNotFoundError(f"File sertifikat TLS tidak ditemukan di {current_dir}")
    app.run(host="127.0.0.1", port=5000, ssl_context=(cert_path, key_path), debug=True)