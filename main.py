import tkinter as tk
from tkinter import filedialog, messagebox
import os
from base64 import b64encode, b64decode

from login import hash_password, check_login
from crypto_text import xor_cipher
from crypto_file import encrypt_file, decrypt_file
from database import init_db, save_message_plain, read_and_decrypt_messages, derive_key, MYSQL_CONFIG
from stego import encode_lsb, decode_lsb

import mysql.connector

# init DB (MySQL auto-create)
init_db()

# AES key dari password tetap
def load_aes_key():
    password = "admin123"
    salt_path = "salt.bin"

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

# GUI
root = tk.Tk()
root.title("Aplikasi Kriptografi Aman")

w, h = 700, 600
sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
x, y = int((sw - w) / 2), int((sh - h) / 2)
root.geometry(f"{w}x{h}+{x}+{y}")
root.config(bg="#E8F0FE")

FONT_TITLE = ("Segoe UI", 14, "bold")
FONT_NORMAL = ("Segoe UI", 10)
BTN_COLOR = "#1976D2"
BTN_HOVER = "#1565C0"
BG_COLOR = "#E8F0FE"

def hover_in(e): e.widget.config(bg=BTN_HOVER)
def hover_out(e): e.widget.config(bg=BTN_COLOR)

# -----------------------
# Login & Register
# -----------------------
def register_user():
    username = entry_reg_user.get().strip()
    password = entry_reg_pass.get().strip()
    if not username or not password:
        return messagebox.showwarning("Error", "Username dan password wajib diisi!")
    pw_hash = hash_password(password)
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, pw_hash))
        conn.commit()
    except mysql.connector.IntegrityError:
        messagebox.showerror("Error", "Username sudah terpakai!")
    except Exception as e:
        messagebox.showerror("Error", str(e))
    finally:
        try:
            c.close()
            conn.close()
        except:
            pass
    entry_reg_user.delete(0, tk.END)
    entry_reg_pass.delete(0, tk.END)
    messagebox.showinfo("Sukses", "Akun berhasil dibuat!")

def do_login():
    username = entry_login_user.get().strip()
    password = entry_login_pass.get().strip()
    if not username or not password:
        return messagebox.showwarning("Error", "Isi username dan password")
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        c = conn.cursor()
        c.execute("SELECT password_hash FROM users WHERE username=%s", (username,))
        row = c.fetchone()
    except Exception as e:
        messagebox.showerror("Error DB", str(e))
        return
    finally:
        try:
            c.close()
            conn.close()
        except:
            pass
    if not row:
        return messagebox.showerror("Login", "Username tidak ditemukan")
    stored_hash = row[0]
    if check_login(password, stored_hash):
        login_frame.pack_forget()
        register_frame.pack_forget()
        main_frame.pack(fill="both", expand=True, pady=10)
    else:
        messagebox.showerror("Login", "Password salah")

# FRAME LOGIN
login_frame = tk.Frame(root, bg=BG_COLOR)
tk.Label(login_frame, text="Login", font=FONT_TITLE, bg=BG_COLOR).pack(pady=10)
tk.Label(login_frame, text="Username:", bg=BG_COLOR).pack()
entry_login_user = tk.Entry(login_frame, font=FONT_NORMAL, width=30)
entry_login_user.pack(pady=5)
tk.Label(login_frame, text="Password:", bg=BG_COLOR).pack()
entry_login_pass = tk.Entry(login_frame, font=FONT_NORMAL, show="*", width=30)
entry_login_pass.pack(pady=5)
btn_login = tk.Button(login_frame, text="Login", font=FONT_NORMAL, bg=BTN_COLOR, fg="white",
                      width=20, command=do_login)
btn_login.pack(pady=10)
btn_login.bind("<Enter>", hover_in)
btn_login.bind("<Leave>", hover_out)
tk.Button(login_frame, text="Buat Akun Baru", font=FONT_NORMAL,
          command=lambda: (login_frame.pack_forget(), register_frame.pack(fill="both", expand=True))
          ).pack(pady=5)
login_frame.pack(fill="both", expand=True)

# FRAME REGISTER
register_frame = tk.Frame(root, bg=BG_COLOR)
tk.Label(register_frame, text="Buat Akun", font=FONT_TITLE, bg=BG_COLOR).pack(pady=10)
tk.Label(register_frame, text="Username:", bg=BG_COLOR).pack()
entry_reg_user = tk.Entry(register_frame, font=FONT_NORMAL, width=30)
entry_reg_user.pack(pady=5)
tk.Label(register_frame, text="Password:", bg=BG_COLOR).pack()
entry_reg_pass = tk.Entry(register_frame, font=FONT_NORMAL, width=30, show="*")
entry_reg_pass.pack(pady=5)
btn_reg = tk.Button(register_frame, text="Registrasi", font=FONT_NORMAL,
                    bg=BTN_COLOR, fg="white", width=20, command=register_user)
btn_reg.pack(pady=10)
btn_reg.bind("<Enter>", hover_in)
btn_reg.bind("<Leave>", hover_out)
tk.Button(register_frame, text="Kembali ke Login", font=FONT_NORMAL,
          command=lambda: (register_frame.pack_forget(), login_frame.pack(fill="both", expand=True))
          ).pack(pady=5)

# -----------------------
# Main functions
# -----------------------
def encrypt_message():
    msg = entry_msg.get("1.0", "end-1c").strip()
    if not msg:
        return messagebox.showwarning("Error", "Masukkan pesan!")
    xor_res = xor_cipher(msg.encode(), 23)       # bytes
    b64_data = b64encode(xor_res).decode()       # base64 string
    try:
        save_message_plain(b64_data, key)            # MySQL version: (plaintext_b64, key)
    except Exception as e:
        return messagebox.showerror("Error DB", str(e))
    entry_msg.delete("1.0", tk.END)
    messagebox.showinfo("Sukses", "Pesan terenkripsi disimpan")

def show_messages():
    try:
        data = read_and_decrypt_messages(key)  # returns list of plaintext_b64 strings
    except Exception as e:
        return messagebox.showerror("Error DB", str(e))
    output.delete("1.0", tk.END)
    for item in data:
        if isinstance(item, str) and item.startswith("[DECRYPTION_FAILED"):
            output.insert(tk.END, item + "\n\n")
            continue
        try:
            raw = b64decode(item)                 # xor bytes
            plain = xor_cipher(raw, 23).decode(errors="ignore")
            output.insert(tk.END, plain + "\n\n")
        except Exception as e:
            output.insert(tk.END, f"[Gagal dekripsi: {e}]\n\n")

def encrypt_file_gui():
    f = filedialog.askopenfilename()
    if f:
        out = f + ".enc"
        encrypt_file(f, out, key)
        messagebox.showinfo("File", "File terenkripsi disimpan:\n" + out)

def decrypt_file_gui():
    f = filedialog.askopenfilename()
    if f and f.endswith(".enc"):
        out = f.replace(".enc", "_dec")
        try:
            decrypt_file(f, out, key)
            messagebox.showinfo("File", "File didekripsi disimpan:\n" + out)
        except Exception as e:
            messagebox.showerror("Error", str(e))

def stego_encode_gui():
    img = filedialog.askopenfilename(filetypes=[("BMP Images", "*.bmp")])
    if not img:
        return messagebox.showwarning("Error", "Pilih gambar BMP terlebih dahulu!")
    msg = entry_msg.get("1.0", "end-1c").strip()
    if not msg:
        return messagebox.showwarning("Error", "Masukkan pesan untuk disisipkan!")
    try:
        out_real = encode_lsb(img, msg, "hasil_stego.bmp")
        messagebox.showinfo("Stego", f"Pesan disisipkan ke {out_real}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def stego_decode_gui():
    img = filedialog.askopenfilename(filetypes=[("BMP Images", "*.bmp")])
    if not img:
        return
    try:
        result = decode_lsb(img)
    except Exception as e:
        return messagebox.showerror("Error", str(e))
    if not result:
        result = "(Gambar tidak memuat pesan)"
    messagebox.showinfo("Pesan Tersembunyi", result)

# FRAME UTAMA
main_frame = tk.Frame(root, bg=BG_COLOR)
tk.Label(main_frame, text="Pesan Rahasia", font=FONT_TITLE, bg=BG_COLOR).pack(pady=10)
entry_msg = tk.Text(main_frame, height=4, width=60, font=FONT_NORMAL)
entry_msg.pack(pady=5)

msg_btn_frame = tk.Frame(main_frame, bg=BG_COLOR)
msg_btn_frame.pack()
tk.Button(msg_btn_frame, text="Enkripsi & Simpan", width=25,
          bg=BTN_COLOR, fg="white", command=encrypt_message).grid(row=0, column=0, padx=5)
tk.Button(msg_btn_frame, text="Tampilkan Pesan", width=25,
          bg=BTN_COLOR, fg="white", command=show_messages).grid(row=0, column=1, padx=5)

output = tk.Text(main_frame, height=7, width=70, font=FONT_NORMAL)
output.pack(pady=10)

tk.Label(main_frame, text="Enkripsi / Dekripsi File", font=FONT_TITLE, bg=BG_COLOR).pack()
file_frame = tk.Frame(main_frame, bg=BG_COLOR)
file_frame.pack(pady=5)
tk.Button(file_frame, text="Enkripsi File", width=25,
          bg=BTN_COLOR, fg="white", command=encrypt_file_gui).grid(row=0, column=0, padx=5)
tk.Button(file_frame, text="Dekripsi File", width=25,
          bg=BTN_COLOR, fg="white", command=decrypt_file_gui).grid(row=0, column=1, padx=5)

tk.Label(main_frame, text="Steganografi BMP", font=FONT_TITLE, bg=BG_COLOR).pack(pady=10)
stego_frame = tk.Frame(main_frame, bg=BG_COLOR)
stego_frame.pack()
tk.Button(stego_frame, text="Sisipkan Pesan ke Gambar", width=25,
          bg=BTN_COLOR, fg="white", command=stego_encode_gui).grid(row=0, column=0, padx=5)
tk.Button(stego_frame, text="Baca Pesan Tersembunyi", width=25,
          bg=BTN_COLOR, fg="white", command=stego_decode_gui).grid(row=0, column=1, padx=5)

main_frame.pack_forget()
root.mainloop()