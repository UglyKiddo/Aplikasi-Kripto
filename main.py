import tkinter as tk
from tkinter import filedialog, messagebox
import os
from base64 import b64encode, b64decode
from login import hash_password, check_login
from crypto_text import xor_cipher
from crypto_file import encrypt_file, decrypt_file
from database import init_db, save_message_plain, read_and_decrypt_messages, derive_key
from stego import encode_lsb, decode_lsb

DB_PATH = "secure.db"
init_db(DB_PATH)

def load_aes_key():
    password = "admin123"
    salt_path = "salt.bin"
    if os.path.exists(salt_path):
        salt = open(salt_path, "rb").read()
    else:
        _, salt = derive_key(password)
        open(salt_path, "wb").write(salt)
    key, _ = derive_key(password, salt)
    return key

key = load_aes_key()
stored_hash = hash_password("admin123")

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

def do_login():
    pwd = entry_pwd.get()
    if check_login(pwd, stored_hash):
        entry_pwd.delete(0, tk.END)
        login_frame.pack_forget()
        main_frame.pack(fill="both", expand=True, pady=10)
    else:
        messagebox.showerror("Login", "Password salah")

login_frame = tk.Frame(root, bg=BG_COLOR)
tk.Label(login_frame, text="Masukkan Password", font=FONT_TITLE, bg=BG_COLOR).pack(pady=20)
entry_pwd = tk.Entry(login_frame, show="*", font=FONT_NORMAL, width=30, justify="center")
entry_pwd.pack(pady=10)
btn_login = tk.Button(login_frame, text="Login", font=FONT_NORMAL, bg=BTN_COLOR, fg="white", width=20, command=do_login)
btn_login.pack(pady=15)
btn_login.bind("<Enter>", hover_in)
btn_login.bind("<Leave>", hover_out)
login_frame.pack(fill="both", expand=True)

def encrypt_message():
    msg = entry_msg.get("1.0", tk.END).strip()
    if not msg:
        return messagebox.showwarning("Error", "Masukkan pesan!")
    xor_res = xor_cipher(msg.encode(), 23)
    save_message_plain(DB_PATH, xor_res.decode(errors="ignore"), key)
    entry_msg.delete("1.0", tk.END)
    messagebox.showinfo("Sukses", "Pesan terenkripsi dan disimpan")

def show_messages():
    data = read_and_decrypt_messages(DB_PATH, key)
    output.delete("1.0", tk.END)
    for dec in data:
        try:
            final = xor_cipher(dec.encode(), 23).decode(errors="ignore")
            output.insert(tk.END, final + "\n\n")
        except Exception as e:
            output.insert(tk.END, f"[Gagal dekripsi: {e}]\n\n")

def encrypt_file_gui():
    f = filedialog.askopenfilename()
    if f:
        out = f + ".enc"
        encrypt_file(f, out, key)
        messagebox.showinfo("File", f"File terenkripsi disimpan:\n{out}")

def decrypt_file_gui():
    f = filedialog.askopenfilename()
    if f:
        if not f.endswith(".enc"):
            return messagebox.showwarning("Peringatan", "Pilih file .enc!")
        out = f.replace(".enc", "_dec")
        try:
            decrypt_file(f, out, key)
            messagebox.showinfo("File", f"File didekripsi disimpan:\n{out}")
        except Exception as e:
            messagebox.showerror("Error", f"Gagal dekripsi:\n{e}")

def stego_encode_gui():
    img = filedialog.askopenfilename(filetypes=[("BMP Images", "*.bmp")])
    msg = entry_msg.get("1.0", tk.END).strip()
    if not img or not msg:
        return
    out = "hasil_stego.bmp"
    try:
        encode_lsb(img, msg, out)
        messagebox.showinfo("Steganografi", f"Pesan disisipkan ke {out}")
        entry_msg.delete("1.0", tk.END)
    except Exception as e:
        messagebox.showerror("Error", f"Gagal menyisipkan: {e}")

def stego_decode_gui():
    img = filedialog.askopenfilename(filetypes=[("BMP Images", "*.bmp")])
    if img:
        result = decode_lsb(img)
        messagebox.showinfo("Pesan Tersembunyi", result)

main_frame = tk.Frame(root, bg=BG_COLOR)
tk.Label(main_frame, text="Pesan Rahasia", font=FONT_TITLE, bg=BG_COLOR).pack(pady=10)
entry_msg = tk.Text(main_frame, height=4, width=60, font=FONT_NORMAL, wrap="word")
entry_msg.pack(pady=5)

msg_button_frame = tk.Frame(main_frame, bg=BG_COLOR)
msg_button_frame.pack(pady=5)
btn_encrypt = tk.Button(msg_button_frame, text="Enkripsi & Simpan", bg=BTN_COLOR, fg="white", font=FONT_NORMAL, width=25, command=encrypt_message)
btn_decrypt = tk.Button(msg_button_frame, text="Tampilkan Pesan", bg=BTN_COLOR, fg="white", font=FONT_NORMAL, width=25, command=show_messages)
btn_encrypt.grid(row=0, column=0, padx=5)
btn_decrypt.grid(row=0, column=1, padx=5)
for b in (btn_encrypt, btn_decrypt):
    b.bind("<Enter>", hover_in)
    b.bind("<Leave>", hover_out)

output = tk.Text(main_frame, height=7, width=70, font=FONT_NORMAL, wrap="word")
output.pack(pady=5)

tk.Label(main_frame, text="Enkripsi / Dekripsi File", font=FONT_TITLE, bg=BG_COLOR).pack(pady=8)
file_button_frame = tk.Frame(main_frame, bg=BG_COLOR)
file_button_frame.pack(pady=5)
btn_enc_file = tk.Button(file_button_frame, text="Enkripsi File", bg=BTN_COLOR, fg="white", font=FONT_NORMAL, width=25, command=encrypt_file_gui)
btn_dec_file = tk.Button(file_button_frame, text="Dekripsi File", bg=BTN_COLOR, fg="white", font=FONT_NORMAL, width=25, command=decrypt_file_gui)
btn_enc_file.grid(row=0, column=0, padx=5)
btn_dec_file.grid(row=0, column=1, padx=5)
for b in (btn_enc_file, btn_dec_file):
    b.bind("<Enter>", hover_in)
    b.bind("<Leave>", hover_out)

tk.Label(main_frame, text="Steganografi BMP", font=FONT_TITLE, bg=BG_COLOR).pack(pady=8)
stego_button_frame = tk.Frame(main_frame, bg=BG_COLOR)
stego_button_frame.pack(pady=5)
btn_steg_encode = tk.Button(stego_button_frame, text="Sisipkan Pesan ke Gambar", bg=BTN_COLOR, fg="white", font=FONT_NORMAL, width=25, command=stego_encode_gui)
btn_steg_decode = tk.Button(stego_button_frame, text="Baca Pesan Tersembunyi", bg=BTN_COLOR, fg="white", font=FONT_NORMAL, width=25, command=stego_decode_gui)
btn_steg_encode.grid(row=0, column=0, padx=5)
btn_steg_decode.grid(row=0, column=1, padx=5)
for b in (btn_steg_encode, btn_steg_decode):
    b.bind("<Enter>", hover_in)
    b.bind("<Leave>", hover_out)

main_frame.pack_forget()
root.mainloop()