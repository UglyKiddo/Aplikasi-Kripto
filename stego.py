from PIL import Image
import os

TERMINATOR = "~~~END~~~"  # lebih panjang agar aman

def encode_lsb(image_path, message, output_path="hasil_stego.bmp"):
    """
    Menyisipkan pesan ke gambar menggunakan LSB, hanya format BMP (24-bit) untuk memastikan bit tidak dikompresi.
    """
    img = Image.open(image_path).convert("RGB")
    w, h = img.size

    # ubah pesan menjadi biner
    msg_bytes = message.encode("utf-8") if isinstance(message, str) else bytes(message)
    binary = ''.join(f'{ord(c):08b}' for c in message + TERMINATOR)

    if len(binary) > w * h * 3:
        img.close()
        raise ValueError("Pesan terlalu panjang untuk gambar ini.")

    pixels = img.load()
    idx = 0

    for y in range(h):
        for x in range(w):
            if idx >= len(binary):
                break
            r, g, b = pixels[x, y]
            r = (r & ~1) | int(binary[idx]) if idx < len(binary) else r; idx += 1
            g = (g & ~1) | int(binary[idx]) if idx < len(binary) else g; idx += 1
            b = (b & ~1) | int(binary[idx]) if idx < len(binary) else b; idx += 1
            pixels[x, y] = (r, g, b)
        if idx >= len(binary):
            break

    # pastikan output .bmp dan tidak overwrite file yang ada
    base, ext = os.path.splitext(output_path)
    if not ext or ext.lower() != ".bmp":
        output_path = base + ".bmp"

    counter = 1
    new_output = output_path
    while os.path.exists(new_output):
        new_output = f"{base}_{counter}.bmp"
        counter += 1

    # Simpan gambar baru (BMP tanpa kompresi)
    img.save(new_output, "BMP")
    img.close()

    # Pastikan file tersimpan dan tidak kosong
    if os.path.getsize(new_output) < 100:
        raise IOError("File stego tidak tersimpan dengan benar.")

    return new_output

def decode_lsb(path):
    img = Image.open(path).convert("RGB")
    w, h = img.size
    pixels = img.load()
    bits = []

    for y in range(h):
        for x in range(w):
            r, g, b = pixels[x, y]
            bits += [str(r & 1), str(g & 1), str(b & 1)]

    img.close()

    # ubah bits ke char
    chars = []
    for i in range(0, len(bits), 8):
        byte = int("".join(bits[i:i+8]), 2)
        chars.append(chr(byte))

    text = "".join(chars)

    if TERMINATOR not in text:
        return ""

    return text.split(TERMINATOR)[0]