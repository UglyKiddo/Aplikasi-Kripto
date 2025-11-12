from PIL import Image
import os

TERMINATOR = '11111111111111101111111111111110'  # lebih panjang agar aman

def encode_lsb(image_path, message, output_path="hasil_stego.bmp"):
    """
    Menyisipkan pesan ke gambar menggunakan LSB, hanya format BMP (24-bit) untuk memastikan bit tidak dikompresi.
    """
    img = Image.open(image_path).convert("RGB")
    w, h = img.size

    # ubah pesan menjadi biner
    msg_bytes = message.encode("utf-8") if isinstance(message, str) else bytes(message)
    binary = ''.join(f'{b:08b}' for b in msg_bytes) + TERMINATOR

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

def decode_lsb(image_path):
    img = Image.open(image_path).convert("RGB")
    w, h = img.size
    pixels = img.load()
    bits = []
    for y in range(h):
        for x in range(w):
            r, g, b = pixels[x, y]
            bits.append(str(r & 1))
            bits.append(str(g & 1))
            bits.append(str(b & 1))
            if len(bits) >= len(TERMINATOR) and ''.join(bits[-len(TERMINATOR):]) == TERMINATOR:
                binary = ''.join(bits[:-len(TERMINATOR)])
                img.close()
                data = bytearray(int(binary[i:i+8], 2) for i in range(0, len(binary), 8))
                try:
                    return data.decode('utf-8')
                except UnicodeDecodeError:
                    return data.decode('latin1')
    img.close()
    return ""