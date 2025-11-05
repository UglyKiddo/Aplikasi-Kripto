from PIL import Image
import os

def encode_lsb(image_path, message, output_path="hasil_stego.bmp"):
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = img.load()
    w, h = img.size

    binary = ''.join(format(byte, '08b') for byte in message.encode('utf-8')) + '1111111111111110'
    if len(binary) > w * h * 3:
        raise ValueError("Pesan terlalu panjang untuk gambar ini.")

    base, ext = os.path.splitext(output_path)
    count = 1
    new_output = output_path
    while os.path.exists(new_output):
        count += 1
        new_output = f"{base}{count}{ext}"

    idx = 0
    for y in range(h):
        for x in range(w):
            if idx >= len(binary):
                break
            r, g, b = pixels[x, y]
            if idx < len(binary):
                r = (r & ~1) | int(binary[idx]); idx += 1
            if idx < len(binary):
                g = (g & ~1) | int(binary[idx]); idx += 1
            if idx < len(binary):
                b = (b & ~1) | int(binary[idx]); idx += 1
            pixels[x, y] = (r, g, b)
        if idx >= len(binary):
            break

    img.save(new_output, format="BMP", bits=24)
    img.close()
    return new_output


def decode_lsb(image_path):
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = img.load()
    w, h = img.size

    binary = ""
    for y in range(h):
        for x in range(w):
            r, g, b = pixels[x, y]
            binary += str(r & 1)
            binary += str(g & 1)
            binary += str(b & 1)
            if binary.endswith('1111111111111110'):
                binary = binary[:-16]
                data = bytearray()
                for i in range(0, len(binary), 8):
                    data.append(int(binary[i:i+8], 2))
                try:
                    return data.decode('utf-8')
                except UnicodeDecodeError:
                    return data.decode('latin1')
    return ""