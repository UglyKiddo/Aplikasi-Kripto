from PIL import Image
import os

TERMINATOR = '1111111111111110'

def encode_lsb(image_path, message, output_path="hasil_stego.bmp"):
    img = Image.open(image_path)
    img = img.convert("RGB")
    w, h = img.size

    # message -> bytes
    if isinstance(message, str):
        msg_bytes = message.encode('utf-8')
    elif isinstance(message, bytes):
        msg_bytes = message
    else:
        msg_bytes = str(message).encode('utf-8')

    binary = ''.join(f'{b:08b}' for b in msg_bytes) + TERMINATOR
    capacity = w * h * 3
    if len(binary) > capacity:
        raise ValueError("Pesan terlalu panjang untuk gambar ini.")

    pixels = list(img.getdata())
    new_pixels = []
    idx = 0

    for p in pixels:
        r, g, b = p
        if idx < len(binary):
            r = (r & ~1) | int(binary[idx]); idx += 1
        if idx < len(binary):
            g = (g & ~1) | int(binary[idx]); idx += 1
        if idx < len(binary):
            b = (b & ~1) | int(binary[idx]); idx += 1
        new_pixels.append((r, g, b))
        if idx >= len(binary):
            # append remaining pixels unchanged
            remaining = pixels[len(new_pixels):]
            if remaining:
                new_pixels.extend(remaining)
            break

    img.putdata(new_pixels)

    base, ext = os.path.splitext(output_path)
    if ext == "":
        ext = ".bmp"
    new_output = output_path
    counter = 1
    while os.path.exists(new_output):
        new_output = f"{base}{counter}{ext}"
        counter += 1

    img.save(new_output, format="BMP")
    img.close()
    return new_output


def decode_lsb(image_path):
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = list(img.getdata())

    bits = []
    for (r, g, b) in pixels:
        bits.append(str(r & 1))
        bits.append(str(g & 1))
        bits.append(str(b & 1))
        # check terminator efficiently on the fly
        if len(bits) >= len(TERMINATOR):
            if ''.join(bits[-len(TERMINATOR):]) == TERMINATOR:
                # build full binary string without terminator
                binary = ''.join(bits)[:-len(TERMINATOR)]
                data = bytearray()
                for i in range(0, len(binary), 8):
                    byte = binary[i:i+8]
                    if len(byte) < 8:
                        break
                    data.append(int(byte, 2))
                try:
                    return data.decode('utf-8')
                except UnicodeDecodeError:
                    return data.decode('latin1')
    return ""