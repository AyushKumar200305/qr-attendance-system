"""
qr_generator.py — QR code generator using qrcode library
Install: pip install qrcode pillow
"""
try:
    import qrcode
    from PIL import Image

    def encode_qr(text: str) -> Image.Image:
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=12, border=4)
        qr.add_data(text)
        qr.make(fit=True)
        return qr.make_image(fill_color="black", back_color="white").convert("RGB")

except ImportError:
    # Fallback — generate a placeholder image if qrcode not installed
    from PIL import Image, ImageDraw, ImageFont

    def encode_qr(text: str) -> Image.Image:
        img  = Image.new('RGB', (400, 400), 'white')
        draw = ImageDraw.Draw(img)
        draw.rectangle([20, 20, 380, 380], outline='black', width=3)
        draw.text((40, 180), "Install qrcode:", fill='black')
        draw.text((40, 210), "pip install qrcode", fill='black')
        draw.text((40, 240), text[:40], fill='gray')
        return img