"""Draws icon.ico / icon.png: a big black key on an amber tile. Run: python make_icon.py"""
from PIL import Image, ImageDraw

S = 512
im = Image.new("RGBA", (S, S), (0, 0, 0, 0))
ImageDraw.Draw(im).rounded_rectangle((8, 8, S - 8, S - 8), 96, fill=(250, 204, 21))

K = (12, 12, 12, 255)
k = Image.new("RGBA", (640, 220), (0, 0, 0, 0))
kd = ImageDraw.Draw(k)
kd.rounded_rectangle((190, 78, 640, 142), 22, fill=K)  # shaft
kd.rectangle((500, 120, 548, 214), fill=K)             # teeth
kd.rectangle((574, 120, 622, 184), fill=K)
kd.ellipse((0, 0, 220, 220), fill=K)                   # bow
kd.ellipse((66, 66, 154, 154), fill=(0, 0, 0, 0))      # bow hole
k = k.resize((500, 172), Image.LANCZOS).rotate(45, expand=True, resample=Image.BICUBIC)
im.alpha_composite(k, ((S - k.width) // 2, (S - k.height) // 2))

im.save("icon.ico", sizes=[(s, s) for s in (16, 24, 32, 48, 64, 128, 256)])
im.save("icon.png")
