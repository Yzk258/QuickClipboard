from PIL import Image, ImageDraw

import os

CLIPBOARD_FILL = (49, 50, 68, 255)
CLIPBOARD_OUTLINE = (137, 180, 250, 255)
CLIP_FILL = (137, 180, 250, 255)
LINE_FILL = (166, 173, 200, 255)
LOCK_FILL = (249, 226, 175, 255)

SIZE = 512

ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets")


def rounded(draw, box, radius, **kwargs):
    draw.rounded_rectangle(box, radius=radius, **kwargs)


def make_icon():
    os.makedirs(ASSETS_DIR, exist_ok=True)
    ico_path = os.path.join(ASSETS_DIR, "app.ico")

    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    rounded(draw, [96, 72, 416, 456], radius=30, fill=CLIPBOARD_FILL,
            outline=CLIPBOARD_OUTLINE, width=10)

    rounded(draw, [196, 36, 316, 104], radius=20, fill=CLIP_FILL)

    for y in (160, 212):
        rounded(draw, [150, y, 362, y + 18], radius=9, fill=LINE_FILL)

    lock_cx = 256
    shackle = [lock_cx - 34, 268, lock_cx + 34, 336]
    draw.arc(shackle, start=180, end=360, fill=LOCK_FILL, width=16)
    rounded(draw, [lock_cx - 52, 328, lock_cx + 52, 420], radius=16, fill=LOCK_FILL)
    keyhole = [lock_cx - 8, 358, lock_cx + 8, 394]
    rounded(draw, keyhole, radius=8, fill=CLIPBOARD_FILL)

    img.save(ico_path, sizes=[(16, 16), (24, 24), (32, 32), (48, 48),
                              (64, 64), (128, 128), (256, 256)])
    print(f"icon generated: {os.path.abspath(ico_path)}")


if __name__ == "__main__":
    make_icon()
