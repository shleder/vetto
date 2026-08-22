#!/usr/bin/env python3
"""Render vetto README banner art (project-native, dark terminal look)."""
import sys
from PIL import Image, ImageDraw, ImageFilter, ImageFont

CANDIDATES_BOLD = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf",
]
CANDIDATES_REG = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
]

def pick(cands):
    for c in cands:
        try:
            ImageFont.truetype(c, 40)
            return c
        except Exception:
            continue
    print("NO FONT FOUND", file=sys.stderr)
    sys.exit(1)

FB = pick(CANDIDATES_BOLD)
FR = pick(CANDIDATES_REG)
print("bold:", FB)
print("reg :", FR)

WHITE = (255, 255, 255, 255)
TXT   = (230, 237, 243, 255)
GRAY  = (139, 148, 158, 255)
DIM   = (110, 119, 129, 255)
CYAN  = (77, 208, 225, 255)
GREEN = (63, 185, 80, 255)
RED   = (248, 81, 73, 255)
REDSL = (255, 138, 128, 255)
BG    = (13, 17, 23)
BAR   = (22, 27, 34)
LINE  = (48, 54, 67)

def font(path, size):
    return ImageFont.truetype(path, size)

def spaced_width(d, text, f, ls):
    return sum(d.textlength(c, font=f) for c in text) + ls * max(0, len(text) - 1)

def draw_spaced(d, xy, text, f, fill, ls=0):
    x, y = xy
    for ch in text:
        d.text((x, y), ch, font=f, fill=fill)
        x += d.textlength(ch, font=f) + ls

def add_glow(img, xy, text, f, ls, color, blur, alpha):
    layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
    draw_spaced(ImageDraw.Draw(layer), xy, text, f, color[:3] + (alpha,), ls)
    layer = layer.filter(ImageFilter.GaussianBlur(blur))
    return Image.alpha_composite(img, layer)

def scanlines(img, step=6, alpha=5):
    layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    for y in range(0, img.height, step):
        d.line([(0, y), (img.width, y)], fill=(255, 255, 255, alpha))
    return Image.alpha_composite(img, layer)

def round_corners(img, r):
    from PIL import ImageDraw as _D
    mask = Image.new("L", img.size, 0)
    d = _D.Draw(mask)
    d.rounded_rectangle([0, 0, img.width - 1, img.height - 1], radius=r, fill=255)
    out = img.copy()
    out.putalpha(mask)
    return out

# ---------------------------------------------------------------- hero ------
def hero():
    W, H = 2400, 800
    img = Image.new("RGBA", (W, H), BG)

    # ambient tints
    tint = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    td = ImageDraw.Draw(tint)
    td.ellipse([100, -200, 1500, 750], fill=(10, 34, 44, 255))   # cyan aura left
    td.ellipse([1500, 50, 2600, 850], fill=(46, 12, 14, 255))    # red aura right
    tint = tint.filter(ImageFilter.GaussianBlur(230))
    img = Image.alpha_composite(img, tint)
    img = scanlines(img)

    d = ImageDraw.Draw(img)

    # terminal chrome
    for i, c in enumerate([(255, 95, 87), (254, 188, 46), (40, 200, 64)]):
        d.ellipse([56 + i * 52, 44, 56 + i * 52 + 28, 44 + 28], fill=c)
    tf = font(FR, 40)
    title = "vetto session — tier=full net=off"
    d.text(((W - d.textlength(title, font=tf)) / 2, 40), title, font=tf, fill=DIM)

    # giant wordmark with glow
    wf = font(FB, 315)
    img = add_glow(img, (124, 140), "vetto", wf, 30, (210, 240, 255), 34, 140)
    d = ImageDraw.Draw(img)
    draw_spaced(d, (124, 140), "vetto", wf, WHITE, ls=30)

    # tagline
    gf = font(FR, 47)
    d.text((134, 520), "from \u201cveto\u201d \u2014 to forbid \u00b7 daemon-less sandbox + security layer for AI coding agents", font=gf, fill=GRAY)

    # kernel line, right-aligned
    kf = font(FR, 44)
    ktxt = "Landlock \u00b7 namespaces \u00b7 seccomp \u00b7 Seatbelt"
    d.text((W - 60 - d.textlength(ktxt, font=kf), 585), ktxt, font=kf, fill=CYAN)

    # VETO stamp
    st = Image.new("RGBA", (760, 360), (0, 0, 0, 0))
    sd = ImageDraw.Draw(st)
    sd.rounded_rectangle([20, 20, 740, 340], radius=30, outline=RED[:3] + (240,), width=18)
    sd.rounded_rectangle([48, 48, 712, 312], radius=20, outline=RED[:3] + (110,), width=6)
    sf = font(FB, 158)
    tw = spaced_width(sd, "VETO", sf, 36)
    x = (760 - tw) / 2
    for ch in "VETO":
        sd.text((x, 95), ch, font=sf, fill=RED)
        x += sd.textlength(ch, font=sf) + 36
    st = st.rotate(-11, expand=True, resample=Image.BICUBIC)
    img.alpha_composite(st, (1560, 55))

    # statusline bar
    bar_y = H - 118
    d = ImageDraw.Draw(img)
    d.rectangle([0, bar_y, W, H], fill=BAR)
    d.line([(0, bar_y), (W, bar_y)], fill=LINE, width=3)
    segs = [
        (" vetto ", WHITE, True),
        ("[tier=full]", GREEN, False),
        (" ", WHITE, False),
        ("[net=off]", GREEN, False),
        (" blocked=", TXT, False),
        ("4", RED, True),
        (" files=132 exec=18 | ", TXT, False),
        ("09:41 BLOCKED cat \u2192 ~/.ssh/id_rsa", REDSL, False),
    ]
    x = 40
    y = bar_y + 32
    for text, color, bold in segs:
        f = font(FB if bold else FR, 46)
        d.text((x, y), text, font=f, fill=color)
        x += d.textlength(text, font=f)

    return img.convert("RGB")

# --------------------------------------------------------------- sections ---
SECTIONS = [
    ("01", "WHY VETTO \u2014 WHEN AGENTS ALREADY SANDBOX THEMSELVES", "section-why"),
    ("02", "TWO TIERS \u2014 FULL AND FS-ONLY, HONEST REQUIREMENTS", "section-tiers"),
    ("03", "NETWORK \u2014 OFF BY DEFAULT, ALLOWLIST WITHOUT SNOOPING", "section-network"),
    ("04", "SEE EVERYTHING \u2014 STATUSLINE, EVENTS, AUDIT REPORTS", "section-visibility"),
    ("05", "START \u2014 ONE BINARY, ZERO DAEMONS", "section-start"),
]

def section(num, title, _name):
    W, H = 2400, 190
    img = Image.new("RGBA", (W, H), BG)
    img = scanlines(img, 10, 4)
    d = ImageDraw.Draw(img)
    nf = font(FB, 88)
    d.text((48, 34), num, font=nf, fill=CYAN)
    tf = font(FB, 62)
    draw_spaced(d, (190, 52), title, tf, WHITE, ls=6)
    d.line([(190, 152), (W - 60, 152)], fill=LINE, width=3)
    return img.convert("RGB")

# ---------------------------------------------------------- terminal demo ---
def terminal():
    W, H = 2400, 950
    img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, W - 1, H - 1], radius=34, fill=BG)

    # title bar (clipped to rounded top)
    bar = Image.new("RGBA", (W, 96), BAR)
    mask = Image.new("L", (W, 96), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, W - 1, 190], radius=34, fill=255)
    img.paste(bar, (0, 0), mask)

    d = ImageDraw.Draw(img)
    for i, c in enumerate([(255, 95, 87), (254, 188, 46), (40, 200, 64)]):
        d.ellipse([56 + i * 52, 34, 56 + i * 52 + 28, 34 + 28], fill=c)
    tf = font(FR, 40)
    t = 'vetto -- codex exec "refactor auth"'
    d.text(((W - d.textlength(t, font=tf)) / 2, 30), t, font=tf, fill=GRAY)

    lines = [
        (("$ ", DIM), ("vetto", WHITE), (" -- codex exec ", TXT), ('"refactor auth"', (165, 214, 167))),
        (("codex: reading project\u2026", GRAY),),
        (("codex: patching src/auth.rs", GRAY),),
        (("codex: running tests\u2026", GRAY),),
        (("\u00d7 BLOCKED [observe-seccomp] cat \u2192 ~/.ssh/id_rsa", RED),),
        (("\u00d7 BLOCKED [observe-seccomp] curl http://exfil.example", RED),),
        (("\u00b7 allowed: exec make \u00b7 read $HOME/.cargo/registry", DIM),),
        (("tests passed \u00b7 14 files changed", TXT),),
        (("vetto: report written: vetto-report-20260822-094103.html", CYAN),),
    ]
    y = 150
    f = font(FR, 46)
    fb = font(FB, 46)
    for line in lines:
        x = 64
        for text, color in line:
            d.text((x, y), text, font=f, fill=color)
            x += d.textlength(text, font=f)
        y += 74

    # statusline row inside the terminal
    bar_y = H - 118
    d.rectangle([0, bar_y, W, H], fill=(38, 50, 56))
    segs = [
        (" vetto ", WHITE, True),
        ("[tier=full]", (165, 214, 167), False),
        (" ", WHITE, False),
        ("[net=off]", (165, 214, 167), False),
        (" blocked=", WHITE, False),
        ("2", (255, 138, 128), True),
        (" files=89 exec=31 | ", WHITE, False),
        ("09:41 exec make test", (255, 138, 128), False),
    ]
    x = 64
    for text, color, bold in segs:
        ff = fb if bold else f
        d.text((x, bar_y + 30), text, font=ff, fill=color)
        x += d.textlength(text, font=ff)

    return img.convert("RGBA")

# ------------------------------------------------------------------ main ----
import os
out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)))
hero().save(os.path.join(out_dir, "hero.png"), optimize=True)
terminal().save(os.path.join(out_dir, "terminal-demo.png"), optimize=True)
for num, title, name in SECTIONS:
    section(num, title, name).save(os.path.join(out_dir, f"{name}.png"), optimize=True)
print("rendered:", os.listdir(out_dir))
