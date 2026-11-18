"""Tiny renderer shared by the two guide generators: content blocks -> ReportLab PDF story and -> HTML.

Content is a list of blocks (tuples):
    ("h1", text) ("h2", text) ("p", text) ("ul", [text, ...]) ("note", text) ("code", text)
    ("table", [header cells], [[row cells], ...], [column width fractions])  ("pagebreak",)
Inline markup inside text: **bold**, `code`. Everything else is plain text and is escaped, so "&" and "<" are safe.
Only core PDF fonts are used, so keep text to ASCII plus common Western punctuation.
"""
import html
import re
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle,
)

_TOKEN = re.compile(r"(\*\*.+?\*\*|`[^`]+`)")

NAVY = colors.HexColor("#0B132B")
BLUE = colors.HexColor("#2563EB")
SLATE = colors.HexColor("#1E293B")
MUTED = colors.HexColor("#64748B")
BORDER = colors.HexColor("#CBD5E1")
CARD = colors.HexColor("#F1F5F9")
NOTE_BG = colors.HexColor("#FFFBEB")
NOTE_BORDER = colors.HexColor("#D97706")


def _inline(text, mode):
    """Convert **bold** and `code` markup, escaping everything else, for 'pdf' (ReportLab) or 'html'."""
    out = []
    esc = xml_escape if mode == "pdf" else html.escape
    for part in _TOKEN.split(text):
        if part.startswith("**") and part.endswith("**") and len(part) > 4:
            out.append(f"<b>{esc(part[2:-2])}</b>")
        elif part.startswith("`") and part.endswith("`") and len(part) > 2:
            inner = esc(part[1:-1])
            out.append(f'<font name="Courier" size="8.5">{inner}</font>' if mode == "pdf" else f"<code>{inner}</code>")
        else:
            out.append(esc(part))
    return "".join(out)


class GuideCanvas(canvas.Canvas):
    """Two-pass canvas: header and footer with page numbers (not on the cover page)."""
    header_left = ""
    header_right = ""
    footer_left = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._states = []

    def showPage(self):
        self._states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._states)
        for state in self._states:
            self.__dict__.update(state)
            self._decorate(total)
            super().showPage()
        super().save()

    def _decorate(self, total):
        if self._pageNumber == 1:
            return
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(MUTED)
        self.drawString(40, 755, self.header_left)
        self.drawRightString(letter[0] - 40, 755, self.header_right)
        self.setStrokeColor(BORDER)
        self.line(40, 747, letter[0] - 40, 747)
        self.line(40, 42, letter[0] - 40, 42)
        self.drawString(40, 28, self.footer_left)
        self.drawRightString(letter[0] - 40, 28, f"Page {self._pageNumber} of {total}")
        self.restoreState()


def _styles():
    base = getSampleStyleSheet()["Normal"]
    mk = lambda name, **kw: ParagraphStyle(name, parent=base, **kw)  # noqa: E731
    return {
        "title": mk("t", fontName="Helvetica-Bold", fontSize=26, leading=30, textColor=NAVY, spaceAfter=8),
        "sub": mk("s", fontName="Helvetica", fontSize=12, leading=16, textColor=BLUE, spaceAfter=10),
        "h1": mk("h1", fontName="Helvetica-Bold", fontSize=16, leading=20, textColor=NAVY, spaceBefore=14, spaceAfter=8, keepWithNext=True),
        "h2": mk("h2", fontName="Helvetica-Bold", fontSize=12, leading=16, textColor=BLUE, spaceBefore=10, spaceAfter=5, keepWithNext=True),
        "p": mk("p", fontName="Helvetica", fontSize=9.5, leading=14, textColor=SLATE, spaceAfter=6),
        "li": mk("li", fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=SLATE, leftIndent=16, firstLineIndent=-10, spaceAfter=3),
        "cell": mk("c", fontName="Helvetica", fontSize=8.3, leading=11, textColor=SLATE),
        "head": mk("th", fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=colors.white),
        "code": ParagraphStyle("code", parent=base, fontName="Courier", fontSize=7.4, leading=9, textColor=colors.HexColor("#0F172A")),
        "meta": mk("m", fontName="Helvetica", fontSize=9.5, leading=14, textColor=SLATE),
    }


def build_pdf(path, cover, blocks, header_left, header_right, footer_left):
    """cover = dict(title, subtitle, lines=[...], meta=[(label, value), ...])"""
    st = _styles()
    width = letter[0] - 80
    story = [Spacer(1, 60), Paragraph(_inline(cover["title"], "pdf"), st["title"]),
             Paragraph(_inline(cover["subtitle"], "pdf"), st["sub"]),
             HRFlowable(width="100%", thickness=2, color=BLUE, spaceBefore=4, spaceAfter=14)]
    for line in cover.get("lines", []):
        story.append(Paragraph(_inline(line, "pdf"), st["p"]))
    if cover.get("meta"):
        rows = [[Paragraph(f"<b>{xml_escape(k)}</b>", st["cell"]), Paragraph(_inline(v, "pdf"), st["cell"])] for k, v in cover["meta"]]
        table = Table(rows, colWidths=[width * 0.28, width * 0.72])
        table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, BORDER), ("BACKGROUND", (0, 0), (0, -1), CARD),
                                   ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        story += [Spacer(1, 14), table]
    story.append(PageBreak())

    for block in blocks:
        kind = block[0]
        if kind in ("h1", "h2", "p"):
            story.append(Paragraph(_inline(block[1], "pdf"), st[kind]))
        elif kind == "ul":
            for item in block[1]:
                story.append(Paragraph("&bull; " + _inline(item, "pdf"), st["li"]))
            story.append(Spacer(1, 3))
        elif kind == "note":
            cell = Paragraph(_inline(block[1], "pdf"), st["cell"])
            table = Table([[cell]], colWidths=[width])
            table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), NOTE_BG), ("LINEBEFORE", (0, 0), (0, -1), 3, NOTE_BORDER),
                                       ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6), ("LEFTPADDING", (0, 0), (-1, -1), 10)]))
            story += [table, Spacer(1, 8)]
        elif kind == "code":
            table = Table([[Preformatted(block[1].strip("\n"), st["code"])]], colWidths=[width])
            table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), CARD), ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
                                       ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
            story += [table, Spacer(1, 8)]
        elif kind == "table":
            _, header, rows, fractions = block
            data = [[Paragraph(_inline(h, "pdf"), st["head"]) for h in header]]
            data += [[Paragraph(_inline(c, "pdf"), st["cell"]) for c in row] for row in rows]
            table = Table(data, colWidths=[width * f for f in fractions], repeatRows=1)
            table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
                                       ("VALIGN", (0, 0), (-1, -1), "TOP"), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, CARD]),
                                       ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
            story += [table, Spacer(1, 10)]
        elif kind == "pagebreak":
            story.append(PageBreak())
        else:
            raise ValueError(f"unknown block {kind}")

    class _Canvas(GuideCanvas):
        pass

    _Canvas.header_left, _Canvas.header_right, _Canvas.footer_left = header_left, header_right, footer_left
    doc = SimpleDocTemplate(path, pagesize=letter, leftMargin=40, rightMargin=40, topMargin=48, bottomMargin=50,
                            title=cover["title"], author="Phantom SOAR")
    doc.build(story, canvasmaker=_Canvas)


_HTML_CSS = """
:root { --navy:#0B132B; --blue:#2563EB; --slate:#334155; --muted:#64748B; --card:#F8FAFC; --border:#E2E8F0; --amber:#D97706; --amber-soft:#FFFBEB; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; color: var(--slate); background: #F1F5F9; line-height: 1.6; padding: 40px 20px; }
.container { max-width: 960px; margin: 0 auto; background: #fff; padding: 56px 48px; border-radius: 12px; border: 1px solid var(--border); }
h1.title { font-size: 34px; color: var(--navy); margin-bottom: 6px; }
.subtitle { color: var(--blue); font-size: 16px; margin-bottom: 18px; }
h2 { color: var(--navy); font-size: 24px; margin: 38px 0 12px; padding-bottom: 6px; border-bottom: 2px solid var(--border); }
h3 { color: var(--blue); font-size: 17px; margin: 22px 0 8px; }
p { margin-bottom: 12px; } ul { margin: 0 0 14px 22px; } li { margin-bottom: 5px; }
table { width: 100%; border-collapse: collapse; margin: 14px 0 22px; font-size: 14px; }
th { background: var(--navy); color: #fff; text-align: left; padding: 8px 10px; }
td { padding: 8px 10px; border: 1px solid var(--border); vertical-align: top; }
tr:nth-child(even) td { background: var(--card); }
pre { background: var(--card); border: 1px solid var(--border); padding: 12px 14px; overflow-x: auto; font-size: 12.5px; margin-bottom: 16px; }
code { font-family: SFMono-Regular, Consolas, Menlo, monospace; font-size: 0.92em; background: #EEF2F7; padding: 1px 4px; border-radius: 3px; }
pre code { background: none; padding: 0; }
.note { background: var(--amber-soft); border-left: 4px solid var(--amber); padding: 10px 14px; margin: 14px 0 18px; }
.meta td:first-child { width: 26%; font-weight: 600; background: var(--card); }
footer { margin-top: 40px; padding-top: 14px; border-top: 1px solid var(--border); color: var(--muted); font-size: 13px; }
nav.toc { background: var(--card); border: 1px solid var(--border); padding: 12px 18px; margin: 20px 0 8px; }
nav.toc a { color: var(--blue); text-decoration: none; } nav.toc li { list-style: none; margin: 3px 0; }
"""


def build_html(path, cover, blocks, footer):
    out = ['<!DOCTYPE html>', '<html lang="en">', '<head>', '<meta charset="UTF-8">',
           '<meta name="viewport" content="width=device-width, initial-scale=1.0">',
           f"<title>{html.escape(cover['title'])}</title>", f"<style>{_HTML_CSS}</style>", "</head>", "<body>",
           '<div class="container">', f'<h1 class="title">{_inline(cover["title"], "html")}</h1>',
           f'<div class="subtitle">{_inline(cover["subtitle"], "html")}</div>']
    for line in cover.get("lines", []):
        out.append(f"<p>{_inline(line, 'html')}</p>")
    if cover.get("meta"):
        out.append('<table class="meta">' + "".join(f"<tr><td>{html.escape(k)}</td><td>{_inline(v, 'html')}</td></tr>" for k, v in cover["meta"]) + "</table>")
    headings = []
    for block in blocks:
        if block[0] == "h1":
            headings.append(block[1])
    out.append('<nav class="toc"><strong>Contents</strong><ul>' + "".join(
        f'<li><a href="#s{i}">{_inline(h, "html")}</a></li>' for i, h in enumerate(headings, 1)) + "</ul></nav>")
    n = 0
    for block in blocks:
        kind = block[0]
        if kind == "h1":
            n += 1
            out.append(f'<h2 id="s{n}">{_inline(block[1], "html")}</h2>')
        elif kind == "h2":
            out.append(f"<h3>{_inline(block[1], 'html')}</h3>")
        elif kind == "p":
            out.append(f"<p>{_inline(block[1], 'html')}</p>")
        elif kind == "ul":
            out.append("<ul>" + "".join(f"<li>{_inline(i, 'html')}</li>" for i in block[1]) + "</ul>")
        elif kind == "note":
            out.append(f'<div class="note">{_inline(block[1], "html")}</div>')
        elif kind == "code":
            out.append(f"<pre><code>{html.escape(block[1].strip(chr(10)))}</code></pre>")
        elif kind == "table":
            _, header, rows, _fractions = block
            out.append("<table><tr>" + "".join(f"<th>{_inline(h, 'html')}</th>" for h in header) + "</tr>"
                       + "".join("<tr>" + "".join(f"<td>{_inline(c, 'html')}</td>" for c in row) + "</tr>" for row in rows) + "</table>")
        elif kind == "pagebreak":
            continue
        else:
            raise ValueError(f"unknown block {kind}")
    out.append(f"<footer>{_inline(footer, 'html')}</footer></div></body></html>")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(out) + "\n")
