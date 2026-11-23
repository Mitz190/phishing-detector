from datetime import datetime
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

_REPLACE = {"\u2019": "'", "\u2018": "'", "\u201c": '"', "\u201d": '"',
            "\u2013": "-", "\u2014": "-", "\u2026": "...", "\u00a0": " "}


def _t(value):
    """Make text safe for the built-in PDF fonts and for reportlab's mini-markup."""
    s = str(value if value is not None else "")
    for old, new in _REPLACE.items():
        s = s.replace(old, new)
    s = s.encode("latin-1", "replace").decode("latin-1")
    return escape(s)


ADVICE = {
    "High risk": "Do not click any links, open attachments, or reply. Do not enter passwords or payment details. Report the email as phishing to your email provider and delete it. If you already interacted with it, change your password and contact the company through its official website.",
    "Medium risk": "Be careful. Do not click links in this email. If it claims to be from a company or colleague, contact them using a phone number or website you already trust, not the details in the email.",
    "Low risk": "No strong warning signs were found, but no tool is perfect. If the email asks for money or passwords, or something feels off, verify it through another channel first.",
}


def build_pdf(data):
    score = int(data.get("score", 0))
    level = data.get("level", "Low risk")
    accent = {"High risk": "#dc2626", "Medium risk": "#ca8a04"}.get(level, "#16a34a")

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Title"], fontSize=20, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=13, spaceBefore=14, spaceAfter=6)
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=10.5, leading=15)
    small = ParagraphStyle("small", parent=body, fontSize=8.5, textColor=colors.grey, leading=11)

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
                            topMargin=18 * mm, bottomMargin=18 * mm,
                            title="Email Threat Analysis Report")
    story = [
        Paragraph("Email Threat Analysis Report", h1),
        Paragraph(datetime.now().strftime("Generated on %d %b %Y, %H:%M"), small),
        Spacer(1, 10),
    ]

    verdict = Table([[Paragraph(f'<font color="white"><b>{_t(level)}</b>  -  score {score}/100</font>',
                                ParagraphStyle("v", parent=body, fontSize=15, leading=20))]],
                    colWidths=[170 * mm])
    verdict.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(accent)),
                                 ("LEFTPADDING", (0, 0), (-1, -1), 12), ("TOPPADDING", (0, 0), (-1, -1), 10),
                                 ("BOTTOMPADDING", (0, 0), (-1, -1), 10)]))
    story += [verdict]

    if data.get("explanation"):
        story += [Paragraph("Summary", h2), Paragraph(_t(data["explanation"]), body)]

    auth = data.get("auth") or {}
    if auth and any(v != "not found" for v in auth.values()):
        line = "   ".join(f"{k.upper()}: {_t(v)}" for k, v in auth.items())
        story += [Paragraph("Sender authentication", h2), Paragraph(line, body)]

    story.append(Paragraph("Warning signs found", h2))
    findings = data.get("findings") or []
    if not findings:
        story.append(Paragraph("No red flags were detected.", body))
    for f in findings:
        story.append(Paragraph(f"<b>{_t(f.get('category'))}</b><br/>{_t(f.get('reason'))}", body))
        story.append(Spacer(1, 6))

    urls = data.get("urls") or []
    if urls:
        story.append(Paragraph("Links found in the email (do not click)", h2))
        for u in urls[:15]:
            story.append(Paragraph(_t(u), body))

    story += [Paragraph("What you should do", h2), Paragraph(_t(ADVICE.get(level, ADVICE["Low risk"])), body),
              Spacer(1, 14),
              Paragraph("This report is generated automatically and is guidance only, not a guarantee. "
                        "It can miss threats or flag safe emails.", small)]
    doc.build(story)
    return buf.getvalue()