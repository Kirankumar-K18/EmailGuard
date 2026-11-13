"""PDF security-analysis report generation with ReportLab."""
from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

NAVY = colors.HexColor("#0B1220")
BLUE = colors.HexColor("#1D4ED8")
CYAN = colors.HexColor("#0891B2")
GREY = colors.HexColor("#475569")
LIGHT = colors.HexColor("#F1F5F9")
BORDER = colors.HexColor("#CBD5E1")
GREEN = colors.HexColor("#15803D")
RED = colors.HexColor("#B91C1C")
ORANGE = colors.HexColor("#B45309")

_STATUS_COLOR = {
    "PASS": GREEN, "AUTHENTICATED": GREEN, "VERIFIED": GREEN, "LOW": GREEN,
    "FAIL": RED, "PERMERROR": RED, "FAILED AUTHENTICATION": RED, "HIGH": RED, "INVALID": RED,
    "SOFTFAIL": ORANGE, "TEMPERROR": ORANGE, "NEUTRAL": ORANGE, "SUSPICIOUS": ORANGE, "MEDIUM": ORANGE,
}


def _status_hex(status: str) -> str:
    return (_STATUS_COLOR.get(status, GREY)).hexval().replace("0x", "#")


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "body": ParagraphStyle("body", parent=base["BodyText"], fontName="Helvetica", fontSize=9, leading=12.5, textColor=colors.HexColor("#0F172A")),
        "small": ParagraphStyle("small", parent=base["BodyText"], fontName="Helvetica", fontSize=7.8, leading=10.5, textColor=GREY),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=BLUE, spaceBefore=12, spaceAfter=5),
        "cell": ParagraphStyle("cell", parent=base["BodyText"], fontName="Helvetica", fontSize=8.5, leading=11, textColor=colors.HexColor("#0F172A")),
        "cellb": ParagraphStyle("cellb", parent=base["BodyText"], fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=colors.HexColor("#0F172A")),
        "mono": ParagraphStyle("mono", parent=base["Code"], fontName="Courier", fontSize=7.5, leading=9.5, textColor=colors.HexColor("#0F172A")),
        "banner": ParagraphStyle("banner", parent=base["BodyText"], fontName="Helvetica-Bold", fontSize=9, leading=12, textColor=colors.white, alignment=TA_CENTER),
    }


def _p(text, style) -> Paragraph:
    return Paragraph(escape(str(text if text is not None else "")), style)


def _kv_table(rows: list[tuple[str, str]], st: dict, widths=(42 * mm, 130 * mm)) -> Table:
    data = [[_p(k, st["cellb"]), _p(v or "-", st["cell"])] for k, v in rows]
    t = Table(data, colWidths=list(widths))
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), LIGHT),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _status_para(status: str, st: dict) -> Paragraph:
    return Paragraph(f'<font color="{_status_hex(status)}"><b>{escape(status)}</b></font>', st["cell"])


def _footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(GREY)
    canvas.drawString(18 * mm, 10 * mm, "EmailGuard - Secure. Authenticate. Protect.  |  Educational CNS mini-project report")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def generate_pdf_report(result: dict) -> bytes:
    """Render ``result`` (from ``analysis_engine.analyze_email``) as a PDF and return its bytes."""
    st = _styles()
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=18 * mm,
                            title="EmailGuard Analysis Report", author="EmailGuard")
    story: list = []

    email = result.get("email", {})
    auth = result.get("authentication", {})
    spoof = result.get("spoofing", {})
    verdict = result.get("verdict", {})
    ts = result.get("timestamp") or datetime.now(timezone.utc).isoformat(timespec="seconds")

    # Header band ---------------------------------------------------------
    head = Table(
        [[Paragraph('<font color="#FFFFFF" size="20"><b>EmailGuard</b></font><br/><font color="#67E8F9" size="9">Secure. Authenticate. Protect.</font>', st["body"]),
          Paragraph('<font color="#FFFFFF" size="12"><b>Email Authentication Analysis Report</b></font><br/>'
                    f'<font color="#94A3B8" size="8">Generated {escape(ts)}'
                    + (f" | Report #{result['analysis_id']}" if result.get("analysis_id") else "") + "</font>", st["body"])]],
        colWidths=[70 * mm, 102 * mm])
    head.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), NAVY), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                              ("LEFTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10)]))
    story += [head, Spacer(1, 6)]

    if result.get("is_demo"):
        banner = Table([[Paragraph("DEMONSTRATION DATA - fictional message evaluated against a simulated DNS zone. Not a real-world result.", st["banner"])]], colWidths=[172 * mm])
        banner.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), ORANGE), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        story += [banner, Spacer(1, 6)]

    # Verdict -------------------------------------------------------------
    classification = verdict.get("classification", "-")
    score, level = verdict.get("risk_score", spoof.get("score", 0)), verdict.get("risk_level", spoof.get("level", "-"))
    box = Table(
        [[Paragraph(f'<font size="8" color="#475569">FINAL SECURITY VERDICT</font><br/><font size="15" color="{_status_hex(classification)}"><b>{escape(classification)}</b></font>', st["body"]),
          Paragraph(f'<font size="8" color="#475569">HEURISTIC RISK SCORE</font><br/><font size="15" color="{_status_hex(level)}"><b>{score}/100</b></font> '
                    f'<font size="9" color="{_status_hex(level)}"><b>{escape(str(level))} RISK</b></font>', st["body"])],
         [Paragraph(escape(verdict.get("headline", "")), st["cell"]), ""]],
        colWidths=[100 * mm, 72 * mm])
    box.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.8, BORDER), ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
                             ("SPAN", (0, 1), (1, 1)), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                             ("LEFTPADDING", (0, 0), (-1, -1), 8)]))
    story += [box]

    # 1. Email information -------------------------------------------------
    story.append(Paragraph("1. Email information", st["h2"]))
    story.append(_kv_table([
        ("Subject", email.get("subject", "")), ("Date", email.get("date", "")), ("Message-ID", email.get("message_id", "")),
        ("To", email.get("to", "")), ("Analysis timestamp (UTC)", ts), ("Input mode", str(result.get("input_mode", "")).replace("_", " ")),
        ("DNS data source", result.get("dns_source", "")),
    ], st))

    # 2. Sender details ----------------------------------------------------
    story.append(Paragraph("2. Sender details", st["h2"]))
    story.append(_kv_table([
        ("From", email.get("from", "")), ("From domain", email.get("from_domain", "")), ("Reply-To", email.get("reply_to", "")),
        ("Return-Path", email.get("return_path", "")), ("Sending IP supplied", result.get("sending_ip", "") or "not supplied"),
        ("SPF identity used", result.get("spf_basis", "")),
    ], st))

    # 3. Authentication results -------------------------------------------
    story.append(Paragraph("3. Authentication results", st["h2"]))
    rows = [[_p(h, st["cellb"]) for h in ("Mechanism", "Result", "Method", "Domain", "Explanation")]]
    for key in ("spf", "dkim", "dmarc"):
        a = auth.get(key, {})
        rows.append([_p(key.upper(), st["cellb"]), _status_para(a.get("status", "-"), st), _p(a.get("method", ""), st["cell"]),
                     _p(a.get("domain", "") or "-", st["cell"]), _p(a.get("explanation", ""), st["cell"])])
    t = Table(rows, colWidths=[25 * mm, 24 * mm, 35 * mm, 30 * mm, 58 * mm], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), LIGHT), ("GRID", (0, 0), (-1, -1), 0.4, BORDER), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(t)
    claims = auth.get("header_claims") or {}
    story.append(Spacer(1, 3))
    story.append(_p("Header-claimed results (stated inside the message, NOT verified by EmailGuard): "
                    + (", ".join(f"{k}={v}" for k, v in claims.items()) if claims else "none present."), st["small"]))

    # 3a-c. Detail sections -----------------------------------------------
    spf = auth.get("spf", {})
    story.append(Paragraph("4. SPF verification", st["h2"]))
    sd = spf.get("details", {})
    story.append(_kv_table([("Status", spf.get("status", "-")), ("Domain checked", spf.get("domain", "")), ("SPF record", sd.get("record", "")),
                            ("Matched term", sd.get("matched", "")), ("DNS lookups used", str(sd.get("lookups", "")))], st))

    dkim = auth.get("dkim", {})
    story.append(Paragraph("5. DKIM verification", st["h2"]))
    sigs = dkim.get("details", {}).get("signatures", [])
    if sigs:
        rows = [[_p(h, st["cellb"]) for h in ("Domain (d=)", "Selector (s=)", "Result", "Key bits", "Reason")]]
        for s in sigs:
            rows.append([_p(s.get("domain", ""), st["cell"]), _p(s.get("selector", ""), st["cell"]), _status_para(s.get("status", "-"), st),
                         _p(s.get("key_bits") or "-", st["cell"]), _p(s.get("explanation", s.get("reason", "")), st["cell"])])
        t = Table(rows, colWidths=[34 * mm, 24 * mm, 22 * mm, 16 * mm, 76 * mm], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), LIGHT), ("GRID", (0, 0), (-1, -1), 0.4, BORDER), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(t)
    else:
        story.append(_p(dkim.get("explanation", "No DKIM information."), st["body"]))

    dmarc = auth.get("dmarc", {})
    dd = dmarc.get("details", {})
    story.append(Paragraph("6. DMARC verification", st["h2"]))
    story.append(_kv_table([("Status", dmarc.get("status", "-")), ("Policy record", dd.get("record", "") or "none retrieved"),
                            ("Policy (p)", dd.get("policy", "")), ("SPF aligned", str(dd.get("spf_aligned"))), ("DKIM aligned", str(dd.get("dkim_aligned")))], st))

    ds = result.get("digital_signature", {})
    story.append(Paragraph("7. Digital signature status", st["h2"]))
    story.append(_kv_table([("Status", ds.get("status", "-")), ("Note", ds.get("note", ""))], st))

    # 8. Indicators --------------------------------------------------------
    story.append(Paragraph("8. Suspicious indicators", st["h2"]))
    inds = spoof.get("indicators", [])
    if inds:
        rows = [[_p(h, st["cellb"]) for h in ("Indicator", "Category", "Points", "Detail")]]
        for i in inds:
            detail = i.get("detail", "") + ("  Evidence: " + "; ".join(i["evidence"]) if i.get("evidence") else "")
            rows.append([_p(i["title"], st["cellb"]), _p(i["category"], st["cell"]), _p(f"+{i['points']}", st["cell"]), _p(detail, st["cell"])])
        t = Table(rows, colWidths=[48 * mm, 24 * mm, 14 * mm, 86 * mm], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), LIGHT), ("GRID", (0, 0), (-1, -1), 0.4, BORDER), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(t)
    else:
        story.append(_p("No suspicious indicators were triggered.", st["body"]))

    story.append(Paragraph("9. Risk score and verdict", st["h2"]))
    story.append(KeepTogether([
        _p(f"Risk score {score}/100 ({level} RISK). Bands: 0-29 LOW, 30-59 MEDIUM, 60-100 HIGH. Raw rule total: {spoof.get('raw_total', score)} (capped at 100).", st["body"]),
        Spacer(1, 3),
        _p(spoof.get("disclaimer", ""), st["small"]),
    ]))

    story.append(Paragraph("10. Method legend and limitations", st["h2"]))
    for name, text in (result.get("method_legend") or {}).items():
        story.append(Paragraph(f"<b>{escape(name)}</b> - {escape(text)}", st["small"]))
    story.append(Spacer(1, 4))
    for lim in result.get("limitations", []):
        story.append(Paragraph(f"- {escape(lim)}", st["small"]))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
