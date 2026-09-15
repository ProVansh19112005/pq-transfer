"""
pdf_receipt.py — Simple clean PDF receipt using canvas
"""
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.colors import HexColor
from io import BytesIO
from datetime import timedelta

W, H = A4

# Colors
CYAN   = HexColor("#0077aa")
GREEN  = HexColor("#27ae60")
GREY   = HexColor("#888888")
DARK   = HexColor("#222222")
LIGHT  = HexColor("#555555")
LINE   = HexColor("#dddddd")
BG     = HexColor("#f8f9fa")
WHITE  = HexColor("#ffffff")
PURPLE = HexColor("#8e44ad")
RED    = HexColor("#c0392b")

ALGO_COLORS = {
    "FALCON":    HexColor("#27ae60"),
    "DILITHIUM": HexColor("#2980b9"),
    "SPHINCS":   HexColor("#c0392b"),
    "AQS-256-1": HexColor("#8e44ad"),
    "AQS-256-2": HexColor("#6c3483"),
}

def algo_color(alg):
    for k, v in ALGO_COLORS.items():
        if alg and alg.startswith(k):
            return v
    return CYAN

def security_level(alg):
    m = {
        "FALCON":    "NIST Level 2 — Dilithium2",
        "DILITHIUM": "NIST Level 3 — Dilithium3",
        "SPHINCS":   "NIST Level 5 — Dilithium5",
        "AQS-256-1": "Hybrid L2+L3 — FALCON + DILITHIUM",
        "AQS-256-2": "Hybrid L3+L5 — DILITHIUM & SPHINCS+",
    }
    for k, v in m.items():
        if alg and alg.startswith(k):
            return v
    return "Post-Quantum"


def wrap_text(text, max_chars=72):
    """Split long text into lines of max_chars."""
    text = str(text)
    words = text.split()
    lines, current = [], ""
    for w in words:
        if len(current) + len(w) + 1 <= max_chars:
            current = (current + " " + w).strip()
        else:
            if current:
                lines.append(current)
            current = w
    if current:
        lines.append(current)
    return lines if lines else ["—"]


def draw_section_header(c, y, text):
    c.setFillColor(GREY)
    c.setFont("Helvetica-Bold", 7.5)
    c.drawString(40, y, text.upper())
    c.setStrokeColor(LINE)
    c.setLineWidth(0.5)
    c.line(40, y - 3, W - 40, y - 3)
    return y - 16


def draw_kv(c, y, key, value, max_val_chars=65):
    """Draw a single key-value row. Returns new y position."""
    val_lines = wrap_text(str(value), max_val_chars)
    row_h     = max(16, len(val_lines) * 13 + 6)

    # Alternating row background handled by caller
    c.setFillColor(DARK)
    c.setFont("Helvetica-Bold", 8)
    c.drawString(50, y - 11, key)

    c.setFillColor(LIGHT)
    c.setFont("Helvetica", 8)
    for i, line in enumerate(val_lines):
        c.drawString(180, y - 11 - i * 12, line)

    c.setStrokeColor(LINE)
    c.setLineWidth(0.3)
    c.line(40, y - row_h + 2, W - 40, y - row_h + 2)

    return y - row_h


def make_receipt(tx, sender, receiver_user) -> BytesIO:
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)

    ist      = tx.timestamp + timedelta(hours=5, minutes=30)
    ts_str   = ist.strftime("%d %B %Y, %H:%M:%S IST")
    gen_str  = ist.strftime("%d %b %Y %H:%M IST")

    if tx.crypto_amount:
        amount_str = f"{tx.crypto_amount} {tx.currency}"
    elif tx.amount and tx.amount > 0:
        amount_str = f"Rs {tx.amount:,.2f}"
    else:
        amount_str = tx.filename or "Non-monetary transfer"

    algo_label = tx.algorithm or "Unknown"
    algo_full  = algo_label
    if tx.aqs_mode:
        algo_full += f" ({tx.aqs_mode})"

    receiver_name = receiver_user.username if receiver_user else "—"

    # ── PAGE 1 ─────────────────────────────────────────────────────────
    y = H - 40

    # Header bar
    c.setFillColor(HexColor("#0f1117"))
    c.rect(0, H - 70, W, 70, fill=1, stroke=0)

    c.setFillColor(CYAN)
    c.setFont("Helvetica-Bold", 20)
    c.drawString(40, H - 40, "PQ Transfer")

    c.setFillColor(GREY)
    c.setFont("Helvetica", 9)
    c.drawString(40, H - 56, "Quantum-Resistant Transaction Receipt")

    c.setFillColor(WHITE)
    c.setFont("Courier", 8)
    c.drawRightString(W - 40, H - 40, f"Receipt #{tx.tx_hash[:12].upper()}")
    c.setFont("Helvetica", 7)
    c.drawRightString(W - 40, H - 54, f"Generated: {gen_str}")

    y = H - 90

    # Status + Amount
    c.setFillColor(GREEN)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(40, y, "✓  CONFIRMED")

    y -= 28
    c.setFillColor(DARK)
    c.setFont("Helvetica-Bold", 22)
    c.drawString(40, y, amount_str)

    y -= 16
    c.setFillColor(GREY)
    c.setFont("Helvetica", 9)
    c.drawString(40, y, ts_str)

    y -= 14
    c.setStrokeColor(LINE)
    c.setLineWidth(0.8)
    c.line(40, y, W - 40, y)
    y -= 18

    # ── Transaction Details ───────────────────────────────────────────
    y = draw_section_header(c, y, "Transaction Details")

    rows = [
        ("TX Hash",     tx.tx_hash),
        ("Type",        tx.tx_type),
        ("From",        sender.username),
        ("To",          receiver_name),
        ("Sensitivity", tx.final_sensitivity),
        ("Status",      tx.status),
        ("Timestamp",   ts_str),
    ]
    if tx.filename:
        rows.append(("Filename", tx.filename))
    if tx.message:
        rows.append(("Message", tx.message))
    if tx.crypto_tx_hash:
        rows.append(("Blockchain TX", tx.crypto_tx_hash))

    for i, (k, v) in enumerate(rows):
        if i % 2 == 0:
            c.setFillColor(BG)
            c.rect(40, y - 14, W - 80, 16, fill=1, stroke=0)
        y = draw_kv(c, y, k, v)
        if y < 100:
            c.showPage()
            y = H - 60

    y -= 14
    c.setStrokeColor(LINE)
    c.setLineWidth(0.8)
    c.line(40, y, W - 40, y)
    y -= 18

    # ── Cryptographic Proof ───────────────────────────────────────────
    y = draw_section_header(c, y, "Post-Quantum Cryptographic Proof")

    crypto_rows = [
        ("Algorithm",      algo_full),
        ("Security Level", security_level(tx.algorithm)),
        ("Sig Size",       f"{tx.sig_size_bytes:,} bytes" if tx.sig_size_bytes else "—"),
        ("Signing Time",   f"{tx.signing_time_ms} ms" if tx.signing_time_ms else "—"),
        ("Risk Score",     f"{tx.risk_score}/100" if tx.risk_score is not None else "—"),
        ("Selection",      tx.reasoning or "Adaptive system selected based on risk score"),
    ]

    for i, (k, v) in enumerate(crypto_rows):
        if i % 2 == 0:
            c.setFillColor(BG)
            c.rect(40, y - 14, W - 80, 16, fill=1, stroke=0)
        y = draw_kv(c, y, k, v)
        if y < 100:
            c.showPage()
            y = H - 60

    # ── AQS-256 section if applicable ─────────────────────────────────
    if tx.aqs_mode:
        y -= 14
        c.setStrokeColor(LINE)
        c.line(40, y, W - 40, y)
        y -= 18
        y = draw_section_header(c, y, "AQS-256 Hybrid Signature Details")

        parts = tx.aqs_mode.split("+") if "+" in tx.aqs_mode else [tx.aqs_mode, ""]
        aqs_rows = [
            ("Mode",        tx.aqs_mode),
            ("Primary",     parts[0].strip()),
            ("Secondary",   parts[1].strip() if len(parts) > 1 else "—"),
            ("Mechanism",   "Independent signing + weighted XOR fusion"),
            ("Verification","Both signatures must be independently valid"),
        ]

        for i, (k, v) in enumerate(aqs_rows):
            if i % 2 == 0:
                c.setFillColor(BG)
                c.rect(40, y - 14, W - 80, 16, fill=1, stroke=0)
            y = draw_kv(c, y, k, v)
            if y < 100:
                c.showPage()
                y = H - 60

    # ── Signature Proof ───────────────────────────────────────────────
    y -= 14
    c.setStrokeColor(LINE)
    c.line(40, y, W - 40, y)
    y -= 18
    y = draw_section_header(c, y, "Embedded Signature Proof (partial)")

    sig_text  = str(tx.signature or "")[:400]
    sig_lines = wrap_text(sig_text, 90)

    c.setFillColor(BG)
    sig_box_h = len(sig_lines) * 11 + 12
    if y - sig_box_h < 80:
        c.showPage()
        y = H - 60
    c.rect(40, y - sig_box_h, W - 80, sig_box_h, fill=1, stroke=0)
    c.setStrokeColor(LINE)
    c.setLineWidth(0.5)
    c.rect(40, y - sig_box_h, W - 80, sig_box_h, fill=0, stroke=1)

    c.setFillColor(LIGHT)
    c.setFont("Courier", 6.5)
    for i, line in enumerate(sig_lines):
        c.drawString(48, y - 11 - i * 10, line)

    y -= sig_box_h + 20

    # ── Footer ────────────────────────────────────────────────────────
    if y < 80:
        c.showPage()
        y = 80

    c.setStrokeColor(LINE)
    c.line(40, 55, W - 40, 55)
    c.setFillColor(GREY)
    c.setFont("Helvetica", 7)
    c.drawCentredString(W / 2, 42,
        "Generated by PQ Transfer — Adaptive Post-Quantum Blockchain Platform")
    c.drawCentredString(W / 2, 31,
        "This receipt contains cryptographic proof using NIST FIPS 204 post-quantum algorithms.")
    c.drawCentredString(W / 2, 20,
        f"pq-transfer.fly.dev  |  {gen_str}")

    c.save()
    buffer.seek(0)
    return buffer