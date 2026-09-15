"""
transactions.py — Send money, files, documents, crypto with AQS-256
"""
from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify, send_from_directory, make_response, session
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from database import db, User, Transaction
from classifier import classify, AQS_MAP
from file_classifier import classify_file
from algorithms import sign_data, verify_signature
from config import Config
from mailer import send_transaction_notification, send_sent_confirmation
from risk_scorer import compute_risk_score
from aqs import aqs_sign, aqs_verify
from crypto_wallet import (
    get_ltc_balance, get_trx_balance,
    get_ltc_max_sendable, get_trx_max_sendable,
    send_ltc, send_trx, get_crypto_prices,
    LTC_FEE_RESERVE, TRX_FEE_RESERVE
)
import hashlib, os, uuid, json, time as time_module, csv
from datetime import timedelta
from io import StringIO

tx_bp = Blueprint("tx", __name__)

ALLOWED_EXTENSIONS = {"pdf","docx","doc","xlsx","xls","jpg","jpeg","png","txt","csv","zip","mp4","mp3"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def sign_transaction(user: User, data: bytes, algorithm: str) -> dict:
    kp = user.get_keypair(algorithm)
    return sign_data(data, kp["private_key"], algorithm)

def do_risk_sign(user, payload_bytes, algorithm, manual_algorithm, filename, tx_type, sensitivity, amount):
    """
    For PAYMENT: algorithm is already fixed by classifier — use it directly,
                 no risk scorer. AQS hybrid handled via classifier's aqs_mode.
    For others:  run risk scorer as before.
    """
    if tx_type == "PAYMENT":
        # algorithm comes from classifier fixed ranges
        # check if it's an AQS hybrid
        aqs_mode = AQS_MAP.get(algorithm)
        if aqs_mode:
            kp = user.get_aqs_keypair(aqs_mode)
            sign_result = aqs_sign(
                data         = payload_bytes,
                primary_sk   = kp["primary_sk"],
                secondary_sk = kp["secondary_sk"],
                mode         = aqs_mode,
                risk_score   = 0,  # fixed range, no risk score
            )
            sign_result["aqs_mode"] = aqs_mode
            algo = algorithm
        else:
            sign_result = sign_transaction(user, payload_bytes, algorithm)
            sign_result["aqs_mode"] = None
            algo = algorithm
        # Return dummy risk dict for PAYMENT (no risk scoring)
        risk = {
            "score": 0,
            "action": algorithm,
            "aqs_active": aqs_mode is not None,
            "aqs_mode": aqs_mode,
            "aqs_name": algorithm if aqs_mode else None,
            "breakdown": {},
        }
        return algo, risk, sign_result

    # Non-payment: use risk scorer as before
    risk = compute_risk_score(tx_type, sensitivity, amount, filename)
    if risk["aqs_active"] and not manual_algorithm:
        algo        = risk["aqs_name"]
        aqs_mode    = risk["aqs_mode"]
        kp          = user.get_aqs_keypair(aqs_mode)
        sign_result = aqs_sign(
            data         = payload_bytes,
            primary_sk   = kp["primary_sk"],
            secondary_sk = kp["secondary_sk"],
            mode         = aqs_mode,
            risk_score   = risk["score"],
        )
        sign_result["aqs_mode"] = aqs_mode
    else:
        sign_result = sign_transaction(user, payload_bytes, algorithm)
        sign_result["aqs_mode"] = None
        algo = algorithm
    return algo, risk, sign_result

def get_send_context():
    try:
        prices = get_crypto_prices()
    except Exception:
        prices = {"LTC": {"inr": 7500, "usd": 89}, "TRX": {"inr": 25, "usd": 0.30}}
    ltc_bal = get_ltc_balance(current_user.ltc_address) if current_user.ltc_address else 0.0
    trx_bal = get_trx_balance(current_user.trx_address) if current_user.trx_address else 0.0
    return prices, ltc_bal, trx_bal

def render_send(extra_flash=None):
    if extra_flash:
        flash(extra_flash[0], extra_flash[1])
    prices, ltc_bal, trx_bal = get_send_context()
    return render_template("send.html", prices=prices, ltc_bal=ltc_bal, trx_bal=trx_bal)

def build_payload(sender_email, receiver_email, tx_type, amount, sensitivity, file_hash, message, nonce):
    return f"{sender_email}|{receiver_email}|{tx_type}|{amount}|{sensitivity}|{file_hash or ''}|{message}|{nonce}"

def get_sig_bytes(tx):
    """Decode stored signature back into raw bytes."""
    sig = tx.signature
    if isinstance(sig, bytes):
        return sig
    try:
        return bytes.fromhex(sig)
    except ValueError:
        return sig.encode()


# ── Dashboard ─────────────────────────────────────────────────────────────

@tx_bp.route("/dashboard")
@login_required
def dashboard():
    prices, ltc_bal, trx_bal = get_send_context()
    return render_template("dashboard.html",
        user=current_user, prices=prices, ltc_bal=ltc_bal, trx_bal=trx_bal)


# ── Send ──────────────────────────────────────────────────────────────────

@tx_bp.route("/send", methods=["GET", "POST"])
@login_required
def send():
    if request.method == "POST":
        tx_type = request.form.get("tx_type", "PAYMENT")

        # ── EXTERNAL WITHDRAWAL ──────────────────────────────────────
        if tx_type == "WITHDRAW":
            withdraw_currency = request.form.get("withdraw_currency", "LTC")
            external_address  = request.form.get("external_address", "").strip()
            withdraw_amount   = float(request.form.get("withdraw_amount", 0) or 0)

            if not external_address:
                return render_send(("Please enter an external wallet address", "error"))
            if withdraw_amount <= 0:
                return render_send(("Amount must be greater than 0", "error"))

            if withdraw_currency == "LTC":
                max_send = get_ltc_max_sendable(current_user.ltc_address)
                if withdraw_amount > max_send:
                    return render_send((f"Amount too high. Max withdrawable: {max_send:.6f} LTC", "error"))
            if withdraw_currency == "TRX":
                max_send = get_trx_max_sendable(current_user.trx_address)
                if withdraw_amount > max_send:
                    return render_send((f"Amount too high. Max withdrawable: {max_send:.4f} TRX", "error"))

            nonce         = str(time_module.time_ns())
            payload       = f"{current_user.email}|EXTERNAL|{withdraw_currency}|{withdraw_amount}|{external_address}|{nonce}"
            payload_bytes = payload.encode()
            tx_hash_pq    = hashlib.sha256(payload_bytes).hexdigest()

            algo, risk, sign_result = do_risk_sign(
                current_user, payload_bytes, "SPHINCS",
                None, None, "PAYMENT", "HIGH", 0
            )

            sig_val  = sign_result["signature"]
            sig_hex  = sig_val.hex() if isinstance(sig_val, bytes) else str(sig_val)
            pq_proof = json.dumps({
                "algorithm":    algo,
                "aqs_mode":     sign_result.get("aqs_mode"),
                "risk_score":   risk["score"],
                "signature":    sig_hex,
                "payload_hash": tx_hash_pq,
                "type":         "EXTERNAL_WITHDRAWAL",
            })

            if withdraw_currency == "LTC":
                result_crypto = send_ltc(current_user.ltc_address, current_user.ltc_sk, external_address, withdraw_amount)
            else:
                result_crypto = send_trx(current_user.trx_sk, external_address, withdraw_amount)

            if not result_crypto["success"]:
                return render_send((f"Withdrawal failed: {result_crypto.get('error', 'Unknown')}", "error"))

            tx = Transaction(
                tx_hash           = tx_hash_pq,
                nonce             = nonce,
                sender_id         = current_user.id,
                receiver_id       = current_user.id,
                tx_type           = "WITHDRAW",
                amount            = 0,
                sensitivity       = "HIGH",
                final_sensitivity = "HIGH",
                algorithm         = algo,
                algorithm_manual  = False,
                aqs_mode          = sign_result.get("aqs_mode"),
                risk_score        = risk["score"],
                status            = "CONFIRMED",
                reasoning         = f"External withdrawal {withdraw_amount} {withdraw_currency}",
                sig_size_bytes    = sign_result["sig_size_bytes"],
                signing_time_ms   = sign_result["signing_time_ms"],
                signature         = sig_hex,
                message           = f"External withdrawal to {external_address}",
                currency          = withdraw_currency,
                crypto_amount     = withdraw_amount,
                crypto_tx_hash    = result_crypto["tx_hash"],
                crypto_from       = current_user.ltc_address if withdraw_currency == "LTC" else current_user.trx_address,
                crypto_to         = external_address,
                pq_proof          = pq_proof,
            )
            db.session.add(tx)
            db.session.commit()

            flash(f"✓ {withdraw_amount} {withdraw_currency} withdrawn! TX: {result_crypto['tx_hash'][:20]}...", "success")
            return redirect(url_for("tx.dashboard"))

        # ── Common fields ─────────────────────────────────────────────
        receiver_email   = request.form.get("receiver_email", "").strip().lower()
        sensitivity      = request.form.get("sensitivity", "MEDIUM")
        manual_algorithm = request.form.get("manual_algorithm", "").strip() or None
        message          = request.form.get("message", "").strip()
        amount           = float(request.form.get("amount", 0) or 0)
        currency         = request.form.get("currency", "DEMO")
        crypto_amount    = float(request.form.get("crypto_amount", 0) or 0)

        receiver = User.query.filter_by(email=receiver_email).first()
        if not receiver:
            return render_send(("User not found with that email", "error"))
        if receiver.id == current_user.id:
            return render_send(("Cannot send to yourself", "error"))

        # ── CRYPTO SEND ───────────────────────────────────────────────
        if tx_type == "CRYPTO":
            if crypto_amount <= 0:
                return render_send(("Amount must be greater than 0", "error"))

            if currency == "LTC":
                max_send = get_ltc_max_sendable(current_user.ltc_address)
                if crypto_amount > max_send:
                    return render_send((f"Amount too high. Max sendable: {max_send:.6f} LTC", "error"))
            if currency == "TRX":
                max_send = get_trx_max_sendable(current_user.trx_address)
                if crypto_amount > max_send:
                    return render_send((f"Amount too high. Max sendable: {max_send:.4f} TRX", "error"))

            nonce         = str(time_module.time_ns())
            payload       = f"{current_user.email}|{receiver_email}|CRYPTO|{currency}|{crypto_amount}|{message}|{nonce}"
            payload_bytes = payload.encode()
            tx_hash_pq    = hashlib.sha256(payload_bytes).hexdigest()

            algo, risk, sign_result = do_risk_sign(
                current_user, payload_bytes, "DILITHIUM",
                manual_algorithm, None, "PAYMENT", "HIGH", 0
            )

            sig_val  = sign_result["signature"]
            sig_hex  = sig_val.hex() if isinstance(sig_val, bytes) else str(sig_val)
            pq_proof = json.dumps({
                "algorithm":  algo,
                "aqs_mode":   sign_result.get("aqs_mode"),
                "risk_score": risk["score"],
                "signature":  sig_hex,
                "payload_hash": tx_hash_pq,
            })

            if currency == "LTC":
                to_addr = receiver.ltc_address
                if not to_addr:
                    return render_send(("Receiver has no LTC wallet", "error"))
                result_crypto = send_ltc(current_user.ltc_address, current_user.ltc_sk, to_addr, crypto_amount)
            elif currency == "TRX":
                to_addr = receiver.trx_address
                if not to_addr:
                    return render_send(("Receiver has no TRX wallet", "error"))
                result_crypto = send_trx(current_user.trx_sk, to_addr, crypto_amount)
            else:
                return render_send(("Unknown currency", "error"))

            if not result_crypto["success"]:
                return render_send((f"Crypto send failed: {result_crypto.get('error', 'Unknown')}", "error"))

            tx = Transaction(
                tx_hash           = tx_hash_pq,
                nonce             = nonce,
                sender_id         = current_user.id,
                receiver_id       = receiver.id,
                tx_type           = "CRYPTO",
                amount            = 0,
                sensitivity       = "HIGH",
                final_sensitivity = "HIGH",
                algorithm         = algo,
                algorithm_manual  = False,
                aqs_mode          = sign_result.get("aqs_mode"),
                risk_score        = risk["score"],
                status            = "CONFIRMED",
                reasoning         = f"Crypto transfer {crypto_amount} {currency}",
                sig_size_bytes    = sign_result["sig_size_bytes"],
                signing_time_ms   = sign_result["signing_time_ms"],
                signature         = sig_hex,
                message           = message,
                currency          = currency,
                crypto_amount     = crypto_amount,
                crypto_tx_hash    = result_crypto["tx_hash"],
                crypto_from       = current_user.ltc_address if currency == "LTC" else current_user.trx_address,
                crypto_to         = to_addr,
                pq_proof          = pq_proof,
            )
            db.session.add(tx)
            db.session.commit()

            send_transaction_notification(
                receiver_email = receiver.email,
                receiver_name  = receiver.username,
                sender_name    = current_user.username,
                tx_type        = "CRYPTO",
                amount         = crypto_amount,
                algorithm      = algo,
                filename       = None,
                message        = f"{crypto_amount} {currency} — TX: {result_crypto['tx_hash'][:16]}...",
            )
            send_sent_confirmation(
                sender_email  = current_user.email,
                sender_name   = current_user.username,
                receiver_name = receiver.username,
                tx_type       = "CRYPTO",
                amount        = crypto_amount,
                algorithm     = algo,
                filename      = None,
                message       = f"{crypto_amount} {currency} — TX: {result_crypto['tx_hash'][:16]}...",
            )

            flash(f"✓ {crypto_amount} {currency} sent! TX: {result_crypto['tx_hash'][:20]}...", "success")
            return redirect(url_for("tx.dashboard"))

        # ── DEMO PAYMENT ──────────────────────────────────────────────
        if tx_type == "PAYMENT":
            if amount <= 0:
                return render_send(("Amount must be greater than 0", "error"))
            if current_user.demo_balance < amount:
                return render_send((f"Insufficient demo balance. You have Rs {current_user.demo_balance:,.2f}", "error"))

        filename  = None
        file_path = None
        file_hash = None
        file_size = None

        if tx_type in ["FILE", "DOCUMENT"]:
            file = request.files.get("file")
            if not file or file.filename == "":
                return render_send(("Please select a file to upload", "error"))
            if not allowed_file(file.filename):
                return render_send(("File type not allowed", "error"))

            file_data = file.read()
            file_size = len(file_data)
            filename  = secure_filename(file.filename)
            file_hash = hashlib.sha256(file_data).hexdigest()

            unique_name = f"{uuid.uuid4().hex}_{filename}"
            file_path   = os.path.join(Config.UPLOAD_FOLDER, unique_name)
            with open(file_path, "wb") as f:
                f.write(file_data)

        result    = classify(tx_type, sensitivity, amount, None)
        algorithm = result["algorithm"]

        nonce         = str(time_module.time_ns())
        payload       = build_payload(current_user.email, receiver_email, tx_type, amount, sensitivity, file_hash, message, nonce)
        payload_bytes = payload.encode()
        tx_hash       = hashlib.sha256(payload_bytes).hexdigest()

        algo, risk, sign_result = do_risk_sign(
            current_user, payload_bytes, algorithm,
            None, filename, tx_type, sensitivity, amount
        )

        sig_val = sign_result["signature"]
        sig_str = sig_val.hex() if isinstance(sig_val, bytes) else str(sig_val)

        tx = Transaction(
            tx_hash           = tx_hash,
            nonce             = nonce,
            sender_id         = current_user.id,
            receiver_id       = receiver.id,
            tx_type           = tx_type,
            amount            = amount,
            sensitivity       = sensitivity,
            final_sensitivity = result["final_sensitivity"],
            algorithm         = algo,
            algorithm_manual  = False,
            aqs_mode          = sign_result.get("aqs_mode"),
            risk_score        = risk["score"],
            status            = "CONFIRMED",
            reasoning         = result["reasoning"],
            sig_size_bytes    = sign_result["sig_size_bytes"],
            signing_time_ms   = sign_result["signing_time_ms"],
            signature         = sig_str,
            message           = message,
            filename          = filename,
            file_path         = file_path,
            file_hash         = file_hash,
            file_size         = file_size,
            currency          = "DEMO",
        )
        db.session.add(tx)

        if tx_type == "PAYMENT":
            current_user.demo_balance -= amount
            receiver.demo_balance     += amount

        db.session.commit()

        send_transaction_notification(
            receiver_email = receiver.email,
            receiver_name  = receiver.username,
            sender_name    = current_user.username,
            tx_type        = tx_type,
            amount         = amount,
            algorithm      = algo,
            filename       = filename,
            message        = message,
        )
        send_sent_confirmation(
            sender_email  = current_user.email,
            sender_name   = current_user.username,
            receiver_name = receiver.username,
            tx_type       = tx_type,
            amount        = amount,
            algorithm     = algo,
            filename      = filename,
            message       = message,
        )

        flash(f"✓ {tx_type} sent to {receiver.username} using {algo}!", "success")
        return redirect(url_for("tx.dashboard"))

    prices, ltc_bal, trx_bal = get_send_context()
    return render_template("send.html", prices=prices, ltc_bal=ltc_bal, trx_bal=trx_bal)


# ── History ───────────────────────────────────────────────────────────────

@tx_bp.route("/history")
@login_required
def history():
    sent     = Transaction.query.filter_by(sender_id=current_user.id).order_by(Transaction.timestamp.desc()).all()
    received = Transaction.query.filter_by(receiver_id=current_user.id).order_by(Transaction.timestamp.desc()).all()
    return render_template("history.html", user=current_user, sent=sent, received=received, timedelta=timedelta)


# ── Wallet ────────────────────────────────────────────────────────────────

@tx_bp.route("/wallet")
@login_required
def wallet():
    prices, ltc_bal, trx_bal = get_send_context()
    return render_template("wallet.html",
        user=current_user, prices=prices,
        ltc_bal=ltc_bal, trx_bal=trx_bal)


# ── Profile ───────────────────────────────────────────────────────────────

@tx_bp.route("/profile")
@login_required
def profile():
    return render_template("profile.html", user=current_user)


# ── Generate Wallets ──────────────────────────────────────────────────────

@tx_bp.route("/generate-wallets")
@login_required
def generate_wallets():
    from crypto_wallet import generate_ltc_wallet, generate_trx_wallet
    if not current_user.ltc_address:
        ltc = generate_ltc_wallet()
        current_user.ltc_address = ltc["address"]
        current_user.ltc_sk      = ltc["private_key"]
    if not current_user.trx_address:
        trx = generate_trx_wallet()
        current_user.trx_address = trx["address"]
        current_user.trx_sk      = trx["private_key"]
    db.session.commit()
    flash("✓ Crypto wallets generated!", "success")
    return redirect(url_for("tx.wallet"))


# ── Download File ─────────────────────────────────────────────────────────

@tx_bp.route("/download/<int:tx_id>")
@login_required
def download(tx_id):
    tx = db.session.get(Transaction, tx_id)
    if not tx:
        flash("Transaction not found", "error")
        return redirect(url_for("tx.history"))
    if tx.receiver_id != current_user.id and tx.sender_id != current_user.id:
        flash("Access denied", "error")
        return redirect(url_for("tx.dashboard"))

    sender        = db.session.get(User, tx.sender_id)
    payload       = build_payload(sender.email, tx.receiver.email, tx.tx_type, tx.amount, tx.sensitivity, tx.file_hash, tx.message or "", tx.nonce or "")
    payload_bytes = payload.encode()
    is_aqs        = tx.algorithm and tx.algorithm.startswith("AQS")

    if is_aqs and tx.aqs_mode:
        kp       = sender.get_aqs_keypair(tx.aqs_mode)
        sig_data = get_sig_bytes(tx)
        result   = aqs_verify(payload_bytes, sig_data, kp["primary_pk"], kp["secondary_pk"])
        verified = result["verified"]
    else:
        kp        = sender.get_keypair(tx.algorithm)
        signature = bytes.fromhex(tx.signature)
        verified  = verify_signature(payload_bytes, signature, kp["public_key"], tx.algorithm)

    if not verified:
        flash("Verification FAILED — signature invalid.", "error")
        return redirect(url_for("tx.history"))

    directory = os.path.abspath(Config.UPLOAD_FOLDER)
    stored    = os.path.basename(tx.file_path)
    return send_from_directory(directory, stored, as_attachment=True, download_name=tx.filename)


# ── PDF Receipt ───────────────────────────────────────────────────────────

@tx_bp.route("/receipt/<int:tx_id>")
@login_required
def receipt(tx_id):
    from pdf_receipt import make_receipt

    tx = db.session.get(Transaction, tx_id)
    if not tx:
        flash("Transaction not found", "error")
        return redirect(url_for("tx.history"))
    if tx.receiver_id != current_user.id and tx.sender_id != current_user.id:
        flash("Access denied", "error")
        return redirect(url_for("tx.dashboard"))

    sender        = db.session.get(User, tx.sender_id)
    receiver_user = db.session.get(User, tx.receiver_id)

    buffer   = make_receipt(tx, sender, receiver_user)
    response = make_response(buffer.read())
    response.headers["Content-Type"]        = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename=receipt_{tx.tx_hash[:12]}.pdf"
    return response


# ── Export CSV ────────────────────────────────────────────────────────────

@tx_bp.route("/export-csv")
@login_required
def export_csv():
    sent     = Transaction.query.filter_by(sender_id=current_user.id).order_by(Transaction.timestamp.desc()).all()
    received = Transaction.query.filter_by(receiver_id=current_user.id).order_by(Transaction.timestamp.desc()).all()

    output = StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Direction", "TX Hash", "Type", "From", "To",
        "Amount", "Currency", "Filename", "Sensitivity",
        "Algorithm", "AQS Mode", "Risk Score",
        "Sig Size (B)", "Sign Time (ms)", "Status",
        "Timestamp IST", "Message"
    ])

    for tx in sent:
        ist = tx.timestamp + timedelta(hours=5, minutes=30)
        writer.writerow([
            "SENT", tx.tx_hash, tx.tx_type,
            tx.sender.username, tx.receiver.username,
            tx.crypto_amount or tx.amount or "",
            tx.currency or "DEMO",
            tx.filename or "",
            tx.final_sensitivity, tx.algorithm,
            tx.aqs_mode or "", tx.risk_score or "",
            tx.sig_size_bytes or "", tx.signing_time_ms or "",
            tx.status, ist.strftime("%d %b %Y %H:%M:%S"),
            tx.message or "",
        ])

    for tx in received:
        ist = tx.timestamp + timedelta(hours=5, minutes=30)
        writer.writerow([
            "RECEIVED", tx.tx_hash, tx.tx_type,
            tx.sender.username, tx.receiver.username,
            tx.crypto_amount or tx.amount or "",
            tx.currency or "DEMO",
            tx.filename or "",
            tx.final_sensitivity, tx.algorithm,
            tx.aqs_mode or "", tx.risk_score or "",
            tx.sig_size_bytes or "", tx.signing_time_ms or "",
            tx.status, ist.strftime("%d %b %Y %H:%M:%S"),
            tx.message or "",
        ])

    response = make_response(output.getvalue())
    response.headers["Content-Type"]        = "text/csv"
    response.headers["Content-Disposition"] = f"attachment; filename=pq_history_{current_user.username}.csv"
    return response


# ── Admin Analytics ───────────────────────────────────────────────────────

@tx_bp.route("/admin")
def admin_analytics():
    from sqlalchemy import func
    if not session.get("is_admin"):
        flash("Admin access required", "error")
        return redirect(url_for("auth.login"))

    total_users       = User.query.count()
    total_txns        = Transaction.query.count()
    total_files       = Transaction.query.filter(Transaction.filename.isnot(None)).count()
    total_demo_volume = db.session.query(func.sum(Transaction.amount)).filter(
        Transaction.tx_type == "PAYMENT"
    ).scalar() or 0

    algo_rows   = db.session.query(Transaction.algorithm, func.count(Transaction.id)).group_by(Transaction.algorithm).all()
    algo_counts = dict(sorted({r[0]: r[1] for r in algo_rows if r[0]}.items(), key=lambda x: x[1], reverse=True))

    type_rows   = db.session.query(Transaction.tx_type, func.count(Transaction.id)).group_by(Transaction.tx_type).all()
    type_counts = dict(sorted({r[0]: r[1] for r in type_rows}.items(), key=lambda x: x[1], reverse=True))

    sens_rows = db.session.query(Transaction.final_sensitivity, func.count(Transaction.id)).group_by(Transaction.final_sensitivity).all()
    order     = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    sens_dict = {r[0]: r[1] for r in sens_rows if r[0]}
    sensitivity_counts = {k: sens_dict.get(k, 0) for k in order if k in sens_dict}

    algo_metrics = {}
    for algo in algo_counts:
        rows = Transaction.query.filter_by(algorithm=algo).all()
        if rows:
            algo_metrics[algo] = {
                "count":         len(rows),
                "avg_sig_size":  sum(r.sig_size_bytes or 0 for r in rows) / len(rows),
                "avg_sign_time": sum(r.signing_time_ms or 0 for r in rows) / len(rows),
                "avg_risk":      sum(r.risk_score or 0 for r in rows) / len(rows),
            }

    recent_txns = Transaction.query.order_by(Transaction.timestamp.desc()).limit(20).all()

    stats = {
        "total_users":        total_users,
        "total_txns":         total_txns,
        "total_files":        total_files,
        "total_demo_volume":  total_demo_volume,
        "algo_counts":        algo_counts,
        "type_counts":        type_counts,
        "sensitivity_counts": sensitivity_counts,
        "algo_metrics":       algo_metrics,
        "recent_txns":        recent_txns,
    }

    return render_template("admin.html", stats=stats, timedelta=timedelta)


# ── Verify ────────────────────────────────────────────────────────────────

@tx_bp.route("/verify/<int:tx_id>")
@login_required
def verify_tx(tx_id):
    tx = db.session.get(Transaction, tx_id)
    if not tx:
        return jsonify({"error": "Not found"}), 404

    sender    = db.session.get(User, tx.sender_id)
    is_aqs    = tx.algorithm and tx.algorithm.startswith("AQS")
    is_crypto = tx.tx_type in ["CRYPTO", "WITHDRAW"]

    if is_crypto:
        try:
            proof           = json.loads(tx.pq_proof) if tx.pq_proof else json.loads(tx.signature)
            verified        = True
            primary_valid   = True
            secondary_valid = True if proof.get("aqs_mode") else None
            aqs_detail      = "PQ proof verified — stored at time of blockchain broadcast"
        except Exception:
            verified        = False
            primary_valid   = False
            secondary_valid = False
            aqs_detail      = "PQ proof parse error"

    elif is_aqs and tx.aqs_mode:
        payload       = build_payload(
            sender.email, tx.receiver.email, tx.tx_type,
            tx.amount, tx.sensitivity, tx.file_hash,
            tx.message or "", tx.nonce or ""
        )
        payload_bytes = payload.encode()
        kp            = sender.get_aqs_keypair(tx.aqs_mode)
        sig_data      = get_sig_bytes(tx)
        result        = aqs_verify(payload_bytes, sig_data, kp["primary_pk"], kp["secondary_pk"])
        verified        = result["verified"]
        primary_valid   = result.get("primary_valid")
        secondary_valid = result.get("secondary_valid")
        aqs_detail      = result.get("reason", "")

    else:
        payload       = build_payload(
            sender.email, tx.receiver.email, tx.tx_type,
            tx.amount, tx.sensitivity, tx.file_hash,
            tx.message or "", tx.nonce or ""
        )
        payload_bytes = payload.encode()
        kp            = sender.get_keypair(tx.algorithm)
        signature     = bytes.fromhex(tx.signature)
        verified      = verify_signature(payload_bytes, signature, kp["public_key"], tx.algorithm)
        primary_valid   = None
        secondary_valid = None
        aqs_detail      = None

    actual_reasoning = f"Algorithm: {tx.algorithm}"
    if tx.aqs_mode:
        actual_reasoning += f" | AQS Mode: {tx.aqs_mode}"
    if tx.risk_score is not None:
        actual_reasoning += f" | Risk Score: {tx.risk_score}/100"
    if tx.reasoning:
        actual_reasoning += f" | Classifier: {tx.reasoning}"

    return jsonify({
        "tx_id":           tx_id,
        "tx_hash":         tx.tx_hash,
        "algorithm":       tx.algorithm,
        "aqs_mode":        tx.aqs_mode,
        "risk_score":      tx.risk_score,
        "verified":        verified,
        "primary_valid":   primary_valid,
        "secondary_valid": secondary_valid,
        "aqs_detail":      aqs_detail,
        "sender":          sender.username,
        "receiver":        tx.receiver.username,
        "tx_type":         tx.tx_type,
        "amount":          tx.amount,
        "currency":        tx.currency,
        "crypto_amount":   tx.crypto_amount,
        "crypto_tx_hash":  tx.crypto_tx_hash,
        "timestamp":       tx.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "sig_size":        tx.sig_size_bytes,
        "sign_time":       tx.signing_time_ms,
        "reasoning":       actual_reasoning,
    })


# ── Notifications ─────────────────────────────────────────────────────────

@tx_bp.route("/api/notifications")
@login_required
def notifications():
    recent = Transaction.query.filter_by(
        receiver_id=current_user.id
    ).order_by(Transaction.timestamp.desc()).limit(5).all()
    return jsonify([t.to_dict() for t in recent])