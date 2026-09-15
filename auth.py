"""
auth.py — Register with OTP, Login with Captcha + Passcode, Logout, Password Reset, Security
"""
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from database import db, User
from algorithms import generate_keypair
from config import Config
from mailer import send_otp, send_welcome, verify_otp
from aqs import aqs_keygen
import hashlib, random, re

auth_bp = Blueprint("auth", __name__)


def create_wallet_for_user(user: User):
    """Generate all PQ keypairs + LTC + TRX wallets."""
    for algo in ["FALCON", "DILITHIUM", "SPHINCS"]:
        kp = generate_keypair(algo)
        if algo == "FALCON":
            user.falcon_pk = kp["public_key"].hex()
            user.falcon_sk = kp["private_key"].hex()
        elif algo == "DILITHIUM":
            user.dilithium_pk = kp["public_key"].hex()
            user.dilithium_sk = kp["private_key"].hex()
        elif algo == "SPHINCS":
            user.sphincs_pk = kp["public_key"].hex()
            user.sphincs_sk = kp["private_key"].hex()

    kp_fd = aqs_keygen("FALCON+DILITHIUM")
    user.aqs_fd_primary_pk   = kp_fd["primary_pk"].hex()
    user.aqs_fd_primary_sk   = kp_fd["primary_sk"].hex()
    user.aqs_fd_secondary_pk = kp_fd["secondary_pk"].hex()
    user.aqs_fd_secondary_sk = kp_fd["secondary_sk"].hex()

    kp_ds = aqs_keygen("DILITHIUM+SPHINCS")
    user.aqs_ds_primary_pk   = kp_ds["primary_pk"].hex()
    user.aqs_ds_primary_sk   = kp_ds["primary_sk"].hex()
    user.aqs_ds_secondary_pk = kp_ds["secondary_pk"].hex()
    user.aqs_ds_secondary_sk = kp_ds["secondary_sk"].hex()

    pk = bytes.fromhex(user.dilithium_pk)
    user.wallet_address = hashlib.sha256(pk).hexdigest()[:40]

    from crypto_wallet import generate_ltc_wallet, generate_trx_wallet
    print("  Generating LTC wallet...")
    ltc = generate_ltc_wallet()
    user.ltc_address = ltc["address"]
    user.ltc_sk      = ltc["private_key"]

    print("  Generating TRX wallet...")
    trx = generate_trx_wallet()
    user.trx_address = trx["address"]
    user.trx_sk      = trx["private_key"]


def is_strong_password(password: str) -> tuple:
    """Returns (is_valid, message)."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=]", password):
        return False, "Password must contain at least one special character"
    return True, ""


def new_captcha():
    a, b = random.randint(1, 12), random.randint(1, 12)
    op = random.choice(["+", "-"])
    if op == "-" and a < b:
        a, b = b, a
    answer = a + b if op == "+" else a - b
    session["captcha_answer"] = answer
    return f"{a} {op} {b} = ?"


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("tx.dashboard"))
    if session.get("is_admin"):
        return redirect(url_for("tx.admin_analytics"))

    if request.method == "POST":
        email         = request.form.get("email", "").strip().lower()
        password      = request.form.get("password", "")
        captcha_input = request.form.get("captcha", "").strip()
        expected      = session.get("captcha_answer")

        # Admin bypass — no captcha needed
        from config import Config
        if email == Config.ADMIN_EMAIL.lower() and password == Config.ADMIN_PASSWORD:
            session["is_admin"] = True
            session.pop("captcha_answer", None)
            return redirect(url_for("tx.admin_analytics"))

        # Normal user captcha check
        if expected is None or captcha_input == "" or not captcha_input.lstrip("-").isdigit() or int(captcha_input) != expected:
            flash("Incorrect captcha answer", "error")
            captcha_question = new_captcha()
            return render_template("login.html", captcha_question=captcha_question)

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session.pop("captcha_answer", None)
            session["is_admin"] = False
            if user.has_passcode:
                session["pending_login_id"] = user.id
                return redirect(url_for("auth.enter_passcode"))
            login_user(user)
            return redirect(url_for("tx.dashboard"))

        flash("Invalid email or password", "error")
        captcha_question = new_captcha()
        return render_template("login.html", captcha_question=captcha_question)

    captcha_question = new_captcha()
    return render_template("login.html", captcha_question=captcha_question)


@auth_bp.route("/enter-passcode", methods=["GET", "POST"])
def enter_passcode():
    user_id = session.get("pending_login_id")
    if not user_id:
        return redirect(url_for("auth.login"))
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        passcode = request.form.get("passcode", "").strip()
        if user.passcode_hash and check_password_hash(user.passcode_hash, passcode):
            session.pop("pending_login_id", None)
            login_user(user)
            return redirect(url_for("tx.dashboard"))
        flash("Incorrect passcode", "error")

    return render_template("enter_passcode.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("tx.dashboard"))

    if request.method == "POST":
        email    = request.form.get("email", "").strip().lower()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")

        valid, msg = is_strong_password(password)
        if not valid:
            flash(msg, "error")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match", "error")
            return render_template("register.html")
        if User.query.filter_by(email=email).first():
            flash("Email already registered", "error")
            return render_template("register.html")
        if User.query.filter_by(username=username).first():
            flash("Username already taken", "error")
            return render_template("register.html")

        session["pending_email"]    = email
        session["pending_username"] = username
        session["pending_password"] = generate_password_hash(password)
        session["otp_purpose"]      = "register"

        send_otp(email, username)
        flash("OTP sent to your email. Please verify.", "success")
        return redirect(url_for("auth.verify_otp_page"))

    return render_template("register.html")


@auth_bp.route("/verify-otp", methods=["GET", "POST"])
def verify_otp_page():
    purpose = session.get("otp_purpose", "register")

    if request.method == "POST":
        otp   = request.form.get("otp", "").strip()
        email = session.get("pending_email")

        if not email:
            flash("Session expired. Please try again.", "error")
            return redirect(url_for("auth.login"))

        if not verify_otp(email, otp):
            flash("Invalid or expired OTP. Please try again.", "error")
            return render_template("verify_otp.html", purpose=purpose)

        if purpose == "register":
            username = session.get("pending_username")
            password = session.get("pending_password")

            user = User(
                email         = email,
                username      = username,
                password_hash = password,
                demo_balance  = Config.DEFAULT_BALANCE,
            )
            db.session.add(user)
            db.session.flush()

            print(f"  Generating all wallets for {username}...")
            create_wallet_for_user(user)
            db.session.commit()
            print(f"  All wallets created for {username}")

            session.pop("pending_email",    None)
            session.pop("pending_username", None)
            session.pop("pending_password", None)
            session.pop("otp_purpose",      None)

            send_welcome(email, username, user.wallet_address)
            login_user(user)
            flash(f"Welcome {username}! Your wallets are ready.", "success")
            return redirect(url_for("tx.dashboard"))

        elif purpose == "reset":
            session["reset_verified"] = True
            return redirect(url_for("auth.reset_password_page"))

    return render_template("verify_otp.html", purpose=purpose)


@auth_bp.route("/resend-otp")
def resend_otp():
    email    = session.get("pending_email")
    username = session.get("pending_username", "User")
    if email:
        send_otp(email, username)
        flash("OTP resent to your email.", "success")
    return redirect(url_for("auth.verify_otp_page"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("tx.dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user  = User.query.filter_by(email=email).first()
        if not user:
            flash("No account found with that email.", "error")
            return render_template("forgot_password.html")

        session["pending_email"]    = email
        session["pending_username"] = user.username
        session["otp_purpose"]      = "reset"
        session["reset_verified"]   = False

        send_otp(email, user.username)
        flash("OTP sent to your email.", "success")
        return redirect(url_for("auth.verify_otp_page"))

    return render_template("forgot_password.html")


@auth_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password_page():
    if not session.get("reset_verified"):
        flash("Please verify your OTP first.", "error")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")

        valid, msg = is_strong_password(password)
        if not valid:
            flash(msg, "error")
            return render_template("reset_password.html")

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("reset_password.html")

        email = session.get("pending_email")
        user  = User.query.filter_by(email=email).first()
        if not user:
            flash("Session expired. Please try again.", "error")
            return redirect(url_for("auth.forgot_password"))

        user.password_hash = generate_password_hash(password)
        db.session.commit()

        session.pop("pending_email",    None)
        session.pop("pending_username", None)
        session.pop("otp_purpose",      None)
        session.pop("reset_verified",   None)

        flash("Password reset successful! Please login.", "success")
        return redirect(url_for("auth.login"))

    return render_template("reset_password.html")


@auth_bp.route("/security", methods=["GET", "POST"])
@login_required
def security():
    if request.method == "POST":
        action = request.form.get("action")

        if action == "set_passcode":
            passcode = request.form.get("passcode", "").strip()
            confirm  = request.form.get("confirm_passcode", "").strip()

            if len(passcode) != 8 or not passcode.isalnum():
                flash("Passcode must be exactly 8 alphanumeric characters", "error")
                return redirect(url_for("auth.security"))
            if passcode != confirm:
                flash("Passcodes do not match", "error")
                return redirect(url_for("auth.security"))

            current_user.passcode_hash = generate_password_hash(passcode)
            db.session.commit()
            flash("✓ Passcode enabled! You'll need it every time you login.", "success")
            return redirect(url_for("auth.security"))

        elif action == "remove_passcode":
            current_password = request.form.get("current_password", "")
            if not check_password_hash(current_user.password_hash, current_password):
                flash("Incorrect password", "error")
                return redirect(url_for("auth.security"))
            current_user.passcode_hash = None
            db.session.commit()
            flash("Passcode removed", "success")
            return redirect(url_for("auth.security"))

    return render_template("security.html", user=current_user)


@auth_bp.route("/admin-logout")
def admin_logout():
    session.pop("is_admin", None)
    session.clear()
    return redirect(url_for("auth.login"))


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))