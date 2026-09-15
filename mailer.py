"""
mailer.py — Email service using Brevo
"""

import os
import random
import string
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException

BREVO_API_KEY = os.environ.get("BREVO_API_KEY")
SENDER_EMAIL  = os.environ.get("BREVO_SENDER_EMAIL")
SENDER_NAME   = os.environ.get("BREVO_SENDER_NAME", "PQ Transfer")

otp_store = {}

def get_api():
    config = sib_api_v3_sdk.Configuration()
    config.api_key["api-key"] = BREVO_API_KEY
    return sib_api_v3_sdk.TransactionalEmailsApi(
        sib_api_v3_sdk.ApiClient(config)
    )

def generate_otp() -> str:
    return "".join(random.choices(string.digits, k=6))

def send_email(to_email: str, to_name: str, subject: str, html: str) -> bool:
    try:
        api     = get_api()
        sender  = sib_api_v3_sdk.SendSmtpEmailSender(email=SENDER_EMAIL, name=SENDER_NAME)
        to      = [sib_api_v3_sdk.SendSmtpEmailTo(email=to_email, name=to_name)]
        content = sib_api_v3_sdk.SendSmtpEmail(
            sender=sender, to=to, subject=subject, html_content=html
        )
        api.send_transac_email(content)
        print(f"  Email sent to {to_email}")
        return True
    except ApiException as e:
        print(f"  Email error: {e}")
        return False

def send_otp(email: str, username: str) -> str:
    otp = generate_otp()
    otp_store[email] = otp
    print(f"  OTP for {email}: {otp}")

    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:0 auto;
                background:#0f1117;color:#e0e0e0;border-radius:12px;
                padding:32px;border:1px solid #ffffff11;">
      <h2 style="color:#00d4ff;margin-bottom:8px;">⚛ PQ Transfer</h2>
      <p style="color:#888;margin-bottom:24px;">Quantum-resistant transfer platform</p>
      <h3 style="margin-bottom:16px;">Verify your email</h3>
      <p style="color:#aaa;margin-bottom:24px;">
        Hi <strong>{username}</strong>, use this OTP to complete your registration:
      </p>
      <div style="background:#00d4ff15;border:2px solid #00d4ff44;
                  border-radius:12px;padding:24px;text-align:center;
                  font-size:2.5rem;font-weight:700;
                  letter-spacing:12px;color:#00d4ff;margin-bottom:24px;">
        {otp}
      </div>
      <p style="color:#555;font-size:0.82rem;">
        This OTP expires in 10 minutes. Do not share it with anyone.
      </p>
    </div>
    """
    send_email(email, username, "Your PQ Transfer OTP", html)
    return otp

def send_welcome(email: str, username: str, wallet_address: str):
    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:0 auto;
                background:#0f1117;color:#e0e0e0;border-radius:12px;
                padding:32px;border:1px solid #ffffff11;">
      <h2 style="color:#00d4ff;margin-bottom:8px;">⚛ PQ Transfer</h2>
      <p style="color:#888;margin-bottom:24px;">Quantum-resistant transfer platform</p>
      <h3 style="margin-bottom:16px;">Welcome, {username}! 🎉</h3>
      <p style="color:#aaa;margin-bottom:16px;">
        Your quantum-resistant wallet has been created successfully.
      </p>
      <div style="background:#2ecc7115;border:1px solid #2ecc7133;
                  border-radius:8px;padding:16px;margin-bottom:20px;">
        <p style="color:#888;font-size:0.78rem;margin-bottom:4px;">Your Wallet Address</p>
        <p style="font-family:monospace;color:#2ecc71;font-size:0.85rem;
                  word-break:break-all;">{wallet_address}</p>
      </div>
      <p style="color:#555;font-size:0.78rem;">
        Starting balance: ₹5,00,000 · Algorithm selected automatically per transaction
      </p>
    </div>
    """
    send_email(email, username, "Welcome to PQ Transfer — Wallet Created!", html)


def _base_email(title, body_html, cta_link=None, cta_text=None):
    cta_block = ""
    if cta_link:
        cta_block = f"""
        <a href="{cta_link}"
           style="display:block;text-align:center;background:#00d4ff22;
                  border:1px solid #00d4ff55;color:#00d4ff;padding:12px;
                  border-radius:8px;text-decoration:none;font-weight:600;margin-top:16px;">
          {cta_text or 'View Transaction →'}
        </a>
        """
    return f"""
    <div style="font-family:sans-serif;max-width:480px;margin:0 auto;
                background:#0f1117;color:#e0e0e0;border-radius:12px;
                padding:32px;border:1px solid #ffffff11;">
      <h2 style="color:#00d4ff;margin-bottom:8px;">⚛ PQ Transfer</h2>
      <p style="color:#888;margin-bottom:24px;">Quantum-resistant transfer platform</p>
      <h3 style="margin-bottom:16px;">{title}</h3>
      {body_html}
      {cta_block}
    </div>
    """


def send_transaction_notification(
    receiver_email: str, receiver_name: str,
    sender_name: str, tx_type: str,
    amount: float, algorithm: str,
    filename: str = None, message: str = None
):
    """Notify the RECEIVER that they got something."""
    if tx_type == "PAYMENT":
        subject = f"⚛ You received ₹{amount:,.0f} from {sender_name}"
        detail  = f"<strong style='color:#2ecc71;'>₹{amount:,.2f}</strong>"
        type_str = "Payment"
    elif tx_type in ["FILE", "DOCUMENT"]:
        subject  = f"⚛ {sender_name} sent you a {tx_type.lower()}"
        detail   = f"<strong style='color:#00d4ff;'>{filename or 'File'}</strong>"
        type_str = tx_type.capitalize()
    else:
        subject  = f"⚛ New {tx_type.lower()} from {sender_name}"
        detail   = f"<strong>{tx_type}</strong>"
        type_str = tx_type.capitalize()

    algo_colors = {"FALCON": "#2ecc71", "DILITHIUM": "#3498db", "SPHINCS": "#e74c3c"}
    algo_color  = algo_colors.get(algorithm, "#9b59b6")

    msg_block = ""
    if message:
        msg_block = f"""
        <div style="background:#ffffff08;border-radius:8px;padding:12px;margin-bottom:16px;">
          <p style="color:#888;font-size:0.78rem;margin-bottom:4px;">Message</p>
          <p style="color:#aaa;font-size:0.85rem;">"{message}"</p>
        </div>
        """

    body = f"""
      <p style="color:#aaa;margin-bottom:20px;">
        Hi <strong>{receiver_name}</strong>,
        <strong>{sender_name}</strong> sent you {detail}.
      </p>
      <div style="background:#ffffff08;border-radius:8px;padding:16px;margin-bottom:16px;">
        <table style="width:100%;font-size:0.82rem;">
          <tr><td style="color:#666;padding:4px 0;">From</td><td style="color:#aaa;">{sender_name}</td></tr>
          <tr><td style="color:#666;padding:4px 0;">Type</td><td style="color:#aaa;">{type_str}</td></tr>
          <tr><td style="color:#666;padding:4px 0;">Amount</td><td style="color:#aaa;">{detail}</td></tr>
          <tr><td style="color:#666;padding:4px 0;">Algorithm</td><td style="color:{algo_color};font-weight:600;">{algorithm}</td></tr>
        </table>
      </div>
      {msg_block}
      <div style="background:#2ecc7115;border:1px solid #2ecc7133;
                  border-radius:8px;padding:12px;">
        <p style="color:#2ecc71;font-size:0.78rem;">
          🔐 Signed with <strong>{algorithm}</strong> post-quantum cryptography.
        </p>
      </div>
    """

    html = _base_email(f"New {type_str} Received", body, "https://pq-transfer.fly.dev/history", "View Transaction →")
    send_email(receiver_email, receiver_name, subject, html)


def send_sent_confirmation(
    sender_email: str, sender_name: str,
    receiver_name: str, tx_type: str,
    amount: float, algorithm: str,
    filename: str = None, message: str = None
):
    """Notify the SENDER that their transfer went through."""
    if tx_type == "PAYMENT":
        subject = f"⚛ You sent ₹{amount:,.0f} to {receiver_name}"
        detail  = f"<strong style='color:#2ecc71;'>₹{amount:,.2f}</strong>"
        type_str = "Payment"
    elif tx_type in ["FILE", "DOCUMENT"]:
        subject  = f"⚛ You sent a {tx_type.lower()} to {receiver_name}"
        detail   = f"<strong style='color:#00d4ff;'>{filename or 'File'}</strong>"
        type_str = tx_type.capitalize()
    else:
        subject  = f"⚛ You sent a {tx_type.lower()} to {receiver_name}"
        detail   = f"<strong>{tx_type}</strong>"
        type_str = tx_type.capitalize()

    algo_colors = {"FALCON": "#2ecc71", "DILITHIUM": "#3498db", "SPHINCS": "#e74c3c"}
    algo_color  = algo_colors.get(algorithm, "#9b59b6")

    msg_block = ""
    if message:
        msg_block = f"""
        <div style="background:#ffffff08;border-radius:8px;padding:12px;margin-bottom:16px;">
          <p style="color:#888;font-size:0.78rem;margin-bottom:4px;">Your Message</p>
          <p style="color:#aaa;font-size:0.85rem;">"{message}"</p>
        </div>
        """

    body = f"""
      <p style="color:#aaa;margin-bottom:20px;">
        Hi <strong>{sender_name}</strong>,
        your transfer of {detail} to <strong>{receiver_name}</strong> was signed and sent successfully.
      </p>
      <div style="background:#ffffff08;border-radius:8px;padding:16px;margin-bottom:16px;">
        <table style="width:100%;font-size:0.82rem;">
          <tr><td style="color:#666;padding:4px 0;">To</td><td style="color:#aaa;">{receiver_name}</td></tr>
          <tr><td style="color:#666;padding:4px 0;">Type</td><td style="color:#aaa;">{type_str}</td></tr>
          <tr><td style="color:#666;padding:4px 0;">Amount</td><td style="color:#aaa;">{detail}</td></tr>
          <tr><td style="color:#666;padding:4px 0;">Algorithm</td><td style="color:{algo_color};font-weight:600;">{algorithm}</td></tr>
        </table>
      </div>
      {msg_block}
      <div style="background:#3498db15;border:1px solid #3498db33;
                  border-radius:8px;padding:12px;">
        <p style="color:#3498db;font-size:0.78rem;">
          ✓ Signed with <strong>{algorithm}</strong> post-quantum cryptography and delivered.
        </p>
      </div>
    """

    html = _base_email(f"{type_str} Sent Successfully", body, "https://pq-transfer.fly.dev/history", "View Transaction →")
    send_email(sender_email, sender_name, subject, html)


def verify_otp(email: str, otp: str) -> bool:
    stored = otp_store.get(email)
    if stored and stored == otp.strip():
        del otp_store[email]
        return True
    return False