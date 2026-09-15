"""
database.py — All database models
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id            = db.Column(db.Integer, primary_key=True)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    username      = db.Column(db.String(80),  unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    passcode_hash = db.Column(db.String(256), nullable=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    demo_balance  = db.Column(db.Float, default=500_000.0)

    falcon_pk     = db.Column(db.Text, nullable=True)
    falcon_sk     = db.Column(db.Text, nullable=True)
    dilithium_pk  = db.Column(db.Text, nullable=True)
    dilithium_sk  = db.Column(db.Text, nullable=True)
    sphincs_pk    = db.Column(db.Text, nullable=True)
    sphincs_sk    = db.Column(db.Text, nullable=True)
    wallet_address = db.Column(db.String(64), unique=True, nullable=True)

    aqs_fd_primary_pk   = db.Column(db.Text, nullable=True)
    aqs_fd_primary_sk   = db.Column(db.Text, nullable=True)
    aqs_fd_secondary_pk = db.Column(db.Text, nullable=True)
    aqs_fd_secondary_sk = db.Column(db.Text, nullable=True)

    aqs_ds_primary_pk   = db.Column(db.Text, nullable=True)
    aqs_ds_primary_sk   = db.Column(db.Text, nullable=True)
    aqs_ds_secondary_pk = db.Column(db.Text, nullable=True)
    aqs_ds_secondary_sk = db.Column(db.Text, nullable=True)

    ltc_address   = db.Column(db.String(128), nullable=True)
    ltc_sk        = db.Column(db.Text,        nullable=True)

    trx_address   = db.Column(db.String(128), nullable=True)
    trx_sk        = db.Column(db.Text,        nullable=True)

    sent_transactions     = db.relationship("Transaction", foreign_keys="Transaction.sender_id",   backref="sender",   lazy=True)
    received_transactions = db.relationship("Transaction", foreign_keys="Transaction.receiver_id", backref="receiver", lazy=True)

    @property
    def balance(self):
        return self.demo_balance

    @balance.setter
    def balance(self, value):
        self.demo_balance = value

    @property
    def has_passcode(self):
        return self.passcode_hash is not None

    def get_keypair(self, algorithm: str) -> dict:
        mapping = {
            "FALCON":    (self.falcon_pk,    self.falcon_sk),
            "DILITHIUM": (self.dilithium_pk, self.dilithium_sk),
            "SPHINCS":   (self.sphincs_pk,   self.sphincs_sk),
        }
        pk_hex, sk_hex = mapping[algorithm]
        return {
            "public_key":  bytes.fromhex(pk_hex),
            "private_key": bytes.fromhex(sk_hex),
        }

    def get_aqs_keypair(self, mode: str) -> dict:
        if mode == "FALCON+DILITHIUM":
            return {
                "primary_pk":   bytes.fromhex(self.aqs_fd_primary_pk),
                "primary_sk":   bytes.fromhex(self.aqs_fd_primary_sk),
                "secondary_pk": bytes.fromhex(self.aqs_fd_secondary_pk),
                "secondary_sk": bytes.fromhex(self.aqs_fd_secondary_sk),
            }
        elif mode == "DILITHIUM+SPHINCS":
            return {
                "primary_pk":   bytes.fromhex(self.aqs_ds_primary_pk),
                "primary_sk":   bytes.fromhex(self.aqs_ds_primary_sk),
                "secondary_pk": bytes.fromhex(self.aqs_ds_secondary_pk),
                "secondary_sk": bytes.fromhex(self.aqs_ds_secondary_sk),
            }

    def __repr__(self):
        return f"User({self.username} | {self.email})"


class Transaction(db.Model):
    __tablename__ = "transactions"

    id                = db.Column(db.Integer, primary_key=True)
    tx_hash           = db.Column(db.String(64),  unique=True, nullable=False)
    nonce             = db.Column(db.String(32),  nullable=True)
    sender_id         = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    receiver_id       = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    tx_type           = db.Column(db.String(32),  nullable=False)
    amount            = db.Column(db.Float,   default=0.0)
    sensitivity       = db.Column(db.String(16),  nullable=False)
    final_sensitivity = db.Column(db.String(16),  nullable=False)
    algorithm         = db.Column(db.String(16),  nullable=False)
    algorithm_manual  = db.Column(db.Boolean, default=False)
    aqs_mode          = db.Column(db.String(32),  nullable=True)
    risk_score        = db.Column(db.Float,   nullable=True)
    status            = db.Column(db.String(16),  default="PENDING")
    reasoning         = db.Column(db.Text,    nullable=True)
    sig_size_bytes    = db.Column(db.Integer, nullable=True)
    signing_time_ms   = db.Column(db.Float,   nullable=True)
    signature         = db.Column(db.Text,    nullable=True)
    message           = db.Column(db.Text,    nullable=True)
    timestamp         = db.Column(db.DateTime, default=datetime.utcnow)

    filename          = db.Column(db.String(256), nullable=True)
    file_path         = db.Column(db.String(512), nullable=True)
    file_hash         = db.Column(db.String(64),  nullable=True)
    file_size         = db.Column(db.Integer,     nullable=True)

    currency          = db.Column(db.String(8),   nullable=True)
    crypto_amount     = db.Column(db.Float,       nullable=True)
    crypto_tx_hash    = db.Column(db.String(128), nullable=True)
    crypto_from       = db.Column(db.String(128), nullable=True)
    crypto_to         = db.Column(db.String(128), nullable=True)
    pq_proof          = db.Column(db.Text,        nullable=True)

    def to_dict(self):
        return {
            "id":               self.id,
            "tx_hash":          self.tx_hash,
            "sender":           self.sender.username   if self.sender   else "?",
            "receiver":         self.receiver.username if self.receiver else "?",
            "tx_type":          self.tx_type,
            "amount":           self.amount,
            "sensitivity":      self.sensitivity,
            "final_sensitivity":self.final_sensitivity,
            "algorithm":        self.algorithm,
            "algorithm_manual": self.algorithm_manual,
            "aqs_mode":         self.aqs_mode,
            "risk_score":       self.risk_score,
            "status":           self.status,
            "reasoning":        self.reasoning,
            "sig_size_bytes":   self.sig_size_bytes,
            "signing_time_ms":  self.signing_time_ms,
            "message":          self.message,
            "filename":         self.filename,
            "file_hash":        self.file_hash,
            "file_size":        self.file_size,
            "currency":         self.currency,
            "crypto_amount":    self.crypto_amount,
            "crypto_tx_hash":   self.crypto_tx_hash,
            "crypto_from":      self.crypto_from,
            "crypto_to":        self.crypto_to,
            "timestamp":        self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        }