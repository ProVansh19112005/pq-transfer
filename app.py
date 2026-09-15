"""
app.py — Main Flask application
"""
from flask import Flask, redirect, url_for
from flask_login import LoginManager
from flask_socketio import SocketIO
from database import db, User
from config import Config
import os

app       = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
socketio  = SocketIO(app, cors_allowed_origins="*")
login_mgr = LoginManager(app)
login_mgr.login_view = "auth.login"

@login_mgr.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route("/")
def index():
    return redirect(url_for("auth.login"))

from auth         import auth_bp
from transactions import tx_bp
app.register_blueprint(auth_bp)
app.register_blueprint(tx_bp)

def run_migrations():
    """Add any missing columns to existing database."""
    from sqlalchemy import text
    columns = [
        ("users", "demo_balance",          "FLOAT DEFAULT 500000.0"),
        ("users", "passcode_hash",         "TEXT"),
        ("users", "ltc_address",           "TEXT"),
        ("users", "ltc_sk",                "TEXT"),
        ("users", "trx_address",           "TEXT"),
        ("users", "trx_sk",                "TEXT"),
        ("users", "aqs_fd_primary_pk",     "TEXT"),
        ("users", "aqs_fd_primary_sk",     "TEXT"),
        ("users", "aqs_fd_secondary_pk",   "TEXT"),
        ("users", "aqs_fd_secondary_sk",   "TEXT"),
        ("users", "aqs_ds_primary_pk",     "TEXT"),
        ("users", "aqs_ds_primary_sk",     "TEXT"),
        ("users", "aqs_ds_secondary_pk",   "TEXT"),
        ("users", "aqs_ds_secondary_sk",   "TEXT"),
        ("transactions", "currency",       "TEXT"),
        ("transactions", "crypto_amount",  "FLOAT"),
        ("transactions", "crypto_tx_hash", "TEXT"),
        ("transactions", "crypto_from",    "TEXT"),
        ("transactions", "crypto_to",      "TEXT"),
        ("transactions", "pq_proof",       "TEXT"),
        ("transactions", "aqs_mode",       "TEXT"),
        ("transactions", "risk_score",     "FLOAT"),
        ("transactions", "nonce",          "TEXT"),
    ]
    with db.engine.connect() as conn:
        for table, column, col_type in columns:
            try:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"))
                conn.commit()
                print(f"  ✓ Migrated {table}.{column}")
            except Exception as e:
                if "duplicate" in str(e).lower() or "already exists" in str(e).lower():
                    pass
                else:
                    print(f"  — {table}.{column}: {e}")
        try:
            conn.execute(text(
                "UPDATE users SET demo_balance = balance "
                "WHERE demo_balance IS NULL OR demo_balance = 0"
            ))
            conn.commit()
        except Exception:
            pass
    print("  Migrations complete.")

with app.app_context():
    os.makedirs("/data/uploads", exist_ok=True)
    db.create_all()
    run_migrations()

if __name__ == "__main__":
    print("\n  PQ Transfer starting...")
    print("  Open http://localhost:5000\n")
    socketio.run(app, debug=False, host="0.0.0.0", port=8080,
                 allow_unsafe_werkzeug=True)