"""
migrate.py — Run once to migrate existing database
"""
from app import app, db
from sqlalchemy import text

def migrate():
    with app.app_context():
        conn = db.engine.connect()

        columns_to_add = [
            ("users", "demo_balance",          "FLOAT DEFAULT 500000.0"),
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
            ("transactions", "currency",        "TEXT"),
            ("transactions", "crypto_amount",   "FLOAT"),
            ("transactions", "crypto_tx_hash",  "TEXT"),
            ("transactions", "crypto_from",     "TEXT"),
            ("transactions", "crypto_to",       "TEXT"),
            ("transactions", "pq_proof",        "TEXT"),
            ("transactions", "aqs_mode",        "TEXT"),
            ("transactions", "risk_score",      "FLOAT"),
        ]

        for table, column, col_type in columns_to_add:
            try:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"))
                conn.commit()
                print(f"  ✓ Added {table}.{column}")
            except Exception as e:
                if "duplicate column" in str(e).lower() or "already exists" in str(e).lower():
                    print(f"  — {table}.{column} already exists")
                else:
                    print(f"  ✗ {table}.{column}: {e}")

        # Copy existing balance to demo_balance
        try:
            conn.execute(text("UPDATE users SET demo_balance = balance WHERE demo_balance IS NULL OR demo_balance = 0"))
            conn.commit()
            print("  ✓ Copied balance → demo_balance")
        except Exception as e:
            print(f"  balance copy: {e}")

        conn.close()
        print("\nMigration complete!")

if __name__ == "__main__":
    migrate()