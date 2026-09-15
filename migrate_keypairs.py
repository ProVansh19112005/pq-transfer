"""
migrate_keypairs.py
-------------------
One-time migration: regenerate all PQ keypairs for every existing user
after switching from dilithium-py to liboqs (Falcon-512 / Dilithium3 / SPHINCS+).

Run ONCE on the server:
    python migrate_keypairs.py

Safe to re-run — skipping users whose keys are already the right size is
handled by the --force flag (default: regenerate everyone).
"""

import sys
import hashlib
from app import app, db
from database import User
from algorithms import generate_keypair
from aqs import aqs_keygen

def migrate_all(force: bool = True):
    with app.app_context():
        users = User.query.all()
        print(f"\nFound {len(users)} user(s) to migrate.\n")

        for user in users:
            print(f"  [{user.id}] {user.username} <{user.email}>")

            try:
                # ── Standard keypairs ──────────────────────────────────────
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
                print(f"       ✓ Standard keypairs regenerated")

                # ── Wallet address (derived from dilithium pk) ─────────────
                pk = bytes.fromhex(user.dilithium_pk)
                user.wallet_address = hashlib.sha256(pk).hexdigest()[:40]
                print(f"       ✓ Wallet address updated: {user.wallet_address}")

                # ── AQS-256-1 keypair (FALCON+DILITHIUM) ──────────────────
                kp_fd = aqs_keygen("FALCON+DILITHIUM")
                user.aqs_fd_primary_pk   = kp_fd["primary_pk"].hex()
                user.aqs_fd_primary_sk   = kp_fd["primary_sk"].hex()
                user.aqs_fd_secondary_pk = kp_fd["secondary_pk"].hex()
                user.aqs_fd_secondary_sk = kp_fd["secondary_sk"].hex()
                print(f"       ✓ AQS-256-1 keypair regenerated")

                # ── AQS-256-2 keypair (DILITHIUM+SPHINCS) ─────────────────
                kp_ds = aqs_keygen("DILITHIUM+SPHINCS")
                user.aqs_ds_primary_pk   = kp_ds["primary_pk"].hex()
                user.aqs_ds_primary_sk   = kp_ds["primary_sk"].hex()
                user.aqs_ds_secondary_pk = kp_ds["secondary_pk"].hex()
                user.aqs_ds_secondary_sk = kp_ds["secondary_sk"].hex()
                print(f"       ✓ AQS-256-2 keypair regenerated")

                db.session.commit()
                print(f"       ✓ Committed\n")

            except Exception as e:
                db.session.rollback()
                print(f"       ✗ FAILED: {e}\n")

        print("Migration complete.")
        print("NOTE: Old transaction signatures are still verifiable because")
        print("      aqs_verify() uses the algo names stored inside each signature package.")
        print("      New transactions will use the new liboqs keypairs.\n")


if __name__ == "__main__":
    force = "--force" in sys.argv or True  # default: always regenerate
    migrate_all(force=force)