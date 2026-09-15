"""
config.py — App configuration
"""
import os

class Config:
    SECRET_KEY              = os.environ.get("SECRET_KEY", "pq-blockchain-secret-2026")
    SQLALCHEMY_DATABASE_URI = "sqlite:////data/pq_transfer.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER           = "/data/uploads"
    MAX_CONTENT_LENGTH      = 50 * 1024 * 1024
    DEFAULT_BALANCE         = 500_000.0
    ADMIN_EMAIL             = "admin@gmail.com"
    ADMIN_PASSWORD          = "vansh@admin"