"""
risk_scorer.py
--------------
Computes risk score (0-100) for non-payment transactions only.

PAYMENT transactions now use fixed algorithm ranges in classifier.py:
  ₹0       – ₹9,999      → FALCON
  ₹10,000  – ₹99,999     → AQS-256-1
  ₹1,00,000 – ₹4,99,999  → AQS-256-2
  ₹5,00,000+              → SPHINCS

For all other types (FILE, DOCUMENT, MESSAGE, CRYPTO, etc.):
  Risk < 30   → FALCON
  Risk 30-59  → AQS-256-1 (FALCON + ML-DSA-65 fusion)
  Risk 60-79  → AQS-256-2 (ML-DSA-65 + SLH-DSA fusion)
  Risk ≥ 80   → SPHINCS
"""

from datetime import datetime

WEIGHTS = {
    "amount":      0.35,
    "tx_type":     0.20,
    "sensitivity": 0.20,
    "time":        0.10,
    "filename":    0.15,
}

TX_TYPE_RISK = {
    "DOCUMENT":       60,
    "FILE":           40,
    "MESSAGE":        20,
    "IDENTITY":       80,
    "ROUTINE":        10,
    "CRYPTO":         50,
    "WITHDRAW":       60,
}

SENSITIVITY_RISK = {
    "LOW":      10,
    "MEDIUM":   40,
    "HIGH":     70,
    "CRITICAL": 95,
}

HIGH_RISK_KEYWORDS = [
    "passport", "visa", "medical", "legal", "contract",
    "bank", "tax", "secret", "classified", "confidential",
    "salary", "court", "deed", "will", "certificate",
]

def compute_amount_risk(amount: float) -> float:
    if amount <= 0:           return 0
    elif amount < 1_000:      return 5
    elif amount < 10_000:     return 20
    elif amount < 50_000:     return 40
    elif amount < 1_00_000:   return 55
    elif amount < 5_00_000:   return 70
    elif amount < 10_00_000:  return 85
    else:                     return 98

def compute_time_risk() -> float:
    hour = datetime.utcnow().hour
    if 2 <= hour <= 5:             return 80
    elif 22 <= hour or hour <= 1:  return 50
    elif 9 <= hour <= 17:          return 10
    else:                          return 25

def compute_filename_risk(filename: str = None) -> float:
    if not filename:
        return 0
    name_lower = filename.lower()
    for kw in HIGH_RISK_KEYWORDS:
        if kw in name_lower:
            return 90
    return 15

def compute_risk_score(
    tx_type: str,
    sensitivity: str,
    amount: float = 0.0,
    filename: str = None,
) -> dict:
    """
    Compute risk score. PAYMENT type is handled by fixed ranges in
    classifier.py — this function should not be called for PAYMENT.
    Returns a dummy result for PAYMENT if called anyway.
    """
    if tx_type == "PAYMENT":
        return {
            "score": 0, "action": "FIXED_RANGE", "aqs_active": False,
            "aqs_mode": None, "aqs_name": None, "breakdown": {},
        }

    amount_risk      = compute_amount_risk(amount)
    tx_type_risk     = TX_TYPE_RISK.get(tx_type, 50)
    sensitivity_risk = SENSITIVITY_RISK.get(sensitivity, 40)
    time_risk        = compute_time_risk()
    filename_risk    = compute_filename_risk(filename)

    score = (
        amount_risk      * WEIGHTS["amount"]      +
        tx_type_risk     * WEIGHTS["tx_type"]      +
        sensitivity_risk * WEIGHTS["sensitivity"]  +
        time_risk        * WEIGHTS["time"]         +
        filename_risk    * WEIGHTS["filename"]
    )
    score = round(min(100, max(0, score)), 2)

    if score < 30:
        action     = "FALCON"
        aqs_active = False
        aqs_mode   = None
        aqs_name   = None
    elif score < 60:
        action     = "AQS-256-1"
        aqs_active = True
        aqs_mode   = "FALCON+DILITHIUM"
        aqs_name   = "AQS-256-1"
    elif score < 80:
        action     = "AQS-256-2"
        aqs_active = True
        aqs_mode   = "DILITHIUM+SPHINCS"
        aqs_name   = "AQS-256-2"
    else:
        action     = "SPHINCS"
        aqs_active = False
        aqs_mode   = None
        aqs_name   = None

    return {
        "score":      score,
        "action":     action,
        "aqs_active": aqs_active,
        "aqs_mode":   aqs_mode,
        "aqs_name":   aqs_name,
        "breakdown": {
            "amount_risk":      amount_risk,
            "tx_type_risk":     tx_type_risk,
            "sensitivity_risk": sensitivity_risk,
            "time_risk":        time_risk,
            "filename_risk":    filename_risk,
        }
    }