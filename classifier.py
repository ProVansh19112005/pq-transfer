"""
classifier.py — Adaptive algorithm selector (Core IP)
"""

SENSITIVITY_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Payment thresholds — fixed algo per range, no risk scorer involved
# ₹0       – ₹9,999     → FALCON
# ₹10,000  – ₹99,999    → AQS-256-1
# ₹1,00,000 – ₹4,99,999 → AQS-256-2
# ₹5,00,000+             → SPHINCS
PAYMENT_RULES = [
    (0,           10_000,       "LOW",      "FALCON"),
    (10_000,      1_00_000,     "MEDIUM",   "AQS-256-1"),
    (1_00_000,    5_00_000,     "HIGH",     "AQS-256-2"),
    (5_00_000,    float("inf"), "CRITICAL", "SPHINCS"),
]

# Decision rules for non-payment transactions
DECISION_RULES = {
    ("FILE",      "LOW"):      "FALCON",
    ("FILE",      "MEDIUM"):   "DILITHIUM",
    ("FILE",      "HIGH"):     "SPHINCS",
    ("FILE",      "CRITICAL"): "SPHINCS",
    ("DOCUMENT",  "LOW"):      "DILITHIUM",
    ("DOCUMENT",  "MEDIUM"):   "DILITHIUM",
    ("DOCUMENT",  "HIGH"):     "SPHINCS",
    ("DOCUMENT",  "CRITICAL"): "SPHINCS",
    ("MESSAGE",   "LOW"):      "FALCON",
    ("MESSAGE",   "MEDIUM"):   "FALCON",
    ("MESSAGE",   "HIGH"):     "DILITHIUM",
    ("MESSAGE",   "CRITICAL"): "SPHINCS",
    ("IDENTITY",  "LOW"):      "DILITHIUM",
    ("IDENTITY",  "MEDIUM"):   "DILITHIUM",
    ("IDENTITY",  "HIGH"):     "SPHINCS",
    ("IDENTITY",  "CRITICAL"): "SPHINCS",
    ("ROUTINE",   "LOW"):      "FALCON",
    ("ROUTINE",   "MEDIUM"):   "FALCON",
    ("ROUTINE",   "HIGH"):     "DILITHIUM",
    ("ROUTINE",   "CRITICAL"): "DILITHIUM",
}

# AQS algorithm name → aqs_mode mapping
AQS_MAP = {
    "AQS-256-1": "FALCON+DILITHIUM",
    "AQS-256-2": "DILITHIUM+SPHINCS",
}


def classify(tx_type: str, sensitivity: str, value: float = 0.0,
             manual_algorithm: str = None) -> dict:
    """
    Classify a transaction and select algorithm.

    For PAYMENT: fixed algorithm by amount range — risk scorer bypassed.
    For others:  uses sensitivity + optional manual override.
    """

    # ── PAYMENT: fixed ranges, no risk scorer ────────────────────────
    if tx_type == "PAYMENT":
        for low, high, sens, algo in PAYMENT_RULES:
            if low <= value < high:
                aqs_mode = AQS_MAP.get(algo)
                return {
                    "tx_type":           tx_type,
                    "sensitivity":       sens,
                    "final_sensitivity": sens,
                    "value":             value,
                    "algorithm":         algo,
                    "aqs_mode":          aqs_mode,
                    "manual":            False,
                    "reasoning":         f"Payment ₹{value:,.0f} → fixed range → algorithm: {algo}",
                }

    # ── Manual override (non-payment) ────────────────────────────────
    if manual_algorithm and manual_algorithm in ["FALCON", "DILITHIUM", "SPHINCS"]:
        return {
            "tx_type":           tx_type,
            "sensitivity":       sensitivity,
            "final_sensitivity": sensitivity,
            "value":             value,
            "algorithm":         manual_algorithm,
            "aqs_mode":          None,
            "manual":            True,
            "reasoning":         f"Algorithm manually overridden to '{manual_algorithm}' by user",
        }

    # ── Auto select (non-payment) ────────────────────────────────────
    algorithm = DECISION_RULES.get((tx_type, sensitivity), "DILITHIUM")
    return {
        "tx_type":           tx_type,
        "sensitivity":       sensitivity,
        "final_sensitivity": sensitivity,
        "value":             value,
        "algorithm":         algorithm,
        "aqs_mode":          None,
        "manual":            False,
        "reasoning":         f"Type '{tx_type}' + sensitivity '{sensitivity}' → algorithm: {algorithm}",
    }