"""
file_classifier.py — File sensitivity analyzer
"""
import os

CRITICAL_KEYWORDS = ["passport","visa","national_id","identity","secret","classified",
                     "confidential","medical","health","diagnosis","prescription",
                     "legal","court","contract","deed","will","government","military"]

HIGH_KEYWORDS = ["bank","statement","salary","tax","finance","invoice","payment",
                 "transfer","account","insurance","mortgage","certificate","license",
                 "official","report","agreement","policy"]

MEDIUM_KEYWORDS = ["employee","hr","payroll","project","proposal","budget","plan",
                   "strategy","research","analysis","audit","review","application"]

EXTENSION_SENSITIVITY = {
    ".pdf": "HIGH", ".docx": "HIGH", ".doc": "HIGH",
    ".xlsx": "MEDIUM", ".xls": "MEDIUM",
    ".jpg": "MEDIUM", ".jpeg": "MEDIUM", ".png": "LOW",
    ".txt": "LOW", ".csv": "MEDIUM", ".json": "LOW",
    ".zip": "MEDIUM", ".mp4": "LOW", ".mp3": "LOW",
}

SENSITIVITY_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

ALGORITHM_MAP = {
    "LOW": "FALCON", "MEDIUM": "DILITHIUM",
    "HIGH": "SPHINCS", "CRITICAL": "SPHINCS"
}

def classify_file(filename: str, filesize: int) -> dict:
    name_lower = filename.lower().replace(" ", "_")
    ext        = os.path.splitext(filename)[1].lower()
    reasons    = []

    ext_sensitivity = EXTENSION_SENSITIVITY.get(ext, "MEDIUM")
    reasons.append(f"File extension '{ext}' → base sensitivity: {ext_sensitivity}")

    keyword_sensitivity = "LOW"
    matched_keyword     = None
    for kw in CRITICAL_KEYWORDS:
        if kw in name_lower:
            keyword_sensitivity = "CRITICAL"
            matched_keyword = kw
            break
    if keyword_sensitivity == "LOW":
        for kw in HIGH_KEYWORDS:
            if kw in name_lower:
                keyword_sensitivity = "HIGH"
                matched_keyword = kw
                break
    if keyword_sensitivity == "LOW":
        for kw in MEDIUM_KEYWORDS:
            if kw in name_lower:
                keyword_sensitivity = "MEDIUM"
                matched_keyword = kw
                break

    if matched_keyword:
        reasons.append(f"Keyword '{matched_keyword}' found → sensitivity: {keyword_sensitivity}")

    size_sensitivity = "LOW"
    if filesize > 100_000_000:   size_sensitivity = "CRITICAL"
    elif filesize > 10_000_000:  size_sensitivity = "HIGH"
    elif filesize > 1_000_000:   size_sensitivity = "MEDIUM"
    reasons.append(f"File size {filesize:,} bytes → size sensitivity: {size_sensitivity}")

    all_levels        = [ext_sensitivity, keyword_sensitivity, size_sensitivity]
    final_num         = max(SENSITIVITY_LEVELS[s] for s in all_levels)
    final_sensitivity = [k for k, v in SENSITIVITY_LEVELS.items() if v == final_num][0]
    algorithm         = ALGORITHM_MAP[final_sensitivity]
    reasons.append(f"Final sensitivity: {final_sensitivity} → Algorithm: {algorithm}")

    return {
        "filename": filename, "filesize": filesize,
        "ext_sensitivity": ext_sensitivity,
        "keyword_sensitivity": keyword_sensitivity,
        "size_sensitivity": size_sensitivity,
        "final_sensitivity": final_sensitivity,
        "algorithm": algorithm, "reasons": reasons,
    }