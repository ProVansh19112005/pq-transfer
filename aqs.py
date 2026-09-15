"""
aqs.py
------
AQS-256: Adaptive Quantum Shield
Novel hybrid post-quantum signature scheme using liboqs-python 0.16.0.

AQS-256-1: Falcon-512   + ML-DSA-65              (L2+L3 hybrid)
AQS-256-2: ML-DSA-65    + SLH_DSA_PURE_SHA2_256F (L3+L5 hybrid)
"""

import hashlib
import json
import time
import oqs

AQS_MODES = {
    "FALCON+DILITHIUM": {
        "primary":   "Falcon-512",
        "secondary": "ML-DSA-65",
        "weight":    0.6,
        "label":     "AQS-256-1",
    },
    "DILITHIUM+SPHINCS": {
        "primary":   "ML-DSA-65",
        "secondary": "SLH_DSA_PURE_SHA2_256F",   # Level 5
        "weight":    0.4,
        "label":     "AQS-256-2",
    },
}


def _xor_fuse(sig1: bytes, sig2: bytes, weight: float) -> bytes:
    """Fuse two signatures using weighted XOR."""
    max_len = max(len(sig1), len(sig2))
    s1 = sig1.ljust(max_len, b'\x00')
    s2 = sig2.ljust(max_len, b'\x00')
    fused = bytearray(max_len)
    for i in range(max_len):
        if i % 10 < int(weight * 10):
            fused[i] = s1[i] ^ (s2[i] >> 1)
        else:
            fused[i] = s2[i] ^ (s1[i] >> 1)
    return bytes(fused)


def aqs_keygen(mode: str) -> dict:
    """Generate real keypairs for both algorithms in AQS mode."""
    cfg = AQS_MODES[mode]
    with oqs.Signature(cfg["primary"]) as s:
        pk1 = s.generate_keypair()
        sk1 = s.export_secret_key()
    with oqs.Signature(cfg["secondary"]) as s:
        pk2 = s.generate_keypair()
        sk2 = s.export_secret_key()
    return {
        "mode":           mode,
        "primary_algo":   cfg["primary"],
        "secondary_algo": cfg["secondary"],
        "primary_pk":     pk1,
        "primary_sk":     sk1,
        "secondary_pk":   pk2,
        "secondary_sk":   sk2,
    }


def aqs_sign(data: bytes, primary_sk: bytes, secondary_sk: bytes,
             mode: str, risk_score: float) -> dict:
    """Sign data using AQS-256 hybrid scheme."""
    cfg    = AQS_MODES[mode]
    weight = cfg["weight"]
    start  = time.perf_counter()

    with oqs.Signature(cfg["primary"], secret_key=primary_sk) as s:
        sig1 = s.sign(data)
    with oqs.Signature(cfg["secondary"], secret_key=secondary_sk) as s:
        sig2 = s.sign(data)

    fused_sig = _xor_fuse(sig1, sig2, weight)
    elapsed   = (time.perf_counter() - start) * 1000

    package = {
        "mode":           mode,
        "primary_algo":   cfg["primary"],
        "secondary_algo": cfg["secondary"],
        "weight":         weight,
        "risk_score":     risk_score,
        "sig1":           sig1.hex(),
        "sig2":           sig2.hex(),
        "fused":          fused_sig.hex(),
        "data_hash":      hashlib.sha256(data).hexdigest(),
    }
    package_bytes = json.dumps(package).encode()

    return {
        "signature":       package_bytes,
        "signing_time_ms": round(elapsed, 4),
        "sig_size_bytes":  len(package_bytes),
        "aqs_mode":        mode,
        "risk_score":      risk_score,
        "primary_algo":    cfg["primary"],
        "secondary_algo":  cfg["secondary"],
    }


def aqs_verify(data: bytes, signature_bytes: bytes,
               primary_pk: bytes, secondary_pk: bytes) -> dict:
    """
    Verify AQS-256 composite signature. Both must pass.
    Reads algo names from inside the stored package for forward compatibility.
    """
    try:
        package        = json.loads(signature_bytes)
        primary_algo   = package["primary_algo"]
        secondary_algo = package["secondary_algo"]
        sig1           = bytes.fromhex(package["sig1"])
        sig2           = bytes.fromhex(package["sig2"])

        if hashlib.sha256(data).hexdigest() != package["data_hash"]:
            return {"verified": False, "reason": "Data hash mismatch — payload tampered",
                    "primary_valid": False, "secondary_valid": False}

        with oqs.Signature(primary_algo) as v:
            primary_valid = v.verify(data, sig1, primary_pk)
        with oqs.Signature(secondary_algo) as v:
            secondary_valid = v.verify(data, sig2, secondary_pk)

        verified = primary_valid and secondary_valid
        return {
            "verified":        verified,
            "primary_valid":   primary_valid,
            "secondary_valid": secondary_valid,
            "primary_algo":    primary_algo,
            "secondary_algo":  secondary_algo,
            "aqs_mode":        package["mode"],
            "risk_score":      package["risk_score"],
            "reason":          "Both signatures valid" if verified else
                               f"Primary: {primary_valid}, Secondary: {secondary_valid}",
        }
    except Exception as e:
        return {"verified": False, "reason": f"Verification error: {str(e)}",
                "primary_valid": False, "secondary_valid": False}