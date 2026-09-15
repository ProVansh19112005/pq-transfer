"""
algorithms.py
-------------
Post-quantum signature algorithm wrapper using liboqs-python 0.16.0.
Uses final NIST algorithm names:

  - FALCON    → Falcon-512                (NIST FIPS 206, Level 2)
  - DILITHIUM → ML-DSA-65                 (NIST FIPS 204, Level 3)
  - SPHINCS   → SLH_DSA_PURE_SHA2_256F   (NIST FIPS 205, Level 5)

SLH_DSA_PURE_SHA2_256F is used for genuine Level 5 security claims.
SLH_DSA_PURE_SHA2_128F would be Level 1 — incorrect for paper claims.
"""

import time
import oqs

ALGORITHM_MAP = {
    "FALCON":    "Falcon-512",
    "DILITHIUM": "ML-DSA-65",
    "SPHINCS":   "SLH_DSA_PURE_SHA2_256F",   # Level 5 — matches FIPS 205 Level 5 claim
}

ALGORITHM_INFO = {
    "FALCON": {
        "full_name":      "FALCON-512",
        "standard":       "NIST FIPS 206",
        "strength":       "Level 2",
        "speed":          "Very Fast",
        "best_for":       "Frequent / lightweight transactions",
        "security_level": 2,
        "family":         "Lattice (NTRU)",
        "public_key_bytes": 897,
    },
    "DILITHIUM": {
        "full_name":      "ML-DSA-65 (Dilithium3)",
        "standard":       "NIST FIPS 204",
        "strength":       "Level 3",
        "speed":          "Fast",
        "best_for":       "Standard / routine transactions",
        "security_level": 3,
        "family":         "Lattice (Module-LWE)",
        "public_key_bytes": 1952,
    },
    "SPHINCS": {
        "full_name":      "SLH-DSA-SHA2-256f (SPHINCS+)",
        "standard":       "NIST FIPS 205",
        "strength":       "Level 5",
        "speed":          "Slower",
        "best_for":       "Critical / high-value transactions",
        "security_level": 5,
        "family":         "Hash-based (stateless)",
        "public_key_bytes": 64,
    },
}


def generate_keypair(algorithm: str) -> dict:
    """Generate a real post-quantum keypair using liboqs."""
    algo_name = ALGORITHM_MAP[algorithm]
    with oqs.Signature(algo_name) as signer:
        public_key  = signer.generate_keypair()
        private_key = signer.export_secret_key()
    return {
        "algorithm":   algorithm,
        "public_key":  public_key,   # bytes
        "private_key": private_key,  # bytes
    }


def sign_data(data: bytes, private_key: bytes, algorithm: str) -> dict:
    """Sign data using the real algorithm. Returns signature + timing."""
    algo_name = ALGORITHM_MAP[algorithm]
    start = time.perf_counter()
    with oqs.Signature(algo_name, secret_key=private_key) as signer:
        signature = signer.sign(data)
    elapsed = (time.perf_counter() - start) * 1000
    return {
        "signature":       signature,
        "signing_time_ms": round(elapsed, 4),
        "sig_size_bytes":  len(signature),
    }


def verify_signature(data: bytes, signature: bytes,
                     public_key: bytes, algorithm: str) -> bool:
    """Verify a real post-quantum signature."""
    algo_name = ALGORITHM_MAP[algorithm]
    try:
        with oqs.Signature(algo_name) as verifier:
            return verifier.verify(data, signature, public_key)
    except Exception:
        return False


def get_algorithm_info(algorithm: str) -> dict:
    return ALGORITHM_INFO.get(algorithm, {})