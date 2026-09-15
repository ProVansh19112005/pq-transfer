"""
crypto_wallet.py
----------------
Generates and manages real Litecoin and Tron wallets.
"""

import os
import time
import requests
import secrets
from tronpy import Tron
from tronpy.keys import PrivateKey as TronPrivateKey

BLOCKCYPHER_TOKEN = os.environ.get("BLOCKCYPHER_TOKEN")
TRONGRID_API_KEY  = os.environ.get("TRONGRID_API_KEY")

# Fee reserves
LTC_FEE_RESERVE = 0.0001   # Lowered for easier testing
TRX_FEE_RESERVE = 0.5
SAFETY_MARGIN   = 0.00002
MIN_SEND_LTC    = 0.0001
MIN_SEND_TRX    = 0.5


def generate_ltc_wallet() -> dict:
    """Generate LTC wallet via BlockCypher."""
    try:
        url = "https://api.blockcypher.com/v1/ltc/main/addrs"
        res = requests.post(url, params={"token": BLOCKCYPHER_TOKEN}, timeout=15)
        if res.status_code == 200:
            data = res.json()
            if "address" in data and "private" in data:
                return {
                    "address":     data["address"],
                    "private_key": data["private"],
                    "public_key":  data.get("public", ""),
                    "network":     "litecoin",
                }
        print(f"  LTC wallet API: {res.status_code} {res.text[:100]}")
    except Exception as e:
        print(f"  LTC wallet error: {e}")
    return _fallback_ltc_wallet()


def _fallback_ltc_wallet() -> dict:
    seed = secrets.token_hex(32)
    return {
        "address":     f"LTC_DEMO_{seed[:20]}",
        "private_key": seed,
        "public_key":  "",
        "network":     "litecoin",
    }


def get_ltc_balance(address: str) -> float:
    """Get LTC balance."""
    try:
        if not address or address.startswith("LTC_DEMO"):
            return 0.0
        url    = f"https://api.blockcypher.com/v1/ltc/main/addrs/{address}/balance"
        params = {"token": BLOCKCYPHER_TOKEN}
        res    = requests.get(url, params=params, timeout=10)
        if res.status_code == 200:
            data = res.json()
            return data.get("balance", 0) / 1e8
        return 0.0
    except Exception as e:
        print(f"  LTC balance error: {e}")
        return 0.0


def get_ltc_max_sendable(address: str) -> float:
    """Get max LTC sendable after fees and margin."""
    balance = get_ltc_balance(address)
    max_send = balance - LTC_FEE_RESERVE - SAFETY_MARGIN
    return round(max(0.0, max_send), 6)


def send_ltc(from_address: str, private_key_hex: str,
             to_address: str, amount_ltc: float) -> dict:
    """Send LTC using BlockCypher's simplified privkey flow."""
    try:
        if not from_address or from_address.startswith("LTC_DEMO"):
            return {"success": False, "error": "Invalid LTC wallet"}

        balance  = get_ltc_balance(from_address)
        max_send = get_ltc_max_sendable(from_address)

        if amount_ltc > max_send:
            return {
                "success": False,
                "error":   f"Insufficient balance. Max sendable: {max_send:.6f} LTC (balance: {balance:.6f}, fees reserved: {LTC_FEE_RESERVE} LTC)"
            }

        amount_satoshi = int(amount_ltc * 1e8)

        # Single-call approach: BlockCypher signs using provided private key
        url     = "https://api.blockcypher.com/v1/ltc/main/txs/new"
        payload = {
            "inputs":  [{"addresses": [from_address]}],
            "outputs": [{"addresses": [to_address], "value": amount_satoshi}],
        }
        res = requests.post(url, json=payload,
                            params={"token": BLOCKCYPHER_TOKEN}, timeout=15)

        if not res.text.strip():
            return {"success": False, "error": "Empty response creating transaction"}

        tx = res.json()
        if "errors" in tx:
            return {"success": False, "error": str(tx["errors"])}
        if "error" in tx:
            return {"success": False, "error": tx["error"]}

        tosign = tx.get("tosign", [])
        if not tosign:
            return {"success": False, "error": "No inputs to sign — check wallet has confirmed UTXOs"}

        # Sign each tosign hash using ecdsa with the private key
        import ecdsa
        from ecdsa.util import sigencode_der_canonize

        sk = ecdsa.SigningKey.from_string(
            bytes.fromhex(private_key_hex), curve=ecdsa.SECP256k1
        )
        vk = sk.get_verifying_key()

        # Compressed pubkey
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        pubkey_compressed = (prefix + x.to_bytes(32, 'big')).hex()

        signatures = []
        pubkeys    = []
        for ts in tosign:
            msg_hash = bytes.fromhex(ts)
            sig = sk.sign_digest(msg_hash, sigencode=sigencode_der_canonize)
            signatures.append(sig.hex())
            pubkeys.append(pubkey_compressed)

        tx["signatures"] = signatures
        tx["pubkeys"]    = pubkeys

        send_url = "https://api.blockcypher.com/v1/ltc/main/txs/send"
        send_res = requests.post(send_url, json=tx,
                                 params={"token": BLOCKCYPHER_TOKEN}, timeout=15)

        if not send_res.text.strip():
            return {"success": False, "error": "Empty response broadcasting transaction"}

        sent = send_res.json()
        if "errors" in sent:
            return {"success": False, "error": str(sent["errors"])}
        if "error" in sent:
            return {"success": False, "error": sent["error"]}

        return {
            "success":  True,
            "tx_hash":  sent.get("tx", {}).get("hash", sent.get("hash", "pending")),
            "amount":   amount_ltc,
            "currency": "LTC",
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Tron ─────────────────────────────────────────────────────────────────

def generate_trx_wallet() -> dict:
    """Generate TRX wallet."""
    try:
        key = TronPrivateKey.random()
        return {
            "address":     key.public_key.to_base58check_address(),
            "private_key": key.hex(),
            "network":     "tron",
        }
    except Exception as e:
        print(f"  TRX wallet error: {e}")
        seed = secrets.token_hex(32)
        return {
            "address":     f"T{seed[:33]}",
            "private_key": seed,
            "network":     "tron",
        }


def get_trx_balance(address: str) -> float:
    """Get TRX balance."""
    try:
        if not address or len(address) < 10:
            return 0.0
        url     = f"https://api.trongrid.io/v1/accounts/{address}"
        headers = {"TRON-PRO-API-KEY": TRONGRID_API_KEY}
        res     = requests.get(url, headers=headers, timeout=10)
        if res.status_code == 200:
            data     = res.json()
            accounts = data.get("data", [])
            if accounts:
                return accounts[0].get("balance", 0) / 1e6
        return 0.0
    except Exception as e:
        print(f"  TRX balance error: {e}")
        return 0.0


def get_trx_max_sendable(address: str) -> float:
    """Get max TRX sendable after fees."""
    balance  = get_trx_balance(address)
    max_send = balance - TRX_FEE_RESERVE - SAFETY_MARGIN
    return round(max(0.0, max_send), 4)


def send_trx(private_key_hex: str, to_address: str, amount_trx: float) -> dict:
    """Send TRX on mainnet."""
    try:
        key          = TronPrivateKey(bytes.fromhex(private_key_hex))
        from_address = key.public_key.to_base58check_address()
        max_send     = get_trx_max_sendable(from_address)

        if amount_trx > max_send:
            balance = get_trx_balance(from_address)
            return {
                "success": False,
                "error":   f"Insufficient balance. Max sendable: {max_send:.4f} TRX (balance: {balance:.4f}, fees reserved: {TRX_FEE_RESERVE} TRX)"
            }

        client     = Tron(network="mainnet")
        amount_sun = int(amount_trx * 1e6)

        txn = (
            client.trx.transfer(from_address, to_address, amount_sun)
            .memo("PQ Transfer")
            .build()
            .sign(key)
        )
        result = txn.broadcast().wait()

        return {
            "success":  True,
            "tx_hash":  result.get("id", "pending"),
            "amount":   amount_trx,
            "currency": "TRX",
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Prices ────────────────────────────────────────────────────────────────

_price_cache = {"data": None, "timestamp": 0}
_CACHE_TTL = 60  # seconds

def get_crypto_prices() -> dict:
    """Get live prices from CoinGecko with short server-side cache + retry."""
    now = time.time()

    if _price_cache["data"] and (now - _price_cache["timestamp"] < _CACHE_TTL):
        return _price_cache["data"]

    for attempt in range(2):
        try:
            url    = "https://api.coingecko.com/api/v3/simple/price"
            params = {"ids": "litecoin,tron", "vs_currencies": "inr,usd"}
            res    = requests.get(url, params=params, timeout=6,
                                  headers={"Accept": "application/json"})
            if res.status_code == 200 and res.text.strip():
                data    = res.json()
                ltc_inr = data.get("litecoin", {}).get("inr", 0)
                if ltc_inr > 0:
                    result = {
                        "LTC": {
                            "inr": data.get("litecoin", {}).get("inr", 0),
                            "usd": data.get("litecoin", {}).get("usd", 0),
                        },
                        "TRX": {
                            "inr": data.get("tron", {}).get("inr", 0),
                            "usd": data.get("tron", {}).get("usd", 0),
                        },
                    }
                    _price_cache["data"]      = result
                    _price_cache["timestamp"] = now
                    return result
        except Exception as e:
            print(f"  Price fetch attempt {attempt+1} failed: {e}")

    # Serve last known good cache even if stale, rather than a fixed fallback
    if _price_cache["data"]:
        print("  Using last cached prices (API unavailable)")
        return _price_cache["data"]

    print("  Using fallback prices (no cache available yet)")
    return {
        "LTC": {"inr": 7500, "usd": 89},
        "TRX": {"inr": 25,   "usd": 0.30},
    }