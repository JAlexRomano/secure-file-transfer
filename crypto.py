import os
import hmac as hmac_module
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hmac, hashes
from cryptography.exceptions import InvalidSignature

# ── Constants ────────────────────────────────────────────────────────────────

SALT_SIZE       = 16        # bytes
IV_SIZE         = 16        # bytes — AES block size
HMAC_SIZE       = 32        # bytes — SHA-256 output
HEADER_SIZE     = SALT_SIZE + IV_SIZE + HMAC_SIZE   # 64 bytes total
KDF_ITERATIONS  = 600_000   # OWASP 2023 recommendation for PBKDF2-SHA256
KEY_SIZE        = 32        # bytes — AES-256
CHUNK_SIZE      = 64 * 1024 # 64 KB read chunks


# ── Key Derivation ────────────────────────────────────────────────────────────
"""
Derive two 32-byte keys from a password using PBKDF2-HMAC-SHA256.

Returns:
    enc_key (32 bytes): AES-256 encryption key
    mac_key (32 bytes): HMAC-SHA256 authentication key
    salt    (16 bytes): Salt used for derivation (generated if not provided)
"""
def derive_keys(password: str, salt: bytes = None) -> tuple[bytes, bytes, bytes]:
    if salt is None:
        salt = os.urandom(SALT_SIZE)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE * 2,    # 64 bytes: 32 enc + 32 mac
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key_material = kdf.derive(password.encode("utf-8"))
    enc_key = key_material[:KEY_SIZE]
    mac_key = key_material[KEY_SIZE:]
    return enc_key, mac_key, salt