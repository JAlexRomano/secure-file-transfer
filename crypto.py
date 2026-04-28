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
# ── Encryption ────────────────────────────────────────────────────────────────
    """
    Encrypt a file using AES-256-CBC and authenticate with HMAC-SHA256.

    Steps:
      1. Derive enc_key + mac_key from password + fresh salt
      2. Generate a random IV
      3. Encrypt plaintext in chunks with PKCS7 padding
      4. Compute HMAC-SHA256 over (IV + ciphertext)
      5. Write: salt | IV | HMAC | ciphertext

    Args:
        input_path:  Path to the plaintext file to encrypt.
        output_path: Path to write the encrypted output file.
        password:    Password used for key derivation.
    """
def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    enc_key, mac_key, salt = derive_keys(password)
    iv = os.urandom(IV_SIZE)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Pass 1: encrypt and collect ciphertext chunks
    ciphertext_chunks = []
    with open(input_path, "rb") as infile:
        while True:
            chunk = infile.read(CHUNK_SIZE)
            if not chunk:
                # Finalize padding on EOF
                padded_final = padder.finalize()
                ciphertext_chunks.append(encryptor.update(padded_final) + encryptor.finalize())
                break
            padded_chunk = padder.update(chunk)
            if padded_chunk:
                ciphertext_chunks.append(encryptor.update(padded_chunk))

    ciphertext = b"".join(ciphertext_chunks)

    # Pass 2: compute HMAC over IV + ciphertext (Encrypt-then-MAC)
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(iv + ciphertext)
    mac_tag = h.finalize()

    # Write header then ciphertext
    with open(output_path, "wb") as outfile:
        outfile.write(salt)     # 16 bytes
        outfile.write(iv)       # 16 bytes
        outfile.write(mac_tag)  # 32 bytes
        outfile.write(ciphertext)

    print(f"[✓] Encrypted: {input_path} → {output_path}")
    print(f"    Salt: {salt.hex()}  IV: {iv.hex()}")