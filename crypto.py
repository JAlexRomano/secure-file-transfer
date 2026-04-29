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
# ── Decryption ────────────────────────────────────────────────────────────────
    """
    Decrypt and verify a file encrypted by encrypt_file().

    Steps:
      1. Read and parse header: salt | IV | HMAC
      2. Re-derive keys from password + salt
      3. Verify HMAC over (IV + ciphertext) — BEFORE decrypting
      4. Decrypt ciphertext in chunks
      5. Strip PKCS7 padding from final chunk

    Args:
        input_path:  Path to the encrypted file.
        output_path: Path to write the decrypted plaintext.
        password:    Password used during encryption.

    Raises:
        InvalidSignature: If the HMAC check fails (file tampered or wrong password).
        ValueError:       If the file is too short to contain a valid header.
    """
def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    with open(input_path, "rb") as infile:
        header = infile.read(HEADER_SIZE)

        if len(header) < HEADER_SIZE:
            raise ValueError(
                f"File too short to be valid (got {len(header)} bytes, need {HEADER_SIZE})"
            )

        salt = header[:SALT_SIZE]
        iv = header[SALT_SIZE:SALT_SIZE + IV_SIZE]
        stored_mac = header[SALT_SIZE + IV_SIZE:]

        # Read ciphertext for HMAC verification
        ciphertext = infile.read()

    # Re-derive keys
    enc_key, mac_key, _ = derive_keys(password, salt)

    # Verify HMAC FIRST — constant-time comparison prevents timing attacks
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(iv + ciphertext)
    try:
        h.verify(stored_mac)
    except InvalidSignature:
        raise InvalidSignature(
            "HMAC verification failed — file may be corrupted, tampered with, or the password is wrong."
        )

    # Decrypt in chunks
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

    with open(output_path, "wb") as outfile:
        offset = 0
        while offset < len(ciphertext):
            chunk = ciphertext[offset:offset + CHUNK_SIZE]
            offset += CHUNK_SIZE
            decrypted_chunk = decryptor.update(chunk)
            unpadded = unpadder.update(decrypted_chunk)
            if unpadded:
                outfile.write(unpadded)

        # Finalize decryption and unpadding
        final = unpadder.update(decryptor.finalize()) + unpadder.finalize()
        if final:
            outfile.write(final)

# ── For testing purposes ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import tempfile

    print("Running self-test...")

    original = b"Hello, secure world! " * 5000  # ~100 KB of test data
    password = "test-password-123"

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(original)
        plain_path = f.name

    enc_path   = plain_path + ".enc"
    dec_path   = plain_path + ".dec"

    encrypt_file(plain_path, enc_path, password)
    decrypt_file(enc_path, dec_path, password)

    with open(dec_path, "rb") as f:
        recovered = f.read()

    assert recovered == original, "Self-test FAILED: decrypted content does not match original!"
    print("[✓] Self-test passed — plaintext recovered correctly")

    # Tamper test
    print("\nTesting tamper detection...")
    with open(enc_path, "r+b") as f:
        f.seek(HEADER_SIZE + 10)
        f.write(b"\xff\xff")    # corrupt 2 bytes of ciphertext

    try:
        decrypt_file(enc_path, dec_path, password)
        print("[✗] Tamper test FAILED — should have raised InvalidSignature!")
    except InvalidSignature as e:
        print(f"[✓] Tamper detected correctly: {e}")

    # Cleanup
    for p in (plain_path, enc_path, dec_path):
        os.unlink(p)