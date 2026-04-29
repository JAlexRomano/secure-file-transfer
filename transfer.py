import argparse
import getpass
import hmac as hmac_module
import os
import socket
import struct
import sys
import tempfile
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hmac, hashes
from cryptography.exceptions import InvalidSignature
from crypto import derive_keys, CHUNK_SIZE, IV_SIZE, SALT_SIZE, HMAC_SIZE

# ── Constants ─────────────────────────────────────────────────────────────────
DEFAULT_PORT    = 5555
DEFAULT_HOST    = "0.0.0.0"
BACKLOG         = 1             # Only accept one connection at a time
STATUS_OK       = b"\x00"
STATUS_ERROR    = b"\x01"

# ── Helpers ───────────────────────────────────────────────────────────────────
def recvall(sock: socket.socket, length: int) -> bytes:
    buf = b""
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise ConnectionError( # Raises ConnectionError if the connection closes early
                f"Connection closed early — expected {length} bytes, got {len(buf)}"
            )
        buf += chunk
    return buf


def fmt_size(size_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def fmt_speed(bytes_count: int, elapsed: float) -> str:
    if elapsed <= 0:
        return "N/A"
    mbps = bytes_count / elapsed / (1024 * 1024)
    return f"{mbps:.2f} MB/s" # Human-readable throughput


def verbose_print(message: str, verbose: bool) -> None:
    if verbose:
        print(f"    {message}")

# ── Send ──────────────────────────────────────────────────────────────────────
def send_file(
    host: str,
    port: int,
    input_path: str,
    password: str,
    verbose: bool = False,
) -> None:
    if not os.path.isfile(input_path): # Error checking
        print(f"[✗] File not found: {input_path}")
        sys.exit(1)

    file_size = os.path.getsize(input_path)
    filename  = os.path.basename(input_path).encode("utf-8")

    if len(filename) > 65535: # Checks for valid length of file
        print("[✗] Filename too long (max 65535 bytes)")
        sys.exit(1)

    # Derive keys
    enc_key, mac_key, salt = derive_keys(password)
    iv = os.urandom(IV_SIZE)

    verbose_print(f"File:     {input_path} ({fmt_size(file_size)})", verbose)
    verbose_print(f"Host:     {host}:{port}", verbose)
    verbose_print(f"Salt:     {salt.hex()}", verbose)
    verbose_print(f"IV:       {iv.hex()}", verbose)

    print(f"[~] Connecting to {host}:{port}...")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port)) # Connects to receiver
    except ConnectionRefusedError:
        print(f"[✗] Connection refused — is the receiver listening on {host}:{port}?")
        sys.exit(1)
    except OSError as e:
        print(f"[✗] Connection failed: {e}")
        sys.exit(1)

    print(f"[✓] Connected.")

    try:
        sock.sendall(struct.pack(">H", len(filename)))
        sock.sendall(filename) # 1. Sends filename length + filename

        sock.sendall(struct.pack(">Q", file_size)) # 2. Send file size

        sock.sendall(salt) # 3. Sends salt + IV
        sock.sendall(iv)

        padder    = padding.PKCS7(algorithms.AES.block_size).padder()
        cipher    = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        encryptor = cipher.encryptor() # 4. Streams encrypted chunks with incremental HMAC
        h         = hmac.HMAC(mac_key, hashes.SHA256())

        bytes_sent = 0 # Tracks bytes and time info for verbose print
        start      = time.perf_counter()

        print(f"[~] Sending {fmt_size(file_size)}...")

        with open(input_path, "rb") as infile:
            while True:
                chunk = infile.read(CHUNK_SIZE)
                if not chunk:
                    padded_final    = padder.finalize() # Finalize padding + encryption
                    encrypted_final = encryptor.update(padded_final) + encryptor.finalize()
                    if encrypted_final:
                        h.update(encrypted_final)
                        sock.sendall(encrypted_final)
                    break

                padded_chunk = padder.update(chunk)
                if padded_chunk:
                    encrypted_chunk = encryptor.update(padded_chunk)
                    if encrypted_chunk:
                        h.update(encrypted_chunk)
                        sock.sendall(encrypted_chunk)

                bytes_sent += len(chunk)
                if verbose:
                    pct = (bytes_sent / file_size * 100) if file_size > 0 else 100
                    print(f"\r    Progress: {pct:.1f}%", end="", flush=True)

        if verbose:
            print()  # newline after progress

        mac_tag = h.finalize()
        sock.sendall(mac_tag) # 5. Sends final HMAC

        elapsed = time.perf_counter() - start

        status = recvall(sock, 1)
        if status == STATUS_OK: # 6. Waits for receiver acknowledgement
            print(f"[✓] Transfer complete — receiver verified successfully.")
            if verbose:
                print(f"    Elapsed:  {elapsed:.3f}s")
                print(f"    Speed:    {fmt_speed(file_size, elapsed)}")
        else:
            print("[✗] Receiver reported an error — file may not have been saved.")
            sys.exit(1)

    except (BrokenPipeError, ConnectionResetError):
        print("[✗] Connection lost during transfer.")
        sys.exit(1)
    finally:
        sock.close()

if __name__=="__main__":
    print('Hello, world!')