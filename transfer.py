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

if __name__=="__main__":
    print('Placeholder')