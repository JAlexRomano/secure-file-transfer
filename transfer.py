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

# ── Receive ───────────────────────────────────────────────────────────────────

def receive_file(
    host: str,
    port: int,
    output_dir: str,
    password: str,
    verbose: bool = False,
) -> None:
    os.makedirs(output_dir, exist_ok=True)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((host, port))
    except OSError as e:
        print(f"[✗] Could not bind to {host}:{port} — {e}")
        sys.exit(1)

    server.listen(BACKLOG)
    print(f"[~] Listening on {host}:{port}... (Ctrl+C to stop)")

    try:
        conn, addr = server.accept()
    except KeyboardInterrupt:
        print("\n[−] Stopped.")
        server.close()
        sys.exit(0)

    print(f"[✓] Connection from {addr[0]}:{addr[1]}")

    temp_path   = None
    final_path  = None

    try:
        fname_len   = struct.unpack(">H", recvall(conn, 2))[0]
        filename    = recvall(conn, fname_len).decode("utf-8")
        final_path  = os.path.join(output_dir, filename) # 1. Receives filename

        verbose_print(f"Filename: {filename}", verbose)

        # 2. Receive file size
        file_size = struct.unpack(">Q", recvall(conn, 8))[0] # 2. Receives file size
        verbose_print(f"Size:     {fmt_size(file_size)}", verbose)

        salt = recvall(conn, SALT_SIZE) # 3. Receives salt + IV
        iv   = recvall(conn, IV_SIZE)
        verbose_print(f"Salt:     {salt.hex()}", verbose)
        verbose_print(f"IV:       {iv.hex()}", verbose)

        enc_key, mac_key, _ = derive_keys(password, salt) # 4. Re-derive keys

        cipher    = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        unpadder  = padding.PKCS7(algorithms.AES.block_size).unpadder()
        h         = hmac.HMAC(mac_key, hashes.SHA256())

        # 5. Receive + decrypt chunks into temp file
        # Total encrypted size = file_size padded to AES block boundary
        # We receive until HMAC_SIZE bytes remain
        # Buffer a sliding window to separate ciphertext from trailing HMAC

        temp_fd, temp_path = tempfile.mkstemp(dir=output_dir, prefix=".tmp_recv_")

        bytes_received  = 0
        start           = time.perf_counter()
        block_size      = algorithms.AES.block_size // 8  # 16 bytes
        padded_size     = ((file_size // block_size) + 1) * block_size
        remaining       = padded_size # Pads file_size up to next AES block boundary for expected ciphertext size

        print(f"[~] Receiving {fmt_size(file_size)}...")

        with os.fdopen(temp_fd, "wb") as tmpfile:
            buf = b"" # Uses a buffer to cleanly separate ciphertext from the trailing HMAC
            while remaining > 0:
                to_read = min(CHUNK_SIZE, remaining)
                chunk   = recvall(conn, to_read)
                remaining -= len(chunk)

                h.update(chunk)
                decrypted = decryptor.update(chunk)
                unpadded  = unpadder.update(decrypted)
                if unpadded:
                    tmpfile.write(unpadded)

                bytes_received += len(chunk)
                if verbose:
                    pct = (bytes_received / padded_size * 100)
                    print(f"\r    Progress: {min(pct, 100):.1f}%", end="", flush=True)


            final_decrypted = unpadder.update(decryptor.finalize()) + unpadder.finalize()
            if final_decrypted: # Finalizes decryption and unpads the file
                tmpfile.write(final_decrypted)

        if verbose:
            print()  # newline after progress

        received_mac = recvall(conn, HMAC_SIZE)
        elapsed      = time.perf_counter() - start

        try:
            h.verify(received_mac) # 6. Receive and verify HMAC
        except InvalidSignature:
            print("[✗] HMAC verification failed — file may be corrupted or tampered with.")
            conn.sendall(STATUS_ERROR)
            os.remove(temp_path)
            temp_path = None
            sys.exit(1)

        if os.path.exists(final_path):
            print(f"[!] Output file already exists: {final_path} — overwriting.")

        os.replace(temp_path, final_path) # 7. Rename temp → final output path on success
        temp_path = None

        conn.sendall(STATUS_OK)
        print(f"[✓] Received and verified → {final_path}")

        if verbose:
            print(f"    Elapsed:  {elapsed:.3f}s")
            print(f"    Speed:    {fmt_speed(file_size, elapsed)}")

    except (ConnectionError, struct.error) as e:
        print(f"[✗] Transfer error: {e}")
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        try:
            conn.sendall(STATUS_ERROR)
        except Exception:
            pass
        sys.exit(1)

    finally:
        conn.close()
        server.close()

# ── Argument Parser ───────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:

    class TransferParser(argparse.ArgumentParser):
        def error(self, message):
            self.print_help()
            print(f"\n[✗] {message}")
            sys.exit(1)

    parser = TransferParser(
        prog="transfer.py",
        description="Streaming AES-256-CBC encrypted file transfer tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
            examples:
            # Receiver listens first
            python transfer.py receive --port 5555

            # Sender connects and streams
            python transfer.py send secret.pdf --host 192.168.1.10 --port 5555

            # With verbose output
            python transfer.py send secret.pdf --host 192.168.1.10 --port 5555 --verbose
            python transfer.py receive --port 5555 --verbose

            # Save received file to a specific directory
            python transfer.py receive --port 5555 --output-dir ~/received
        """,
    )

    parser.add_argument("--version", action="version", version="%(prog)s 1.0.0")

    subparsers = parser.add_subparsers(dest="command", metavar="command")
    subparsers.required = True

    send_parser = subparsers.add_parser( # Sends subcommand
        "send",
        help="encrypt and stream a file to a receiver",
        description="Encrypt and stream a file to a waiting receiver.",
    )
    send_parser.add_argument("input", help="path to the file to send")
    send_parser.add_argument("--host", required=True, help="receiver's IP address or hostname")
    send_parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port to connect to (default: {DEFAULT_PORT})")
    send_parser.add_argument("--verbose", "-v", action="store_true", help="show progress, timing, and throughput")
    send_parser.set_defaults(func=handle_send)

    recv_parser = subparsers.add_parser( # Receives subcommand
        "receive",
        help="listen for and decrypt an incoming file",
        description="Listen for an incoming encrypted file and decrypt it on arrival.",
    )
    recv_parser.add_argument("--host", default=DEFAULT_HOST, help=f"interface to listen on (default: {DEFAULT_HOST})")
    recv_parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port to listen on (default: {DEFAULT_PORT})")
    recv_parser.add_argument("--output-dir", default=".", help="directory to save received files (default: current directory)")
    recv_parser.add_argument("--verbose", "-v", action="store_true", help="show progress, timing, and throughput")
    recv_parser.set_defaults(func=handle_receive)

    return parser

# ── Subcommand Handlers ───────────────────────────────────────────────────────
def handle_send(args: argparse.Namespace) -> None:
    password = getpass.getpass("Password: ")
    if not password:
        print("[!] Password cannot be empty.")
        sys.exit(1)
    send_file(args.host, args.port, args.input, password, args.verbose)


def handle_receive(args: argparse.Namespace) -> None:
    password = getpass.getpass("Password: ")
    if not password:
        print("[!] Password cannot be empty.")
        sys.exit(1)
    receive_file(args.host, args.port, args.output_dir, password, args.verbose)

# ── Main ───────────────────────────────────────────────────────────────
def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()