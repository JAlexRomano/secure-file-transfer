import argparse
import getpass
import os
import sys
import time
from cryptography.exceptions import InvalidSignature
from crypto import decrypt_file, encrypt_file, HEADER_SIZE

# ── Output Path Helpers ───────────────────────────────────────────────────────
def make_encrypt_output(input_path: str) -> str:
    return input_path + ".enc"

def make_decrypt_output(input_path: str) -> str:
    if input_path.endswith(".enc"):
        return input_path[:-4]
    return input_path + ".dec"

# ── Password Prompt ───────────────────────────────────────────────────────────
def prompt_password_encrypt() -> str:
    while True:
        password = getpass.getpass("Password: ")
        if not password:
            print("[!] Password cannot be empty. Try again.")
            continue
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("[!] Passwords do not match. Try again.")
            continue
        return password


def prompt_password_decrypt() -> str:
    password = getpass.getpass("Password: ")
    if not password:
        print("[!] Password cannot be empty.")
        sys.exit(1)
    return password

# ── Verbose Helpers ───────────────────────────────────────────────────────────
def verbose_print(message: str, verbose: bool) -> None:
    if verbose:
        print(f"    {message}")

def print_verbose_stats(
    input_path: str,
    output_path: str,
    elapsed: float,
    verbose: bool,
) -> None:
    if not verbose:
        return

    input_size  = os.path.getsize(input_path)
    output_size = os.path.getsize(output_path)

    print(f"    Input:   {input_path} ({_fmt_size(input_size)})")
    print(f"    Output:  {output_path} ({_fmt_size(output_size)})")
    print(f"    Elapsed: {elapsed:.3f}s")
    if elapsed > 0:
        throughput = input_size / elapsed / (1024 * 1024)
        print(f"    Speed:   {throughput:.2f} MB/s")


def _fmt_size(size_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"

# ── Subcommand Handlers ───────────────────────────────────────────────────────
def handle_encrypt(args: argparse.Namespace) -> None:
    input_path  = args.input
    output_path = make_encrypt_output(input_path)

    # Pre-flight checks
    if not os.path.isfile(input_path):
        print(f"[✗] File not found: {input_path}")
        sys.exit(1)

    if os.path.exists(output_path):
        print(f"[!] Output file already exists: {output_path}")
        overwrite = input("    Overwrite? [y/N]: ").strip().lower()
        if overwrite != "y":
            print("[−] Aborted.")
            sys.exit(0)

    verbose_print(f"Input:  {input_path} ({_fmt_size(os.path.getsize(input_path))})", args.verbose)
    verbose_print(f"Output: {output_path}", args.verbose)

    password = prompt_password_encrypt()

    print(f"[~] Encrypting...")
    start = time.perf_counter()

    try:
        encrypt_file(input_path, output_path, password)
    except FileNotFoundError as e:
        print(f"[✗] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[✗] Encryption failed: {e}")
        sys.exit(1)

    elapsed = time.perf_counter() - start
    print(f"[✓] Encrypted → {output_path}")
    print_verbose_stats(input_path, output_path, elapsed, args.verbose)


def handle_decrypt(args: argparse.Namespace) -> None:
    input_path  = args.input
    output_path = make_decrypt_output(input_path)

    # Pre-flight checks
    if not os.path.isfile(input_path):
        print(f"[✗] File not found: {input_path}")
        sys.exit(1)

    file_size = os.path.getsize(input_path)
    if file_size < HEADER_SIZE:
        print(f"[✗] File is too small to be a valid encrypted file ({_fmt_size(file_size)})")
        sys.exit(1)

    if os.path.exists(output_path):
        print(f"[!] Output file already exists: {output_path}")
        overwrite = input("    Overwrite? [y/N]: ").strip().lower()
        if overwrite != "y":
            print("[−] Aborted.")
            sys.exit(0)

    verbose_print(f"Input:  {input_path} ({_fmt_size(file_size)})", args.verbose)
    verbose_print(f"Output: {output_path}", args.verbose)

    password = prompt_password_decrypt()

    print(f"[~] Decrypting...")
    start = time.perf_counter()

    try:
        decrypt_file(input_path, output_path, password)
    except InvalidSignature:
        print("[✗] Authentication failed — wrong password or file has been tampered with.")
        if os.path.exists(output_path):  # remove partial output on auth failure
            os.remove(output_path)
        sys.exit(1)
    except ValueError as e:
        print(f"[✗] Invalid file format: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"[✗] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[✗] Decryption failed: {e}")
        sys.exit(1)

    elapsed = time.perf_counter() - start
    print(f"[✓] Decrypted → {output_path}")
    print_verbose_stats(input_path, output_path, elapsed, args.verbose)

# ── Argument Parser ───────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    class SecureTransferParser(argparse.ArgumentParser):
        def error(self, message):
            self.print_help()
            print(f"\n[✗] {message}")
            sys.exit(1)

    parser = SecureTransferParser(
        prog="cli.py",
        description="AES-256-CBC encrypted file transfer tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        examples:
        python cli.py encrypt report.pdf
        python cli.py decrypt report.pdf.enc
        python cli.py encrypt report.pdf --verbose
        python cli.py decrypt report.pdf.enc --verbose
            """,
    )

    parser.add_argument(
        "--version", action="version", version="%(prog)s 1.0.0"
    )

    subparsers = parser.add_subparsers(dest="command", metavar="command")
    subparsers.required = True

    # encrypt subcommand
    enc_parser = subparsers.add_parser(
        "encrypt",
        help="encrypt a file  (output: <file>.enc)",
        description="Encrypt a file using AES-256-CBC + HMAC-SHA256.",
    )
    enc_parser.add_argument("input", help="path to the plaintext file")
    enc_parser.add_argument(
        "--verbose", "-v", action="store_true", help="show file sizes, timing, and throughput"
    )
    enc_parser.set_defaults(func=handle_encrypt)

    # decrypt subcommand
    dec_parser = subparsers.add_parser(
        "decrypt",
        help="decrypt a file  (output: <file> with .enc stripped)",
        description="Decrypt and verify a file encrypted by this tool.",
    )
    dec_parser.add_argument("input", help="path to the encrypted .enc file")
    dec_parser.add_argument(
        "--verbose", "-v", action="store_true", help="show file sizes, timing, and throughput"
    )
    dec_parser.set_defaults(func=handle_decrypt)

    return parser

# ── Main ───────────────────────────────────────────────────────────────
def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
