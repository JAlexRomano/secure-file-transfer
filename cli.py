import argparse
import getpass
import os
import sys
import time
from cryptography.exceptions import InvalidSignature
from crypto import decrypt_file, encrypt_file, HEADER_SIZE

# ── Output Path Helpers ───────────────────────────────────────────────────────
def make_encrypt_output(input_path: str) -> str:
    return input_path + ".enc" # Append .enc to the input path

def make_decrypt_output(input_path: str) -> str:
    if input_path.endswith(".enc"):
        return input_path[:-4] # Strips .enc from the input path
    return input_path + ".dec" # Falls back to <input>.dec if the file doesn't end in .enc

# ── Password Prompt ───────────────────────────────────────────────────────────
def prompt_password_encrypt() -> str: # Prompt for a password twice and verify they match
    while True: # Loops until the user enters matching non-empty passwords
        password = getpass.getpass("Password: ")
        if not password:
            print("[!] Password cannot be empty. Try again.")
            continue
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("[!] Passwords do not match. Try again.")
            continue
        return password


def prompt_password_decrypt() -> str: #Prompts the user for a password once and returns it
    password = getpass.getpass("Password: ")
    if not password:
        print("[!] Password cannot be empty.")
        sys.exit(1)
    return password

# ── Verbose Helpers ───────────────────────────────────────────────────────────
def verbose_print(message: str, verbose: bool) -> None:
    if verbose: # Only print if verbose mode is enabled
        print(f"    {message}")

def print_verbose_stats(
    input_path: str,
    output_path: str,
    elapsed: float,
    verbose: bool,
) -> None: # Prints file size and timing info in verbose mode
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


# Gets called by print_verbose_stats to make file size human-readable
def _fmt_size(size_bytes: int) -> str: # 
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"