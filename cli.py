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
