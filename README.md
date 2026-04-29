# cipherport

A Python command-line tool for secure local encryption and encrypted file transfer over a network. Uses AES-256-CBC for encryption and HMAC-SHA256 for authentication.

---

## Features

- AES-256-CBC encryption with PKCS7 padding
- HMAC-SHA256 authentication (Encrypt-then-MAC)
- PBKDF2-HMAC-SHA256 key derivation (600,000 iterations)
- Unique salt and IV generated per file
- Two independent keys derived per operation (encryption + authentication)
- Chunked streaming for arbitrarily large files
- Local encrypt/decrypt via `cli.py`
- Live streaming encrypted transfer over raw sockets via `transfer.py`
- Temp file protection — received files only written on successful HMAC verification

---

## Requirements

- Python 3.10+
- [cryptography](https://pypi.org/project/cryptography/)

Install dependencies:

```bash
pip install cryptography
```

---

## Project Structure

```
cipherport/
├── crypto.py       # AES-256-CBC + HMAC core logic
├── cli.py          # Local file encryption/decryption
├── transfer.py     # Streaming network file transfer
└── README.md
```

---

## Usage

### Local Encryption (`cli.py`)

Encrypt a file — output saved as `<filename>.enc`:

```bash
python cli.py encrypt report.pdf
```

Decrypt a file — `.enc` extension is stripped from output:

```bash
python cli.py decrypt report.pdf.enc
```

With verbose output (file sizes, timing, throughput):

```bash
python cli.py encrypt report.pdf --verbose
python cli.py decrypt report.pdf.enc --verbose
```

Password is always prompted interactively. Encryption requires confirmation to prevent typo-lockout.

---

### Network Transfer (`transfer.py`)

The receiver must be listening before the sender connects.

**Receiver:**

```bash
python transfer.py receive --port 5555
```

**Sender:**

```bash
python transfer.py send secret.pdf --host 192.168.1.10 --port 5555
```

Both sides are prompted for a password. The passwords must match — the receiver verifies the HMAC before writing the final file.

With verbose output:

```bash
python transfer.py receive --port 5555 --verbose
python transfer.py send secret.pdf --host 192.168.1.10 --port 5555 --verbose
```

Save received files to a specific directory:

```bash
python transfer.py receive --port 5555 --output-dir ~/received
```

Test locally using two terminals with `127.0.0.1`:

```bash
# Terminal 1
python transfer.py receive --port 5555 --verbose

# Terminal 2
python transfer.py send secret.pdf --host 127.0.0.1 --port 5555 --verbose
```

---

## File Formats

### Local (`cli.py`)

```
[ salt (16 bytes) ][ iv (16 bytes) ][ hmac (32 bytes) ][ ciphertext ]
```

HMAC is stored in the header since the full ciphertext is available before writing.

### Network stream (`transfer.py`)

```
[ filename length (2 bytes) ][ filename ][ file size (8 bytes) ]
[ salt (16 bytes) ][ iv (16 bytes) ][ encrypted chunks ][ hmac (32 bytes) ]
```

HMAC trails the stream since it cannot be computed until all chunks are sent.

---

## Security Notes

- Passwords are never passed as command-line arguments — always prompted via `getpass`
- Each encryption generates a fresh random salt and IV — the same file encrypted twice produces different ciphertext
- Two keys are derived per operation — one for AES encryption, one for HMAC — preventing key reuse across operations
- HMAC is verified before any decryption begins (local) or before the output file is finalized (network)
- Received files are written to a temp file and only renamed on successful HMAC verification — a failed or interrupted transfer leaves no partial output
- Passwords are never stored or transmitted

---

## Networking

By default the receiver listens on `0.0.0.0` (all interfaces) and port `5555`.

**Same network (LAN):** works out of the box. Use the receiver's local IP address.

**Different networks (WAN):** requires one of:
- Port forwarding on the receiver's router (forward port `5555` to the receiver's machine)
- Both users on the same VPN (e.g. Tailscale, WireGuard)

The tool itself requires no changes for either scenario — only the `--host` address changes.

---

## License

MIT
