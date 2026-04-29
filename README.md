# secure-file-transfer
AES-256 encrypted file transfer tool written in Python

crypto.py — AES-256-CBC + HMAC-SHA256 encrypted file transfer utility.
File format (binary layout):
  [ salt (16) ][ iv (16) ][ hmac (32) ][ ciphertext (variable) ]
Design:
  - Encrypt-then-MAC over IV + ciphertext
  - Two keys derived from one password via PBKDF2-HMAC-SHA256 (64 bytes total)
  - Chunked streaming to handle arbitrarily large files
  - HMAC verified before any decryption begins


cli.py — Command-line interface for the AES-256-CBC secure file transfer tool.
Usage:
    python cli.py encrypt <input>              # output: <input>.enc
    python cli.py decrypt <input>.enc          # output: <input> (stripped .enc)
    python cli.py encrypt <input> --verbose
    python cli.py decrypt <input>.enc --verbose
Password is always prompted interactively — never passed as an argument.
Encrypt prompts twice for confirmation to prevent typo-lockout.


transfer.py — Streaming AES-256-CBC + HMAC-SHA256 secure file transfer over raw sockets.
Usage:
    python transfer.py recieve --port <input>
    python transfer send <input> --host <input> --port <input>
Example inputs:
    python transfer.py receive --port 5555 --verbose
    python transfer.py send secret.pdf --host 127.0.0.1 --port 5555 --verbose
Stream format (in order):
  [ filename length (2 bytes, big-endian uint16) ]
  [ filename        (variable)                   ]
  [ file size       (8 bytes, big-endian uint64)  ]
  [ salt            (16 bytes)                    ]
  [ iv              (16 bytes)                    ]
  [ encrypted chunks (variable)                  ]
  [ hmac            (32 bytes)                    ]
After transfer, receiver sends a 1-byte status back to the sender:
  0x00 = success
  0x01 = error (HMAC failure or other)
Design notes:
  - HMAC is computed incrementally over all ciphertext chunks
  - HMAC is sent at the END of the stream (can't pre-compute with streaming)
  - Receiver writes to a temp file; renames to final path only on HMAC success
  - Both sender and receiver prompt for password interactively via getpass
