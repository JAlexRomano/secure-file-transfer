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
