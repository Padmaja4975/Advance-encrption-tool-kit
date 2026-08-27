# Advanced Encryption Toolkit (AES-256)

A command-line file encryption/decryption tool using AES-256-CBC with password-based key derivation.

## Features
- AES-256-CBC file encryption and decryption
- Secure key derivation using PBKDF2-HMAC-SHA256 (100,000 iterations)
- Random salt and IV generated per encryption for security
- Hidden password input with confirmation on encryption

## Tech Stack
- Python 3
- Library: cryptography

## How to Run
1. Install dependency: `pip install cryptography`
2. Run `python encryption_tool.py`
3. Choose to encrypt or decrypt a file, and enter the password when prompted

## Project Context
Built during the Cybersecurity & Ethical Hacking internship at CodTech IT Solutions.
