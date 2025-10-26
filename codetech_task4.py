#!/usr/bin/env python3
import os
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend

# --- Key derivation (PBKDF2) to produce AES-256 key from password + salt ---
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# --- Encrypt a file with AES-256-CBC ---
def encrypt_file(filepath: str, password: str) -> None:
    if not os.path.isfile(filepath):
        print(f"[!] File not found: {filepath}")
        return

    with open(filepath, "rb") as f:
        plaintext = f.read()

    salt = os.urandom(16)  # store with file
    iv = os.urandom(16)
    key = derive_key(password, salt)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    out_data = salt + iv + ciphertext
    out_path = filepath + ".enc"

    with open(out_path, "wb") as f:
        f.write(out_data)

    print(f"[+] Encrypted -> {out_path}")

# --- Decrypt a file previously encrypted by this tool ---
def decrypt_file(enc_path: str, password: str) -> None:
    if not os.path.isfile(enc_path):
        print(f"[!] File not found: {enc_path}")
        return

    with open(enc_path, "rb") as f:
        data = f.read()

    if len(data) < 32:
        print("[!] Invalid or corrupted encrypted file.")
        return

    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    try:
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        print("[!] Decryption failed. Wrong password or corrupted file.")
        return

    # produce a sensible output filename
    if enc_path.lower().endswith(".enc"):
        out_path = enc_path[:-4] + "_decrypted"
    else:
        out_path = enc_path + "_decrypted"

    # preserve original file extension if possible (optional)
    # We simply write bytes out; user can rename if necessary.
    with open(out_path, "wb") as f:
        f.write(plaintext)

    print(f"[+] Decrypted -> {out_path}")

# --- Simple CLI with password confirmation for encryption ---
def main():
    while True:
        print("\n=== ADVANCED ENCRYPTION TOOL (AES-256) ===")
        print("1) Encrypt a file")
        print("2) Decrypt a file")
        print("3) Exit")
        choice = input("Choose (1/2/3): ").strip()

        if choice == "1":
            filepath = input("Enter path of file to encrypt: ").strip()
            # password + confirmation
            password = getpass("Enter password (will be used to derive AES key): ")
            confirm = getpass("Confirm password: ")
            if password != confirm:
                print("[!] Passwords do not match. Aborting encryption.")
                continue
            if password == "":
                print("[!] Empty password not allowed. Use a strong passphrase.")
                continue
            encrypt_file(filepath, password)

        elif choice == "2":
            enc_path = input("Enter .enc file path to decrypt: ").strip()
            password = getpass("Enter password used during encryption: ")
            if password == "":
                print("[!] Empty password not allowed.")
                continue
            decrypt_file(enc_path, password)

        elif choice == "3":
            print("Exiting.")
            break

        else:
            print("[!] Invalid choice. Please enter 1, 2 or 3.")

if __name__ == "__main__":
    main() 