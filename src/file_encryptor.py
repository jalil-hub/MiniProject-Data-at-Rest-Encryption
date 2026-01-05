import os
import time
import getpass
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

backend = default_backend()

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    return kdf.derive(password.encode())

def encrypt_file(filename, password):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)

    with open(filename, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    start = time.time()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    end = time.time()

    with open(filename + ".enc", 'wb') as f:
        f.write(salt + iv + encrypted_data)

    print(f"Encryption time: {end - start:.6f} seconds")

def decrypt_file(filename, password):
    with open(filename, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    start = time.time()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    end = time.time()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    with open(filename.replace(".enc", ".dec"), 'wb') as f:
        f.write(data)

    print(f"Decryption time: {end - start:.6f} seconds")

if __name__ == "__main__":
    choice = input("Encrypt or Decrypt (e/d): ").lower()
    file_path = input("Enter file path: ")
    password = getpass.getpass("Enter password: ")

    if choice == 'e':
        encrypt_file(file_path, password)
    elif choice == 'd':
        decrypt_file(file_path, password)
