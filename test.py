import socket, argparse, os, sys, time
from config import *
from pwinput import pwinput
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from hashlib import sha3_512, md5
import netifaces


class EncryptionSystem:
    def __init__(self, master_key: str):
        if not master_key:
            raise ValueError("Master key cannot be empty.")
        self.master_key = master_key.encode()
        self.backend = default_backend()

    def derive_local_key(self, salt: bytes) -> bytes:
        """Derive a local key from the master key using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(self.master_key)

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypted Text format:
        
        [SALT] + [IV] + [ENCRYPTED TEXT]
        """
        salt = os.urandom(16)
        iv = os.urandom(16)
        local_key = self.derive_local_key(salt)

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(algorithms.AES(local_key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        return salt + iv + encrypted

    def decrypt(self, combined_data: bytes) -> bytes:
        salt = combined_data[:16]
        iv = combined_data[16:32]
        ct = combined_data[32:]

        local_key = self.derive_local_key(salt)

        cipher = Cipher(algorithms.AES(local_key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ct) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext

b = b"\x54\x68\x69\x73\x20\x61\x70\x70\x20\x69\x73\x20\x64\x65\x76\x65\x6c\x6f\x70\x65\x64\x20\x62\x79\x20\x6d\x61\x78\x39\x38\x33\x36\x40\x67\x69\x74\x68\x75\x62\x2e\x20\x54\x68\x61\x6e\x6b\x20\x79\x6f\x75\x20\x66\x6f\x72\x20\x75\x73\x69\x6e\x67\x20\x74\x68\x69\x73\x20\x61\x70\x70\x20\x61\x6e\x64\x20\x63\x6f\x6e\x74\x72\x69\x62\x75\x74\x69\x6e\x67\x20\x74\x6f\x20\x6f\x70\x65\x6e\x20\x73\x6f\x75\x72\x63\x65\x20\x70\x72\x6f\x6a\x65\x63\x74\x73\x2e\x20\x46\x6f\x6c\x6c\x6f\x77\x20\x6d\x65\x20\x6f\x6e\x20\x67\x69\x74\x68\x75\x62\x3a\x20\x68\x74\x74\x70\x73\x3a\x2f\x2f\x67\x69\x74\x68\x75\x62\x2e\x63\x6f\x6d\x2f\x6d\x61\x78\x39\x38\x33\x36"
Encryptor = EncryptionSystem("This-is-a-good-example-of-a-strong-password")
encrypted = Encryptor.encrypt(b)
print("Encrypted-Text=" + encrypted.hex())
decrypted = Encryptor.decrypt(encrypted)
print("Decrypted-Text=" + str(decrypted))

