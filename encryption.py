from pwinput import pwinput
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from exceptions import *
import time
import os
import threading
import time
from contextlib import contextmanager
from pwinput import pwinput
from config import *

# Security constants
TIME_CONSTANT = int(time.time() * 1000)
SALT_RANDOM = os.urandom(16)

class SecureString:
    def __init__(self):
        self.encrypted = None
        self.temp = None
        self._clear_timer = None
        self._access_lock = threading.Lock()

    def set(self, string):
        """Securely store a string"""
        with self._access_lock:
            if self.encrypted:
                self.clear()
            self.temp = string.encode('utf-8')
            self.encrypted = mem_encryptor.encrypt_mem(self.temp)
            shred_mem(bytearray(self.temp))
            self.temp = None

    @contextmanager
    def temporary_access(self, max_exposure_sec=5):
        """Context manager for secure temporary access"""
        with self._access_lock:
            if not self.encrypted:
                yield ""
                return

            # Decrypt and make available
            decrypted = mem_encryptor.decrypt_mem(self.encrypted)
            self.temp = decrypted.decode('utf-8')

            # Set up auto-clear timer
            self._setup_clear_timer(max_exposure_sec)

            try:
                yield self.temp
            finally:
                self._clear_temp()

    def _setup_clear_timer(self, max_exposure_sec):
        """Ensure temp data is cleared after timeout"""
        if self._clear_timer:
            self._clear_timer.cancel()

        def clear_callback():
            with self._access_lock:
                self._clear_temp()

        self._clear_timer = threading.Timer(
            max_exposure_sec,
            clear_callback
        )
        self._clear_timer.start()

    def _clear_temp(self):
        """Securely clear temporary storage"""
        if self.temp:
            # Convert to mutable bytearray and shred
            temp_bytes = bytearray(self.temp.encode('utf-8'))
            shred_mem(temp_bytes)
            self.temp = None

        if self._clear_timer:
            self._clear_timer.cancel()
            self._clear_timer = None

    def clear(self):
        """Completely clear all data"""
        with self._access_lock:
            self._clear_temp()
            if self.encrypted:
                shred_mem(bytearray(self.encrypted))
                self.encrypted = None

    def __del__(self):
        self.clear()

class MemoryEncryptor:
    def __init__(self):
        self.backend = default_backend()
        self.key = self._derive_key()

    def _derive_key(self) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt=SALT_RANDOM,
            iterations=pim*1000,
            backend=self.backend
        )
        return kdf.derive(TIME_CONSTANT.to_bytes(32, 'big'))

    def encrypt_mem(self, data: bytes) -> bytes:
        iv = os.urandom(16)
        padder = padding.PKCS7(256).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        return iv + encryptor.update(padded_data) + encryptor.finalize()

    def decrypt_mem(self, encrypted_data: bytes) -> bytes:
        if len(encrypted_data) < 32:
            return b''
        iv = encrypted_data[:16]
        ct = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(256).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

class EncryptionSystem:
    def __init__(self, master_key: SecureString):
        """Initialize with a SecureString instead of raw string"""
        self._master_key = master_key  # Store SecureString directly
        self.backend = default_backend()
        self._key_cache = {}
        self._cache_lock = threading.Lock()
        self.pim = pim

    def _derive_local_key(self, salt: bytes) -> bytes:
        """Securely derive key with memory protection"""
        salt_key = salt.hex()

        # Check cache first
        with self._cache_lock:
            if salt_key in self._key_cache:
                return self._key_cache[salt_key]

        # Get key material securely
        with self._master_key.temporary_access() as key_str:
            kdf = PBKDF2HMAC(
                algorithm=SHA256(),
                length=32,
                salt=salt,
                iterations=self.pim*1000,
                backend=self.backend
            )
            key = kdf.derive(key_str.encode('utf-8'))

        # Cache the key
        with self._cache_lock:
            self._key_cache[salt_key] = key

        return key

    def encrypt(self, plaintext: bytes) -> bytes:
        """Memory-safe encryption"""
        salt = os.urandom(16)
        iv = os.urandom(16)

        try:
            local_key = self._derive_local_key(salt)

            # Use temporary buffer
            padded_data = bytearray()
            padder = padding.PKCS7(256).padder()
            padded_data.extend(padder.update(plaintext))
            padded_data.extend(padder.finalize())
            del padder, plaintext

            cipher = Cipher(algorithms.AES(local_key), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(padded_data) + encryptor.finalize()

            return salt + iv + encrypted
        finally:
            # Securely wipe temporary buffers
            if 'padded_data' in locals():
                shred_mem(padded_data)

    def decrypt(self, combined_data: bytes) -> bytes:
        """Memory-safe decryption"""
        if len(combined_data) < 32:
            raise EncryptionError("Invalid ciphertext length")

        salt = combined_data[:16]
        iv = combined_data[16:32]
        ct = combined_data[32:]

        try:
            local_key = self._derive_local_key(salt)

            cipher = Cipher(algorithms.AES(local_key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()

            # Use temporary buffer
            padded_plaintext = bytearray()
            padded_plaintext.extend(decryptor.update(ct))
            padded_plaintext.extend(decryptor.finalize())

            unpadder = padding.PKCS7(256).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            return plaintext
        finally:
            # Securely wipe temporary buffers
            if 'padded_plaintext' in locals():
                shred_mem(padded_plaintext)

    def clear_cache(self):
        """Securely clear key cache"""
        with self._cache_lock:
            for key in self._key_cache.values():
                if isinstance(key, (bytes, bytearray)):
                    shred_mem(bytearray(key))
            self._key_cache.clear()

    def __del__(self):
        self.clear_cache()

def shred_mem(bytearray_obj):
    if not isinstance(bytearray_obj, (bytes, bytearray)):
        return
    random_data = [os.urandom(len(bytearray_obj)) for _ in range(MEMORY_SHRED_PASSES)]
    for i in range(MEMORY_SHRED_PASSES):
        bytearray_obj[:] = random_data[i] if i < MEMORY_SHRED_PASSES-1 else b'\x00'*len(bytearray_obj)
    del random_data

def secure_pwinput(prompt="", mask="*"):
    """Secure password input that returns a SecureString object"""
    password = pwinput(prompt, mask)
    secure_str = SecureString()
    secure_str.set(password)
    # Overwrite the password in memory
    pw_bytes = bytearray(password.encode('utf-8'))
    shred_mem(pw_bytes)
    del password
    return secure_str

mem_encryptor = MemoryEncryptor()
