import hashlib
import random


class KeyGenerator:
    def __init__(self):
        self.session_key = None
        self.file_encryption_key = None
        self.integrity_verification_key = None
        self.initialization_value = None

    def session_key_generation(self):
        self.session_key = hashlib.sha256(str(random.randint(100000, 1000000)).encode()).hexdigest()

    def generate_keys(self, session_key):
        temporary_key = "0x" + session_key
        self.file_encryption_key = hex(int(temporary_key, 16) + 0x1).lstrip("0x").encode('utf-8')
        self.integrity_verification_key = hex(int(temporary_key, 16) + 0x2).lstrip("0x").encode('utf-8')
        self.initialization_value = hex(int(temporary_key, 16) - 0x1).lstrip("0x").encode('utf-8')

