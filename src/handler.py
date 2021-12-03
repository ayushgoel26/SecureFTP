import os
import hashlib
from termcolor import colored
from src.config import EOF, INCORRECT_FILE


def hash_xor(data, key, previous_data):
    byte_stream = hashlib.sha256(key + previous_data).digest()
    output_stream = bytes([a ^ b for a, b in zip(byte_stream, data)])
    return output_stream


class FileHandler:
    def __init__(self, directory_name):
        self.path = os.path.dirname(os.path.dirname(__file__)) + directory_name
        self.chunk_size = 32

    # List files in local directory
    def local_files(self):
        l_files = os.listdir(self.path)  # gets content of folder
        print("File Directory: " + self.path)
        if not l_files:
            print(colored("The Directory is empty", 'red'))
            return
        # prints only files in the folder
        for file in l_files:
            file_path = os.path.join(self.path, file)
            if os.path.isfile(file_path):
                print("\t -- " + file)
        return l_files

    def upload_file(self, conn, file_name, integrity_key, encryption_key, initialization_value):
        file_path = self.path + file_name
        integrity_hash = hashlib.sha256()
        integrity_hash.update(integrity_key)
        if os.path.isfile(file_path):
            print(colored("File found successfully", 'green'))
            with open(file_path, 'rb') as file:
                chunk = '-'
                previous_chunk = initialization_value
                while chunk[-3:] != EOF:
                    chunk = file.read(self.chunk_size)
                    integrity_hash.update(chunk)
                    if len(chunk) < self.chunk_size:
                        chunk += EOF
                    encrypted_chunk = hash_xor(chunk, encryption_key, previous_chunk)
                    previous_chunk = encrypted_chunk
                    conn.send(encrypted_chunk)
            return integrity_hash.digest()
        else:
            print(colored("File Does not exist", 'red'))
            return None

    def download_file(self, conn, file_name, integrity_key, encryption_key, initialization_value):
        file_path = self.path + file_name
        integrity_hash = hashlib.sha256()
        integrity_hash.update(integrity_key)
        encrypted_file_chunk = conn.recv(self.chunk_size)
        if encrypted_file_chunk == INCORRECT_FILE:
            print(colored("File does not exist", 'red'))
            return None
        with open(file_path, 'wb') as file:
            # chunk = '-'
            previous_chunk = initialization_value
            while True:
                chunk = hash_xor(encrypted_file_chunk, encryption_key, previous_chunk)
                previous_chunk = encrypted_file_chunk
                if chunk[-3:] == EOF:
                    chunk = chunk[:-3]
                    integrity_hash.update(chunk)
                    file.write(chunk)
                    break
                integrity_hash.update(chunk)
                file.write(chunk)
                encrypted_file_chunk = conn.recv(self.chunk_size)
                if not chunk:
                    break
        return integrity_hash.digest()
