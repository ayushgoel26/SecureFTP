import os
import hashlib


def hash_xor(data, key, previous_data):
    byte_stream = hashlib.sha256(key + previous_data).digest()
    output_stream = bytes([a ^ b for a, b in zip(byte_stream, data)])
    return output_stream


class FileTransfer:
    def __init__(self, directory_folder):
        jf = None
        self.path = os.path.dirname(os.path.dirname(__file__)) + directory_folder
        self.chunk_size = 32

    # List files in local directory
    def local_files(self):
        l_files = os.listdir(self.path)  # gets content of folder
        print("File Directory: " + self.path)
        if not l_files:
            print("The Directory is empty")
            return
        # prints only files in the folder
        for file in l_files:
            file_path = os.path.join(self.path, file)
            if os.path.isfile(file_path):
                print("\t" + file)
        return l_files

    def upload_file(self, conn, file_name, integrity_key, encryption_key, initialization_value):
        file_path = self.path + "/" + file_name
        integrity_hash = hashlib.sha256()
        integrity_hash.update(integrity_key)
        if os.path.isfile(file_path):
            print("\t file exists")
            with open(file_path, 'rb') as file:
                chunk = '-'
                previous_chunk = initialization_value
                while chunk[-3:] != b'EOF':
                    chunk = file.read(self.chunk_size)
                    integrity_hash.update(chunk)
                    if len(chunk) < self.chunk_size:
                        chunk += b'EOF'
                    encrypted_chunk = hash_xor(chunk, encryption_key, previous_chunk)
                    previous_chunk = encrypted_chunk
                    conn.send(encrypted_chunk)
        return integrity_hash.digest()

    def download_file(self, conn, file_name, integrity_key, encryption_key, initialization_value):
        file_path = self.path + "/" + file_name
        integrity_hash = hashlib.sha256()
        integrity_hash.update(integrity_key)
        # add code to check if file already exists -> ask client if wants to rewrite or give file new name
        with open(file_path, 'wb') as file:
            chunk = '-'
            previous_chunk = initialization_value
            while chunk:
                encrypted_file_chunk = conn.recv(self.chunk_size)
                chunk = hash_xor(encrypted_file_chunk, encryption_key, previous_chunk)
                previous_chunk = encrypted_file_chunk
                if chunk[-3:] == b'EOF':
                    chunk = chunk[:-3]
                    integrity_hash.update(chunk)
                    file.write(chunk)
                    break
                integrity_hash.update(chunk)
                file.write(chunk)
        return integrity_hash.digest()
