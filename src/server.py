import socket
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from src.key_generation import KeyGenerator
from src.handler import FileHandler
from src.config import HOST, PORT, SECRET_FOLDER, SERVER_FOLDER, SERVER_PVT_KEY, ROOT_FOLDER, ACK, \
    FAILED_INTEGRITY_CHECK, SUCCESS_INTEGRITY_CHECK


class Server:
    def __init__(self, host, port):
        print("SFTP Server side")
        # Socket object is created with the address family in argument
        # Socket type.AF_INET -> Internet address family for IPv4
        # SOCK_STREAM is the socket type for TCP
        self.key_generation = KeyGenerator()
        self.file_transfer = FileHandler(SERVER_FOLDER + ROOT_FOLDER)
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Used to associate the socket with a specific network interface. Arguments passed to bind
        self.connection.bind((host, port))
        self.connection.listen(1)  # depend on the address family we choose
        print("Listening at %s:%d" % (HOST, PORT))
        print("Waiting for connection")

    def authenticate(self, conn):
        authentication_payload_encrypted = conn.recv(4096)
        private_key = RSA.import_key(open(os.path.dirname(os.path.dirname(__file__)) + SERVER_FOLDER + SECRET_FOLDER +
                                          SERVER_PVT_KEY, 'r').read())
        # pick servers private key
        cipher = PKCS1_OAEP.new(key=private_key)
        authentication_payload = cipher.decrypt(authentication_payload_encrypted)
        nonce, session_key = authentication_payload.decode('utf-8').split(',')
        conn.send(nonce.encode('utf-8'))
        self.key_generation.generate_keys(session_key)

    def list_contents(self, conn):
        print("The client requested a list of remote directories")
        local_files = self.file_transfer.local_files()
        local_files = str(local_files).encode('utf-8')
        conn.send(local_files)

    def put(self, conn, filename):
        print('Client requesting to upload file. Sending Acknowledgement')
        conn.send(ACK)
        integrity_value = self.file_transfer.download_file(conn, filename,
                                                           self.key_generation.integrity_verification_key,
                                                           self.key_generation.file_encryption_key,
                                                           self.key_generation.initialization_value)
        print("File has been uploaded")
        conn.send(ACK)
        integrity_value_received = conn.recv(4096)
        if integrity_value == integrity_value_received:
            print("Integrity verification successful")
            conn.send(SUCCESS_INTEGRITY_CHECK)
        else:
            print("Integrity Verification failed")
            conn.send(FAILED_INTEGRITY_CHECK)

    def get(self, conn, filename):
        print('Client requested to download a file. Sending file')
        integrity_value = self.file_transfer.upload_file(conn, filename,
                                                         self.key_generation.integrity_verification_key,
                                                         self.key_generation.file_encryption_key,
                                                         self.key_generation.initialization_value)
        confirmation = conn.recv(4096).decode('utf-8')
        if confirmation == ACK.decode("utf-8"):
            conn.send(integrity_value)
            confirmation = conn.recv(4096).decode('utf-8')
            print(confirmation)
