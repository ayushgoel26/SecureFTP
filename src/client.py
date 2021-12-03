import socket
import random
from src.key_generation import KeyGeneration
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from src.file_transfer import FileTransfer
from src.config import HOST, PORT, SECRET_FOLDER, CLIENT_FOLDER, ROOT_FOLDER, SERVER_PUBLIC_KEY
import os


class Client:
    def __init__(self, host, port):
        # Socket object is created with the address family in argument
        # Socket type.AF_INET -> Internet address family for IPv4
        # SOCK_STREAM is the socket type for TCP
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((host, port))  # connect to server
        # Used to associate the socket with a specific network interface. Arguments passed to bind
        self.file_transfer = FileTransfer(CLIENT_FOLDER + ROOT_FOLDER)
        self.key_generator = KeyGeneration()
        self.key_generator.session_key_generation()  # generating session key and other keys

    def authenticate(self):
        # check if the server is authentic
        # https://www.peterspython.com/en/blog/using-python-s-pyopenssl-to-verify-ssl-certificates-downloaded-from-a-host
        # pick servers public key
        server_public_key = RSA.import_key(open(os.path.dirname(os.path.dirname(__file__)) + CLIENT_FOLDER +
                                                SECRET_FOLDER + SERVER_PUBLIC_KEY, 'r').read())
        nonce = str(random.randint(100000, 1000000))   # pick random nonce to authenticate server
        authentication_payload = nonce + "," + str(self.key_generator.session_key)
        cipher = PKCS1_OAEP.new(server_public_key)
        authentication_payload_encrypted = cipher.encrypt(str(authentication_payload).encode('utf-8'))
        self.connection.send(authentication_payload_encrypted)
        nonce_received = self.connection.recv(4096).decode('utf-8')
        if nonce == nonce_received:
            print("Server authenticated successfully")
            self.key_generator.generate_keys(self.key_generator.session_key)
        else:
            print("Server failed authentication")
            exit(1)

    def list_content(self):
        self.file_transfer.local_files()

    def list_remote_content(self, command):
        self.connection.sendall(command.encode('utf-8'))
        remote_file_list = self.connection.recv(4096).decode('utf-8')
        remote_file_list = eval(remote_file_list)
        if not remote_file_list:
            print('Remote directory has no files')
        else:
            print('The files in the remote directory are')
            for file in remote_file_list:
                print("\t" + file)

    def put(self, command, filename):
        self.connection.sendall(command.encode('utf-8'))
        confirmation = self.connection.recv(4096).decode('utf-8')
        if confirmation == 'Ack':
            print("\t Acknowledgement received")
            print("\t Preparing file to send")
            integrity_value = self.file_transfer.upload_file(self.connection, filename,
                                                             self.key_generator.integrity_verification_key,
                                                             self.key_generator.file_encryption_key,
                                                             self.key_generator.initialization_value)
            confirmation = self.connection.recv(4096).decode('utf-8')
            if confirmation == 'Ack':
                self.connection.send(integrity_value)
                confirmation = self.connection.recv(4096).decode('utf-8')
                print(confirmation)

    def get(self, command, filename):
        self.connection.sendall(command.encode('utf-8'))
        integrity_value = self.file_transfer.download_file(self.connection, filename,
                                                           self.key_generator.integrity_verification_key,
                                                           self.key_generator.file_encryption_key,
                                                           self.key_generator.initialization_value)
        print('File has been downloaded')
        self.connection.send(b'Ack')
        print('Doing Integrity Check')
        integrity_value_received = self.connection.recv(4096)
        if integrity_value == integrity_value_received:
            print("Integrity verification successful")
            self.connection.send(b'The file passed integrity verification. The file was not corrupted')
        else:
            print("Integrity Verification failed")
            self.connection.send(b'The file did not pass integrity verification. The file was corrupted')
