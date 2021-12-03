import socket
import random
from src.key_generation import KeyGeneration
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from src.file_transfer import FileTransfer
from src.config import HOST, PORT, SECRET_FOLDER, CLIENT_FOLDER, ROOT_FOLDER, SERVER_PUBLIC_KEY
import os


class Client:
    """
    Client Class
    """
    def __init__(self, host, port):
        # Socket object is created with the address family in argument
        # Socket type.AF_INET -> Internet address family for IPv4
        # SOCK_STREAM is the socket type for TCP
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((host, port))  # connect to server
        # Used to associate the socket with a specific network interface. Arguments passed to bind
        self.file_transfer = FileTransfer(CLIENT_FOLDER + ROOT_FOLDER)
        self.key_generator = KeyGeneration()  # object for a class to generate keys
        self.key_generator.session_key_generation()  # generating session key and other keys

    def authenticate(self):
        """
        User to authenticate the server
        """
        # check if the server is authentic
        # https://www.peterspython.com/en/blog/using-python-s-pyopenssl-to-verify-ssl-certificates-downloaded-from-a-host
        # picking servers public key to validate the server
        server_public_key = RSA.import_key(open(os.path.dirname(os.path.dirname(__file__)) + CLIENT_FOLDER +
                                                SECRET_FOLDER + SERVER_PUBLIC_KEY, 'r').read())
        nonce = str(random.randint(100000, 1000000))   # pick random nonce to authenticate server
        authentication_payload = nonce + "," + str(self.key_generator.session_key) # making authentication payload
        cipher = PKCS1_OAEP.new(server_public_key)  # loading the servers public key to use for encryption
        # encrypting the authentication payload using the server public key
        authentication_payload_encrypted = cipher.encrypt(str(authentication_payload).encode('utf-8'))
        # send the payload to the server
        self.connection.send(authentication_payload_encrypted)
        # Receiving nonce from the server to verify if the server is who is says he is
        nonce_received = self.connection.recv(4096).decode('utf-8')
        # check if the nonce received is same as the nonce we sent
        if nonce == nonce_received:
            print("Server authenticated successfully")
            # generate other keys as the server is authenticated
            self.key_generator.generate_keys(self.key_generator.session_key)
        else:
            # exit as the server failed authentication
            print("Server failed authentication")
            exit(1)

    def list_content(self):
        """
        User to list the content of the local directory of the client
        """
        self.file_transfer.local_files()  # function to find file names and print them

    def list_remote_content(self, command):
        """
        Get the list of files in the servers directory
        :param command: the command passed by the client
        """
        self.connection.sendall(command.encode('utf-8'))    # send the command to the server
        remote_file_list = self.connection.recv(4096).decode('utf-8')   # receive the list of files from the server
        remote_file_list = eval(remote_file_list)
        # if list is empty print so else print the file names
        if not remote_file_list:
            print('Remote directory has no files')
        else:
            print('The files in the remote directory are')
            for file in remote_file_list:
                print("\t" + file)

    def put(self, command, filename):
        """
        command to upload the file to the server
        :param command: command passed by the client
        :param filename: the name of the file to be uploaded
        """
        self.connection.sendall(command.encode('utf-8'))  # sending command to the server
        confirmation = self.connection.recv(4096).decode('utf-8')   # server sends an acknowledgment for uploading
        # if confirmation is an acknowledgement then send the file to server
        if confirmation == 'Ack':
            print("\t Acknowledgement received")
            print("\t Preparing file to send")
            # function to send file to the server and get bath the integrity value
            integrity_value = self.file_transfer.upload_file(self.connection, filename,
                                                             self.key_generator.integrity_verification_key,
                                                             self.key_generator.file_encryption_key,
                                                             self.key_generator.initialization_value)
            # receive a confirmation from the server on receiving the file
            confirmation = self.connection.recv(4096).decode('utf-8')
            if confirmation == 'Ack':
                # send the integrity value to the server to check if the file was corrupted or not
                self.connection.send(integrity_value)
                # receive conformation about the file
                confirmation = self.connection.recv(4096).decode('utf-8')
                print(confirmation)

    def get(self, command, filename):
        """
        command to download the file from server
        :param command: command passed by  the client
        :param filename: name of the file to be downloaded
        """
        self.connection.sendall(command.encode('utf-8'))  # send the command to the server
        # download the file sent by the server to the client
        integrity_value = self.file_transfer.download_file(self.connection, filename,
                                                           self.key_generator.integrity_verification_key,
                                                           self.key_generator.file_encryption_key,
                                                           self.key_generator.initialization_value)
        print('File has been downloaded')
        self.connection.send(b'Ack')  # send an acknowledgement after receiving the file
        print('Doing Integrity Check')
        integrity_value_received = self.connection.recv(4096)  # receive the integrity value calculated by the server
        if integrity_value == integrity_value_received:  # compare the integrity values and send acknowledgement message
            print("Integrity verification successful")
            self.connection.send(b'The file passed integrity verification. The file was not corrupted')
        else:
            print("Integrity Verification failed")
            self.connection.send(b'The file did not pass integrity verification. The file was corrupted')
