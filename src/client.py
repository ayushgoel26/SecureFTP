import socket
import random
import os
from termcolor import colored
import subprocess
from src.key_generation import KeyGenerator
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from src.handler import FileHandler
from src.config import SECRET_FOLDER, CLIENT_FOLDER, ROOT_FOLDER, SERVER_PUBLIC_KEY, \
    FAILED_INTEGRITY_CHECK, SUCCESS_INTEGRITY_CHECK, ACK, INCORRECT_FILE, CA_FOLDER, SERVER_FOLDER


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
        self.file_transfer = FileHandler(CLIENT_FOLDER + ROOT_FOLDER)
        self.key_generator = KeyGenerator()  # object for a class to generate keys
        self.key_generator.session_key_generation()  # generating session key and other keys

    def authenticate(self):
        """
        User to authenticate the server
        """
        verify = subprocess.check_output(['openssl', 'verify', '-CAfile', os.path.dirname(os.path.dirname(__file__)) +
                                          CA_FOLDER + '/ca.pem', os.path.dirname(os.path.dirname(__file__)) +
                                          SERVER_FOLDER + SECRET_FOLDER + '/server-cert.pem'])
        if verify == os.path.dirname(os.path.dirname(__file__)).encode('utf-8') + SERVER_FOLDER.encode('utf-8') + \
                SECRET_FOLDER.encode('utf-8') + b"/server-cert.pem: OK\n":
            print("Server Cert Verified")
        else:
            print("Error verifying server's certificate with certificate authority")
            exit(1)
        # picking servers public key to validate the server
        server_public_key = RSA.import_key(open(os.path.dirname(os.path.dirname(__file__)) + CLIENT_FOLDER +
                                                SECRET_FOLDER + SERVER_PUBLIC_KEY, 'r').read())
        nonce = str(random.randint(100000, 1000000))   # pick random nonce to authenticate server
        authentication_payload = nonce + "," + str(self.key_generator.session_key)  # making authentication payload
        cipher = PKCS1_OAEP.new(server_public_key)  # loading the servers public key to use for encryption
        # encrypting the authentication payload using the server public key
        authentication_payload_encrypted = cipher.encrypt(str(authentication_payload).encode('utf-8'))
        # send the payload to the server
        self.connection.send(authentication_payload_encrypted)
        # Receiving nonce from the server to verify if the server is who is says he is
        nonce_received = self.connection.recv(4096).decode('utf-8')
        # check if the nonce received is same as the nonce we sent
        if nonce == nonce_received:
            print(colored("Server authenticated successfully", 'green'))
            # generate other keys as the server is authenticated
            self.key_generator.generate_keys(self.key_generator.session_key)
        else:
            # exit as the server failed authentication
            print(colored("Server failed authentication", 'red'))
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
            print(colored('Remote root directory is empty', 'red'))
        else:
            print('The files in the remote directory are')
            for file in remote_file_list:
                print("\t -- " + file)

    def put(self, command):
        """
        command to upload the file to the server
        :param command: command passed by the client
        """
        self.connection.sendall(command.encode('utf-8'))  # sending command to the server
        confirmation = self.connection.recv(4096).decode('utf-8')   # server sends an acknowledgment for uploading
        # if confirmation is an acknowledgement then send the file to server
        if confirmation == ACK.decode("utf-8"):
            print(colored("Acknowledgement received", 'green'))
            print("Preparing file to send")
            # function to send file to the server and get bath the integrity value
            integrity_value = self.file_transfer.upload_file(self.connection, "/" + command.split(" ")[1],
                                                             self.key_generator.integrity_verification_key,
                                                             self.key_generator.file_encryption_key,
                                                             self.key_generator.initialization_value)
            if integrity_value:
                # receive a confirmation from the server on receiving the file
                confirmation = self.connection.recv(4096).decode('utf-8')
                # send the integrity value to the server to check if the file was corrupted or not
                if confirmation == ACK.decode("utf-8"):
                    self.connection.send(integrity_value)
                    # receive conformation about the file
                    confirmation = self.connection.recv(4096).decode('utf-8')
                    print(confirmation)
            else:
                self.connection.send(INCORRECT_FILE)

    def get(self, command):
        """
        command to download the file from server
        :param command: command passed by  the client
        """
        self.connection.sendall(command.encode('utf-8'))  # send the command to the server
        # download the file sent by the server to the client
        integrity_value = self.file_transfer.download_file(self.connection, "/" + command.split(" ")[1],
                                                           self.key_generator.integrity_verification_key,
                                                           self.key_generator.file_encryption_key,
                                                           self.key_generator.initialization_value)
        if integrity_value:
            print(colored('File has been downloaded', 'green'))
            self.connection.send(ACK)  # send an acknowledgement after receiving the file
            print('Doing Integrity Check')
            # receive the integrity value calculated by the server
            integrity_value_received = self.connection.recv(4096)
            # compare the integrity values and send acknowledgement message
            if integrity_value == integrity_value_received:
                print(colored("Integrity verification successful", 'green'))
                self.connection.send(SUCCESS_INTEGRITY_CHECK)
            else:
                print(colored("Integrity Verification failed", 'red'))
                self.connection.send(FAILED_INTEGRITY_CHECK)
