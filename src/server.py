import socket
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from src.key_generation import KeyGenerator
from src.handler import FileHandler
from src.config import HOST, PORT, SECRET_FOLDER, SERVER_FOLDER, SERVER_PVT_KEY, ROOT_FOLDER, ACK, \
    FAILED_INTEGRITY_CHECK, SUCCESS_INTEGRITY_CHECK


class Server:
    """
    Server Class
    """
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
        """
        pass authentication
        :param conn: connection object after the server connects to the client
        """
        authentication_payload_encrypted = conn.recv(4096)  # receive the authentication payload from client
        # pick its private key
        private_key = RSA.import_key(open(os.path.dirname(os.path.dirname(__file__)) + SERVER_FOLDER + SECRET_FOLDER +
                                          SERVER_PVT_KEY, 'r').read())
        cipher = PKCS1_OAEP.new(key=private_key)  # loading its public key to use for encryption
        authentication_payload = cipher.decrypt(authentication_payload_encrypted)  # decrypt the authentication payload
        # get the session key and the nonce from the payload
        nonce, session_key = authentication_payload.decode('utf-8').split(',')
        conn.send(nonce.encode('utf-8'))  # send the nonce to the client
        self.key_generation.generate_keys(session_key)  # generate the other keys from the session key

    def list_contents(self, conn):
        """
        list the files in the server directory and send it to the client
        :param conn: connection object after the server connects to the client
        """
        print("The client requested a list of remote directories")
        local_files = self.file_transfer.local_files()  # function to find file names ,print them and pass a list for client
        local_files = str(local_files).encode('utf-8')  # make the list into string and encode it
        conn.send(local_files)  # send the list of files to the client

    def put(self, conn, filename):
        """
        receive file from the client that it wants to upload
        :param conn: connection object after the server connects to the client
        :param filename: name of the file being uploaded
        """
        print('Client requesting to upload file. Sending Acknowledgement')
        conn.send(ACK)  # send an acknowledgment for sending the file
        # call method to receive the file and get the integrity value

        integrity_value = self.file_transfer.download_file(conn, filename,
                                                           self.key_generation.integrity_verification_key,
                                                           self.key_generation.file_encryption_key,
                                                           self.key_generation.initialization_value)
        if integrity_value:
            print("File has been uploaded")
            conn.send(ACK)   # send an acknowledge for receiving the file
            integrity_value_received = conn.recv(4096)  # receive the integrity value from the client after he receives file
            # check if integrity values are same and send an acknowledgement
            if integrity_value == integrity_value_received:
                print("Integrity verification successful")
                conn.send(SUCCESS_INTEGRITY_CHECK)
            else:
                print("Integrity Verification failed")
                conn.send(FAILED_INTEGRITY_CHECK)

    def get(self, conn, filename):
        """
        upload the file the server requested for
        :param conn: connection object after the server connects to the client
        :param filename: name of the file being uploaded
        """
        print('Client requested to download a file. Sending file')
        # function to upload the file and get the integrity value
        integrity_value = self.file_transfer.upload_file(conn, filename,
                                                         self.key_generation.integrity_verification_key,
                                                         self.key_generation.file_encryption_key,
                                                         self.key_generation.initialization_value)
        if integrity_value:
            confirmation = conn.recv(4096).decode('utf-8')  # receive the confirmation from the client
            if confirmation == ACK.decode("utf-8"):
                conn.send(integrity_value)  # send client the integrity value
                confirmation = conn.recv(4096).decode('utf-8')  # receive acknowledgement about the integrity of the file
                print(confirmation)
        else:
            conn.send(b'File does not exist')
