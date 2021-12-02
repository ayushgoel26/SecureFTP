import socket
import os
import pickle
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from src.key_generation import KeyGeneration
from src.fileTansfer import FileTransfer
from src.config import HOST, PORT, CONFIDENTIAL_FILES_FOLDER


def get_connection(host, port):
    # Socket object is created with the address family in argument
    # Socket type.AF_INET -> Internet address family for IPv4
    # SOCK_STREAM is the socket type for TCP
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Used to associate the socket with a specific network interface. Arguments passed to bind
    connection.bind((host, port))
    return connection


class Socket:
    def __init__(self):
        pass


class Client:
    def __init__(self):
        pass

    def start(self):
        pass


class Server:
    def __init__(self):
        pass

    def start(self):
        pass


print("SFTP Server side")
connect = get_connection(HOST, PORT)
# Used to associate the socket with a specific network interface. Arguments passed to bind
connect.listen(1)  # depend on the address family we choose
print("Listening at %s:%d" % (HOST, PORT))
print("Waiting for connection")

conn, address = connect.accept()
print('Connection received from client ', address)

authenticationPayloadEncrypted = conn.recv(4096)

private_key = RSA.import_key(open(os.path.dirname(os.path.dirname(__file__)) + '/' + CONFIDENTIAL_FILES_FOLDER +
                                  'server-key.pem', 'r').read())

# pick servers private key
cipher = PKCS1_OAEP.new(key=private_key)
authenticationPayload = cipher.decrypt(authenticationPayloadEncrypted)

nonce, session_key = authenticationPayload.decode('utf-8').split(',')
conn.send(nonce.encode('utf-8'))
key_generation = KeyGeneration()
key_generation.generate_keys(session_key)

command = None
while command != 'exit':
    file_transfer = FileTransfer('/server_files')
    client_command = conn.recv(4096).decode('utf-8').split(" ")
    command = client_command[0]
    if client_command[0] == "lsr":
        print("The client requested a list of remote directories")
        local_files = file_transfer.local_files()
        local_files = str(local_files).encode('utf-8')
        conn.send(local_files)
    elif client_command[0] == "upload":
        print('Client requesting to upload file. Sending Acknowledgement')
        conn.send(b"Ack")
        integrity_value = file_transfer.download_file(conn, client_command[1], key_generation.integrity_verification_key,
                                                      key_generation.file_encryption_key, key_generation.initialization_value)
        print("File has been uploaded")
        conn.send(b"Ack")
        integrity_value_received = conn.recv(4096)
        if integrity_value == integrity_value_received:
            print("Integrity verification successful")
            conn.send(b'The file passed integrity verification. The file was not corrupted')
        else:
            print("Integrity Verification failed")
            conn.send(b'The file did not pass integrity verification. The file was corrupted')
    elif client_command[0] == "download":
        print('Client requested to download a file. Sending file')
        integrity_value = file_transfer.upload_file(conn, client_command[1], key_generation.integrity_verification_key,
                                                    key_generation.file_encryption_key, key_generation.initialization_value)
        confirmation = conn.recv(4096).decode('utf-8')
        if confirmation == "Ack":
            conn.send(integrity_value)
            confirmation = conn.recv(4096).decode('utf-8')
            print(confirmation)
    elif client_command[0] == "exit":
        print("Client is leaving connection")
        break


