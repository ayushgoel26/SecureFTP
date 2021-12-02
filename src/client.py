import socket
import random
from src.key_generation import KeyGeneration
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from src.fileTansfer import FileTransfer
from src.config import HOST, PORT, CONFIDENTIAL_FILES_FOLDER
import os
import pickle

# Socket object is created with the address family in argument
# Socket type.AF_INET -> Internet address family for IPv4
# SOCK_STREAM is the socket type for TCP
conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn.connect((HOST, PORT))  # connect to server

nonce = str(random.randint(100000, 1000000))   # pick random nonce to authenticate server
key_generation = KeyGeneration()
key_generation.session_key_generation()   # generating session key and other keys

# check if the server is authentic
# https://www.peterspython.com/en/blog/using-python-s-pyopenssl-to-verify-ssl-certificates-downloaded-from-a-host
# pick servers public key
server_public_key = RSA.import_key(open(os.path.dirname(os.path.dirname(__file__)) + '/' + CONFIDENTIAL_FILES_FOLDER +
                                        'server-key-public.pem', 'r').read())

authenticationPayLoad = nonce + "," + str(key_generation.session_key)
cipher = PKCS1_OAEP.new(server_public_key)
authenticationPayLoadEncrypted = cipher.encrypt(str(authenticationPayLoad).encode('utf-8'))
conn.send(authenticationPayLoadEncrypted)
nonce_received = conn.recv(4096).decode('utf-8')
if nonce == nonce_received:
    print("Server authenticated successfully")
    key_generation.generate_keys(key_generation.session_key)
else:
    print("Server failed authentication")
    exit(1)

print("Type 'help' to get list of available command")
while True:
    file_transfer = FileTransfer("/client_files")
    command = input('command: ')
    command_split = command.split(" ")
    if command_split[0] == "help":
        print("\t help: provide the list of commands")
        print("\t lsl: provides the list of files in the client directory")
        print("\t lsr: proves the list of files in the server directory")
        print("\t upload <Filename> : Uploads the file")
        print("\t download <Filename> : Download the file")
        print("\t exit : exits the client server")
    elif command_split[0] == "lsl":
        file_transfer.local_files()
    elif command_split[0] == "lsr":
        conn.sendall(command.encode('utf-8'))
        remote_file_list = conn.recv(4096).decode('utf-8')
        remote_file_list = eval(remote_file_list)
        if not remote_file_list:
            print('Remote directory has no files')
        else:
            print('The files in the remote directory are')
            for file in remote_file_list:
                print("\t" + file)
    elif command_split[0] == 'upload':
        conn.sendall(command.encode('utf-8'))
        confirmation = conn.recv(4096).decode('utf-8')
        if confirmation == 'Ack':
            print("\t Acknowledgement received")
            print("\t Preparing file to send")
            integrity_value = file_transfer.upload_file(conn, command_split[1], key_generation.integrity_verification_key,
                                                        key_generation.file_encryption_key, key_generation.initialization_value)
            confirmation = conn.recv(4096).decode('utf-8')
            if confirmation == 'Ack':
                conn.send(integrity_value)
                confirmation = conn.recv(4096).decode('utf-8')
                print(confirmation)
    elif command_split[0] == 'download':
        conn.sendall(command.encode('utf-8'))
        integrity_value = file_transfer.download_file(conn, command_split[1], key_generation.integrity_verification_key,
                                                      key_generation.file_encryption_key, key_generation.initialization_value)
        print('File has been downloaded')
        conn.send(b'Ack')
        integrity_value_received = conn.recv(4096)
        if integrity_value == integrity_value_received:
            print("Integrity verification successful")
            conn.send(b'The file passed integrity verification. The file was not corrupted')
        else:
            print("Integrity Verification failed")
            conn.send(b'The file did not pass integrity verification. The file was corrupted')
    elif command_split[0] == 'exit':
        conn.sendall(b"exit")
        print("Disconnecting")
        break
    else:
        print("Wrong command. Please enter again")
