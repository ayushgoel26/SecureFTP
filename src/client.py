import socket
import random
from src.key_generation import KeyGeneration
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from src.fileTansfer import FileTransfer
from src.config import HOST, PORT, CONFIDENTIAL_FILES_FOLDER
import os

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
    command = input('command: ').split(" ")
    if command[0] == "help":
        print("help: provide the list of commands")
        print("localFiles: provides the list of files in the client directory")
        print("remoteFiles: proves the list of files in the server directory")
        print("upload <Filename> : Uploads the file")
        print("download <Filename> : Download the file")
        print("exit : exits the client server")
    elif command[0] == "localFiles":
        file_transfer.local_files()
    elif command[0] == "remoteFiles":
        conn.sendall(b"remoteFiles")
        remote_file_list = conn.recv(4096).decode('utf-8')
        if not remote_file_list:
            print("The Directory is empty")
        else:
            # prints only files in the folder
            for file in remote_file_list:
                print("\t" + file)
    elif command[0] == 'exit':
        conn.sendall(b"exit")
        print("Disconnecting")
        break