import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from src.key_generation import KeyGeneration
from src.fileTansfer import FileTransfer
from src.config import HOST, PORT, CONFIDENTIAL_FILES_FOLDER
import os

print("SFTP Server side")

# Socket object is created with the address family in argument
# Socket type.AF_INET -> Internet address family for IPv4
# SOCK_STREAM is the socket type for TCP
connect = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect.bind((HOST, PORT))  # Used to associate the socket with a specific network interface. Arguments passed to bind
connect.listen(1)  # depend on the address family we choose

print("Listening to %s on port %d" % (HOST, PORT))
print("Waiting for connection")

conn, address = connect.accept()
print('Connection received from client ', address)

authenticationPayloadEncrypted = conn.recv(4096)

private_key = RSA.import_key(open(os.path.dirname(os.path.dirname(__file__)) + '/' + CONFIDENTIAL_FILES_FOLDER + 'server-key.pem', 'r').read())
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
    if client_command[0] == "remoteFiles":
        print("The client requested a list of remote directories")
        local_files = file_transfer.local_files()
        conn.send(local_files.encode('utf-8'))
    elif client_command[0] == "exit":
        print("Client is leaving connection")
        break
