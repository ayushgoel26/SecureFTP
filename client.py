import socket
import random
from key_generation import KeyGeneration
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

HOST = '127.0.0.1'  # localhost
PORT = 1234    # port used by server

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
server_public_key = RSA.import_key(open('Certificates_and_keys/server-key-public.pem', 'r').read())

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
