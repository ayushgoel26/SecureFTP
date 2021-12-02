import getopt, sys

# Remove 1st argument from the
# list of command line arguments
argumentList = sys.argv[1:]

# Options
options = "hsc"

# Long options
long_options = ["help", "client", "server"]

try:
    # Parsing argument
    arguments, values = getopt.getopt(argumentList, options, long_options)

    # checking each argument
    for currentArgument, currentValue in arguments:

        if currentArgument in ("-h", "--help"):
            print("""-----------------------------------------
DISPLAYING THE HELP MENU
-----------------------------------------
>> python -m src.run [ -h | --help ] 
-----------------------------------------
STARTING THE SERVER
-----------------------------------------    
>> python -m src.run [ -s | --server ]
-----------------------------------------
STARTING THE CLIENT
-----------------------------------------
>> python -m src.run [ -c | --client ] 
-----------------------------------------""")

        elif currentArgument in ("-s", "--server"):
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
            connect.bind((HOST,
                          PORT))  # Used to associate the socket with a specific network interface. Arguments passed to bind
            connect.listen(1)  # depend on the address family we choose

            print("Listening to %s on port %d" % (HOST, PORT))
            print("Waiting for connection")

            conn, address = connect.accept()
            print('Connection received from client ', address)

            authenticationPayloadEncrypted = conn.recv(4096)

            private_key = RSA.import_key(
                open(os.path.dirname(os.path.dirname(__file__)) + '/' + CONFIDENTIAL_FILES_FOLDER + 'server-key.pem',
                     'r').read())
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

        elif currentArgument in ("-c", "--client"):
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

            nonce = str(random.randint(100000, 1000000))  # pick random nonce to authenticate server
            key_generation = KeyGeneration()
            key_generation.session_key_generation()  # generating session key and other keys

            # check if the server is authentic
            # https://www.peterspython.com/en/blog/using-python-s-pyopenssl-to-verify-ssl-certificates-downloaded-from-a-host
            # pick servers public key
            server_public_key = RSA.import_key(
                open(os.path.dirname(os.path.dirname(__file__)) + '/' + CONFIDENTIAL_FILES_FOLDER +
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
except getopt.error as err:
    # output error, and return with an error code
    print(str(err))
