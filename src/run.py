import getopt
import sys
import pyfiglet
from src.server import Server
from src.client import Client
from src.config import HOST, PORT, WELCOME_TEXT, HELP_TEXT, SecureFTP_HELP_TEXT

argumentList = sys.argv[1:]
options = "hsc"
long_options = ["help", "client", "server"]

try:
    arguments, values = getopt.getopt(argumentList, options, long_options)
    for currentArgument, currentValue in arguments:
        if currentArgument in ("-h", "--help"):
            print(HELP_TEXT)
        elif currentArgument in ("-s", "--server"):
            ascii_banner = pyfiglet.figlet_format("S E R V E R")
            print(ascii_banner)
            server = Server(HOST, PORT)
            conn, address = server.connection.accept()
            print('Connection received from client ', address)
            server.authenticate(conn)
            command = None
            while command != 'exit':
                client_command = conn.recv(4096).decode('utf-8').split(" ")
                command = client_command[0]
                if command == "lsr":
                    server.list_contents(conn)
                elif command == "put":
                    server.put(conn, client_command[1])
                elif command == "get":
                    server.get(conn, client_command[1])
                elif command == "exit":
                    print("Client is leaving connection")
                    break
        elif currentArgument in ("-c", "--client"):
            ascii_banner = pyfiglet.figlet_format("C L I E N T")
            print(ascii_banner)
            print(WELCOME_TEXT)
            while True:
                client = Client(HOST, PORT)
                command = input('>> ')
                command_split = command.split(" ")
                if command_split[0] == "help":
                    print(SecureFTP_HELP_TEXT)
                elif command_split[0] == "lsl":
                    client.list_content()
                elif command_split[0] == "lsr":
                    client.list_remote_content(command)
                elif command_split[0] == 'put':
                    client.put(command, command_split[1])
                elif command_split[0] == 'get':
                    client.get(command, command_split[1])
                elif command_split[0] == 'exit':
                    client.connection.sendall(b"exit")
                    print("Disconnecting")
                    break
                else:
                    print("Wrong command. Please enter again")
except getopt.error as err:
    print(str(err))
