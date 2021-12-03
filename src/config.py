HOST = '127.0.0.1'  # localhost
PORT = 1234    # port used by server

# Directory Names
SERVER_FOLDER = '/server'
CLIENT_FOLDER = '/client'
ROOT_FOLDER = '/root'
SECRET_FOLDER = '/secret'
CA_FOLDER = '/ca'

# Secret File Names
SERVER_PVT_KEY = ''
SERVER_PUBLIC_KEY = '/server-key-public.pem'


WELCOME_TEXT = """---------------------------------------------------
TYPE  >> help  TO GET THE LIST OF ALLOWED COMMANDS 
---------------------------------------------------"""

SecureFTP_HELP_TEXT = """
    >> lsl                               : Lists the contents of the client's root folder
    >> lsr                               : Lists the contents of the remote server's root folder
    >> put <file-name in client root>    : Uploads a file from Client to Server 
    >> get <file-name in remote's root>  : Downloads a file from Server to Client
    >> exit                              : Exit the SecureFTP module"""

HELP_TEXT = """-----------------------------------------
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
-----------------------------------------"""