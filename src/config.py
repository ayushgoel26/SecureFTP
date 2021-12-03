HOST = '127.0.0.1'  # localhost
PORT = 1234    # port used by server

CONFIDENTIAL_FILES_FOLDER = 'confidential/'

WELCOME_TEXT = """---------------------------------------------------
TYPE  >> help  TO GET THE LIST OF ALLOWED COMMANDS 
---------------------------------------------------"""

SecureFTP_HELP_TEXT = """-----------------------------------------
Local Root Directory Content List
-----------------------------------------    
Lists the contents of the client's root folder
>> lsl
-----------------------------------------
Remote Root Directory Content List
-----------------------------------------
Lists the contents of the remote server's root folder
>> lsr
-----------------------------------------
Put a file in remote server 
-----------------------------------------
Uploads a file from Client to Server 
>> put <file-name in client root>
-----------------------------------------
Get a file from remote server 
-----------------------------------------
Downloads a file from Server to Client
>> get <file-name in remote's root>
-----------------------------------------
Exit the SecureFTP module 
-----------------------------------------
cancels the connection and exits 
>> exit
-----------------------------------------"""

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