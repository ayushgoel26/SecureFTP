# SecureFTP

## Setup

    $ cd SecureFTP
    $ pip3 install -r requirements.txt

## Running SecureFTP 

**NOTE: Need two different terminal windows for client and server**

#### Running the server 
    
    $ python3 -m src.run [ -s | --server ]  

#### Running the client 

    $ python3 -m src.run [ -c | --client ]  

## Using SecureFTP Client
    
##### List all available commands 
    
    >> help 

##### List all files available in client side root directory
    
    >> lsl 

##### List all files available in server side root directory
    
    >> lsr 

##### Uploads a file from Client to Server 
    
    >> put <file-name in client's root>

##### Downloads a file from Server to Client
    
    >> get <file-name in remote's root>

##### Exit the SecureFTP module
    
    >> exit 


