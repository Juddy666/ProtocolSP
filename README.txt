This is a README file for the Secure Programming project of Group 31:
    - Daniel Mosler / a1687565
    - Jeffrey Judd / a1833565
    - Maeve Elshaug-Betson a1824050
    - Mehdi Mahzounieh / a1870199

Dependencies:
    This project is being developed in Python using Microsoft Visual Studio Code as an IDE, as such using this environment is 
    recommended. 
    VSC can be downloaded for Windows or Mac at:
        https://code.visualstudio.com/

    VScode uses extensions to enable the use of different programming languages. Reccomended extensions include:
        - Python (Provides support for the python language)                                 *Required
        - Python Debugger (Provides an improved debugging experience for python programs)   *Recommended
        - Pylance                                                                           *Recommended
        - Pip Manager (used to manage pip libraries)                                        *May or may not be required

    For Windows Users:
        If you have not used python before, you will need to install a python interpreter from www.python.org/downloads, 
        alternativelyrunning the command "python" in VScode will prompt a download from the microsoft store.

        Windows users will need to install the cryptography and requests library if they have not done so previously via the command:
            pip install cryptography
            pip install request


    For Mac Users:
        If you have not used python before, you will need to install a python interpreter for your system using the command:
            brew install python3

        Mac users will need to install the cryptography and requests library using the command:
            python3 -m pip install cryptography, OR
            brew install cryptography, depending on your environment and
            python3 -m pip install requests, OR
            brew install requests

        
Vulnerabilites:
    ATTENTION!! This code purposley contains backdoors to assess the awareness of students. It is highly vulenrable and can be subject to malicious use. Please use at your risk.
        

Use guide:
servers need to be connected to their neighbouring servers for proper connection
TEST CASES 
#for local machines type in your terminal
# start server 1 
python server.py --host localhost --port 8088 --server_port 8090 --neighbours localhost:8091
# start server2
python server.py --host localhost --port 8089 --server_port 8091 --neighbours localhost:8090

# add client 1 on server 1
python client.py --host localhost --port 8088
# add client 2 on server 2
python client.py --host localhost --port 8089

# running server on different machines
add the ip of your host if of your machine
python server.py --host 192.168.1.2 --port 8088 --server_port 9000 --neighbours 192.168.1.3:9001
python server.py --host 192.168.1.3 --port 8089 --server_port 9001 --neighbours 192.168.1.2:9000


Overview
The Encrypted Chat System is a Python program that lets users communicate over a network. It uses RSA encryption to share keys and AES to encrypt messages, ensuring security for private chats. The server manages connections between clients and but also links up with other servers to form a neighbourhood. This allows clients to send messages to other client on different servers and decentralises the protocol, making more secure. 

Encryption:
The protocol uses RSA and AES encryption to secure messages. RSA is used to safely share AES keys, while AES is used to encrypt the actual messages. All messages are signed using RSA to ensure they haven’t been tampered with. Each message also has a counter to prevent someone from re-sending (or replaying) old messages. This should prevent replay attacks. 

Identification:
When a client connects, it creates a unique fingerprint from its RSA public key. This fingerprint acts like a unique ID for each user and is used when sending private messages to make sure messages go to the right person. Users can ask for a list of all connected clients, along with their fingerprint. This helps them find and securely chat with specific people.

Sending a private message:
The server oversees managing all connections. It handles client connections and connects to neighbouring servers to build a larger chat neighbourhood. 
When a client wants to send a private message, the server will look at the ‘destination server’ to see if they are the intended server. The server will then look at the ‘recipients’ to see if they are connected to the sever. Then the server will send the ‘flood’ the packet to all clients connect to the server to decrypted by the recipients.
make sure to refresh the online clients before attempting to send an encrypted message. simply press 3 on the menu. if the inserted finger print is incorrect or not in the sender's client list you will receive an error that public key doesn't exist.
  
Sending a public chat:
In addition to private messages, users can also send public messages. Public messages are broadcasted by the server to all clients connected to it. If the server is part of a neighbourhood, it will forward the public message to other servers, allowing all users in the neighbourhood to see the message

Point-to-point file transfer:
File transfers are performed over an HTTP[S] API. Users can upload a file via it's file path and the server will respond with the file data as a URL. This URL can be sent to other user's by copying and pasting it into a public or encrypted chat message. Receiving users can then download the file by copying and pasting the received URL into the "Download file" option. File uploads and downloads are not authenticated and rely on keeping the URL a secret. User can share the address of the uploaded file privately to another user who can use this url to download the file.
