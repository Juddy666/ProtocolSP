servers need to be connected to their neighbouring servers for proper connection
TEST CASES 
##for local machines
#type in your terminal
# start server 1 
python server.py --host localhost --port 8088 --server_port 8090 --neighbours localhost:8091
# start server2
python server.py --host localhost --port 8089 --server_port 8091 --neighbours localhost:8090

# add client 1 on server 1
python client.py --host localhost --port 8088

# add client 2 on server 2
python client.py --host localhost --port 8089


## running server on different machines
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
The server oversees managing all connections. It handles client connections and connects to neighbouring servers to build a larger chat neighbourhood. When a client wants to send a private message, the server will look at the ‘destination server’ to see if they are the intended server. The server will then look at the ‘recipients’ to see if they are connected to the sever. Then the server will send the ‘flood’ the packet to all clients connect to the server to decrypted by the recipients.

Sending a public chat:
In addition to private messages, users can also send public messages. Public messages are broadcasted by the server to all clients connected to it. If the server is part of a neighbourhood, it will forward the public message to other servers, allowing all users in the neighbourhood to see the message
