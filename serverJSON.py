import socket
import threading
import json
import hashlib

class ServerJSON:
    def __init__(self, host='localhost', port=8088):
        self.address = (host, port)
        self.clients = {}  # Store clients as {fingerprint: (client_socket, public_key)}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.server_socket.bind(self.address)
            self.server_socket.listen(5)
            print(f"Server started at {self.address}")
        except OSError as e:
            print(f"Error: {e}")
            if "Address already in use" in str(e):
                print("Try changing the port or check for running processes using the same port.")

    def start(self):
        while True:
            client_socket, client_address = self.server_socket.accept()
            print(f"Client {client_address} connected")
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        data = ""
        while True:
            try:
                # Receive and decode message (use a larger buffer size to avoid truncation)
                part = client_socket.recv(4096).decode('utf-8')
                if not part:
                    break
                data += part

                # Attempt to parse JSON data once the message is complete
                try:
                    json_data = json.loads(data)
                    print(f"Received JSON message: {json_data}")

                    # Reset the data buffer for the next message
                    data = ""

                    # Handle the received message based on its type
                    message_type = json_data.get('data', {}).get('type')
                    if message_type == 'hello':
                        self.handle_hello_message(client_socket, json_data['data'])
                    elif message_type == 'client_list_request':
                        self.send_client_list(client_socket)
                    elif message_type == 'chat':
                        self.send_private_message(client_socket, json_data)
                    else:
                        # Handle other types of messages (e.g., broadcast or public chat)
                        self.broadcast_message(client_socket, json_data)
                except json.JSONDecodeError:
                    # Continue receiving if the message is incomplete
                    continue
            except Exception as e:
                print(f"Client disconnected or error occurred: {e}")
                self.remove_client(client_socket)
                break

    def handle_hello_message(self, client_socket, message_data):
        # Extract public key from message and generate a fingerprint
        public_key_pem = message_data['public_key'].encode()
        fingerprint = self.generate_fingerprint(public_key_pem)
        print(f"New client connected with fingerprint: {fingerprint}")

        # Store client information: fingerprint -> (client_socket, public_key)
        self.clients[fingerprint] = (client_socket, public_key_pem)

    def generate_fingerprint(self, public_key_pem):
        # Generate a fingerprint of the public key (SHA-256 hash)
        fingerprint = hashlib.sha256(public_key_pem).hexdigest()
        return fingerprint

    def send_client_list(self, client_socket):
        # Prepare the client list response
        client_list = {
            "type": "client_list",
            "servers": [
                {
                    "address": f"{self.address[0]}:{self.address[1]}",
                    "clients": [{"fingerprint": fingerprint}
                                for fingerprint, (sock, public_key) in self.clients.items()]
                }
            ]
        }
        # Send the client list to the requesting client
        client_socket.send(json.dumps(client_list).encode('utf-8'))

    def send_private_message(self, sender_socket, message_dict):
        # Convert the dictionary into a JSON string
        json_message = json.dumps(message_dict)
        
        # Broadcast the private message to all clients except the sender
        for fingerprint, (client_socket, public_key) in self.clients.items():
            if client_socket != sender_socket:
                try:
                    # Send the JSON string to the client
                    client_socket.send(json_message.encode('utf-8'))
                    print(f"Sent private message to client with fingerprint: {fingerprint}")
                except Exception as e:
                    print(f"Error sending private message: {e}")
                    self.remove_client(client_socket)

    def broadcast_message(self, sender_socket, message_dict):
        # Convert the dictionary into a JSON string
        json_message = json.dumps(message_dict)
        for fingerprint, (client_socket, public_key) in self.clients.items():
            if client_socket != sender_socket:
                try:
                    # Send the JSON string to other clients
                    client_socket.send(json_message.encode('utf-8'))
                except Exception as e:
                    print(f"Error sending message: {e}")
                    self.remove_client(client_socket)

    def remove_client(self, client_socket):
        # Remove client from the list of connected clients
        for fingerprint, (sock, public_key) in list(self.clients.items()):
            if sock == client_socket:
                del self.clients[fingerprint]
                break

# Start the server
if __name__ == "__main__":
    server = ServerJSON()
    threading.Thread(target=server.start).start()
