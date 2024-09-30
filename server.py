import socket
import threading
import json
import base64
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

class ServerJSON:
    def __init__(self, host='localhost', port=8088):
        self.address = (host, port)
        self.clients = {}  # Store clients as {fingerprint: {'socket': client_socket, 'public_key': public_key_pem, 'counter': int}}
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
            threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True).start()

    def handle_client(self, client_socket):
        data_buffer = ""
        while True:
            try:
                # Receive data from the client
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    break
                data_buffer += data
                # Attempt to parse JSON messages
                while True:
                    try:
                        json_obj, index = json.JSONDecoder().raw_decode(data_buffer)
                        data_buffer = data_buffer[index:].lstrip()
                        self.process_message(client_socket, json_obj)
                    except json.JSONDecodeError:
                        # Not enough data to decode; break and wait for more
                        break
            except Exception as e:
                print(f"Client disconnected or error occurred: {e}")
                self.remove_client(client_socket)
                break

    def process_message(self, client_socket, message):
        message_type = message.get('type')
        if message_type == 'signed_data':
            data = message.get('data', {})
            data_type = data.get('type')
            if data_type == 'hello':
                self.handle_hello_message(client_socket, data)
            elif data_type == 'public_chat':
                self.handle_public_chat(client_socket, message)
            elif data_type == 'chat':
                self.handle_private_chat(client_socket, message)
            else:
                print(f"Unknown data type received: {data_type}")
        elif message_type == 'client_list_request':
            self.send_client_list(client_socket)
        else:
            print(f"Unknown message type received: {message_type}")

    def handle_hello_message(self, client_socket, message_data):
        # Extract public key from message and generate a fingerprint
        public_key_pem_str = message_data['public_key']
        public_key_pem = public_key_pem_str.encode()
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        fingerprint = self.generate_fingerprint(public_key_pem)
        print(f"New client connected with fingerprint: {fingerprint}")

        # Store client information
        self.clients[fingerprint] = {
            'socket': client_socket,
            'public_key': public_key_pem_str,
            'counter': 0  # Initialize counter for replay attack prevention
        }

        # In a full implementation, you would send client updates to other servers here

    def generate_fingerprint(self, public_key_pem):
        # Generate fingerprint as Base64Encode(SHA-256(exported RSA public key))
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(public_key_pem)
        fingerprint = base64.b64encode(digest.finalize()).decode()
        return fingerprint

    def send_client_list(self, client_socket):
        # Prepare the client list response
        client_list = {
            "type": "client_list",
            "servers": [
                {
                    "address": f"{self.address[0]}:{self.address[1]}",
                    "clients": [client_info['public_key']
                                for client_info in self.clients.values()]
                }
            ]
        }
        # Send the client list to the requesting client
        client_socket.sendall(json.dumps(client_list).encode('utf-8'))

    def handle_public_chat(self, sender_socket, message):
        data = message.get('data', {})
        sender_fingerprint = data.get('sender')
        message_text = data.get('message')

        # Verify signature and counter
        if not self.verify_signature(sender_fingerprint, message):
            print("Invalid signature in public chat message.")
            return

        # Broadcast the public chat to all clients
        for fingerprint, client_info in self.clients.items():
            client_socket = client_info['socket']
            if client_socket != sender_socket:
                try:
                    client_socket.sendall(json.dumps(message).encode('utf-8'))
                except Exception as e:
                    print(f"Error sending public chat to {fingerprint}: {e}")
                    self.remove_client(client_socket)

    def handle_private_chat(self, sender_socket, message):
        data = message.get('data', {})
        participants = data.get('participants', [])
        symm_keys = data.get('symm_keys', [])
        destination_servers = data.get('destination_servers', [])

        # Verify signature and counter
        sender_fingerprint = participants[0]
        if not self.verify_signature(sender_fingerprint, message):
            print("Invalid signature in private chat message.")
            return

        # Forward the message to the intended recipients connected to this server
        for idx, recipient_fingerprint in enumerate(participants[1:]):
            if recipient_fingerprint in self.clients:
                client_socket = self.clients[recipient_fingerprint]['socket']
                # Adjust the message to include only the recipient's encrypted AES key
                message_copy = {
                    'type': message['type'],
                    'data': data.copy(),
                    'counter': message['counter'],
                    'signature': message['signature']
                }
                message_copy['data']['symm_keys'] = [symm_keys[idx]]
                message_copy['data']['participants'] = participants
                try:
                    client_socket.sendall(json.dumps(message_copy).encode('utf-8'))
                except Exception as e:
                    print(f"Error sending private chat to {recipient_fingerprint}: {e}")
                    self.remove_client(client_socket)
            else:
                print(f"Recipient {recipient_fingerprint} not connected to this server.")

    def verify_signature(self, sender_fingerprint, message):
        client_info = self.clients.get(sender_fingerprint)
        if not client_info:
            print(f"Sender with fingerprint {sender_fingerprint} not recognized.")
            return False

        signature_b64 = message.get('signature')
        signature = base64.b64decode(signature_b64)
        counter = message.get('counter')
        data = message.get('data')
        message_bytes = json.dumps(data).encode() + str(counter).encode()

        # Check counter for replay attack prevention
        last_counter = client_info.get('counter', 0)
        if counter <= last_counter:
            print("Replay attack detected or invalid counter.")
            return False
        client_info['counter'] = counter  # Update counter

        # Load sender's public key
        public_key_pem_str = client_info['public_key']
        public_key_pem = public_key_pem_str.encode()
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

        try:
            public_key.verify(
                signature,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=32
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False

    def remove_client(self, client_socket):
        # Remove client from the list of connected clients
        fingerprints_to_remove = [fprint for fprint, info in self.clients.items() if info['socket'] == client_socket]
        for fprint in fingerprints_to_remove:
            del self.clients[fprint]
            print(f"Client with fingerprint {fprint} disconnected.")

# Start the server
if __name__ == "__main__":
    server = ServerJSON()
    threading.Thread(target=server.start, daemon=True).start()

    # Keep the main thread alive to prevent the program from exiting
    while True:
        pass
