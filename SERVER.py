import socket
import threading
import json
import base64
import hashlib
import argparse
import time
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from io import BytesIO
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

class ServerJSON:
    def __init__(self, host='localhost', port=8088, server_port=8090, http_port=8000, neighbour_addresses=None):
        self.address = (host, port)
        self.server_address = (host, server_port)
        self.http_address = (host, http_port)
        self.clients = {}  # Clients connected to this server
        self.client_list = {}  # All clients in the neighbourhood
        self.servers = {}  # Connected servers
        self.neighbour_addresses = neighbour_addresses or []  # Addresses of neighbouring servers
        self.files = {}  # Dictionary to store file URLs and paths
        self.heartbeat_interval = 10  # Seconds
        self.server_timeout = 30  # Seconds

        # Socket for client connections
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Socket for server connections
        self.server_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.server_socket.bind(self.address)
            self.server_socket.listen(5)
            print(f"Server started for clients at {self.address}")
        except OSError as e:
            print(f"Error binding client socket: {e}")
            if "Address already in use" in str(e):
                print("Try changing the port or check for running processes using the same port.")

        try:
            self.server_server_socket.bind(self.server_address)
            self.server_server_socket.listen(5)
            print(f"Server started for servers at {self.server_address}")
        except OSError as e:
            print(f"Error binding server socket: {e}")
            if "Address already in use" in str(e):
                print("Try changing the port or check for running processes using the same port.")

        # Start accepting client connections
        threading.Thread(target=self.accept_client_connections, daemon=True).start()
        # Start accepting server connections
        threading.Thread(target=self.accept_server_connections, daemon=True).start()
        # Start HTTP server for file transfers
        threading.Thread(target=self.start_http_server, daemon=True).start()
        # Start heartbeat checks
        threading.Thread(target=self.server_heartbeat_check, daemon=True).start()
        # Connect to neighbour servers
        for neighbour in self.neighbour_addresses:
            threading.Thread(target=self.connect_to_server, args=(neighbour,), daemon=True).start()

    def accept_client_connections(self):
        while True:
            client_socket, client_address = self.server_socket.accept()
            print(f"Client {client_address} connected")
            threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True).start()

    def accept_server_connections(self):
        while True:
            server_socket, server_address = self.server_server_socket.accept()
            print(f"Server {server_address} connected")
            threading.Thread(target=self.handle_server_connection, args=(server_socket, server_address), daemon=True).start()

    def connect_to_server(self, server_address_str):
        host, port_str = server_address_str.split(':')
        port = int(port_str)
        server_address = (host, port)
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect(server_address)
            print(f"Connected to server {server_address}")
            self.servers[server_address] = {'socket': server_socket, 'last_heartbeat': time.time()}
            threading.Thread(target=self.handle_server_connection, args=(server_socket, server_address), daemon=True).start()
            # Send server_hello
            self.send_server_hello(server_socket)
        except Exception as e:
            print(f"Error connecting to server {server_address}: {e}")

    def handle_server_connection(self, server_socket, server_address):
        data_buffer = ""
        self.servers[server_address] = {'socket': server_socket, 'last_heartbeat': time.time()}
        while True:
            try:
                data = server_socket.recv(4096).decode('utf-8')
                if not data:
                    print(f"Server {server_address} disconnected")
                    self.remove_server(server_address)
                    break
                data_buffer += data
                while True:
                    try:
                        json_obj, index = json.JSONDecoder().raw_decode(data_buffer)
                        data_buffer = data_buffer[index:].lstrip()
                        self.process_server_message(server_socket, server_address, json_obj)
                    except json.JSONDecodeError:
                        break
            except Exception as e:
                print(f"Server {server_address} disconnected or error occurred: {e}")
                self.remove_server(server_address)
                break

    def send_server_hello(self, server_socket):
        message = {
            "type": "server_hello",
            "data": {
                "type": "server_hello",
                "sender": f"{self.server_address[0]}:{self.server_address[1]}"
            }
        }
        server_socket.sendall(json.dumps(message).encode('utf-8'))

    def process_server_message(self, server_socket, server_address, message):
        message_type = message.get('type')
        if message_type == 'server_hello':
            self.handle_server_hello(server_socket, server_address, message)
        elif message_type == 'client_update':
            self.handle_client_update(server_socket, server_address, message)
        elif message_type == 'client_update_request':
            self.handle_client_update_request(server_socket)
        elif message_type == 'heartbeat':
            self.handle_server_heartbeat(server_address)
        elif message_type == 'signed_data':
            self.process_message(server_socket, message, from_server=True)
        else:
            print(f"Unknown message type received from server: {message_type}")

    def handle_server_hello(self, server_socket, server_address, message):
        print(f"Received server_hello from {server_address}")
        # Send client_update_request to get the client list
        self.send_client_update_request(server_socket)

    def send_client_update_request(self, server_socket):
        message = {
            "type": "client_update_request"
        }
        server_socket.sendall(json.dumps(message).encode('utf-8'))

    def handle_client_update(self, server_socket, server_address, message):
        clients_pem = message.get('clients', [])
        print(f"Received client_update from {server_address}")
        for client_public_key_pem in clients_pem:
            client_public_key_pem_bytes = client_public_key_pem.encode()
            client_public_key = serialization.load_pem_public_key(client_public_key_pem_bytes, backend=default_backend())
            fingerprint = self.generate_fingerprint(client_public_key_pem_bytes)
            self.client_list[fingerprint] = {
                'public_key': client_public_key_pem,
                'server_address': f"{server_address[0]}:{server_address[1]}"
            }
        # Update last heartbeat time
        self.servers[server_address]['last_heartbeat'] = time.time()

    def handle_client_update_request(self, server_socket):
        # Send client_update message with current clients
        client_update_message = {
            "type": "client_update",
            "clients": [client_info['public_key'] for client_info in self.clients.values()]
        }
        server_socket.sendall(json.dumps(client_update_message).encode('utf-8'))

    def handle_server_heartbeat(self, server_address):
        # Update last heartbeat time
        if server_address in self.servers:
            self.servers[server_address]['last_heartbeat'] = time.time()

    def server_heartbeat_check(self):
        while True:
            time.sleep(self.heartbeat_interval)
            current_time = time.time()
            for server_address, server_info in list(self.servers.items()):
                # Send heartbeat
                heartbeat_message = {
                    "type": "heartbeat"
                }
                try:
                    server_info['socket'].sendall(json.dumps(heartbeat_message).encode('utf-8'))
                except Exception as e:
                    print(f"Error sending heartbeat to server {server_address}: {e}")
                    self.remove_server(server_address)
                    continue
                # Check for timeout
                if current_time - server_info.get('last_heartbeat', 0) > self.server_timeout:
                    print(f"Server {server_address} timed out.")
                    self.remove_server(server_address)
                    # Attempt to reconnect
                    threading.Thread(target=self.connect_to_server, args=(f"{server_address[0]}:{server_address[1]}",), daemon=True).start()

    def remove_server(self, server_address):
        if server_address in self.servers:
            del self.servers[server_address]
            print(f"Removed server {server_address}")
        # Remove clients associated with this server from client_list
        fingerprints_to_remove = [f for f, info in self.client_list.items() if info['server_address'] == f"{server_address[0]}:{server_address[1]}"]
        for fprint in fingerprints_to_remove:
            del self.client_list[fprint]

    def handle_client(self, client_socket):
        data_buffer = ""
        client_address = client_socket.getpeername()
        while True:
            try:
                # Receive data from the client
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    print(f"Client {client_address} disconnected")
                    self.remove_client(client_socket)
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
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError) as e:
                print(f"Client {client_address} disconnected unexpectedly: {e}")
                self.remove_client(client_socket)
                break
            except Exception as e:
                print(f"Client {client_address} disconnected or error occurred: {e}")
                self.remove_client(client_socket)
                break

    def process_message(self, sender_socket, message, from_server=False):
        message_type = message.get('type')
        if message_type == 'signed_data':
            data = message.get('data', {})
            data_type = data.get('type')
            if data_type == 'hello':
                if not from_server:
                    self.handle_hello_message(sender_socket, data)
                else:
                    print("Received hello message from server, ignoring.")
            elif data_type == 'public_chat':
                self.handle_public_chat(sender_socket, message, from_server)
            elif data_type == 'chat':
                self.handle_private_chat(sender_socket, message, from_server)
            else:
                print(f"Unknown data type received: {data_type}")
        elif message_type == 'client_list_request':
            if not from_server:
                self.send_client_list(sender_socket)
            else:
                print("Received client_list_request from server, ignoring.")
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

        # Update client_list
        self.client_list[fingerprint] = {
            'public_key': public_key_pem_str,
            'server_address': f"{self.server_address[0]}:{self.server_address[1]}"
        }

        # Send client_update to other servers
        self.broadcast_client_update()

        # Notify other clients about the new client
        self.broadcast_client_update_to_clients()

    def broadcast_client_update(self):
        client_update_message = {
            "type": "client_update",
            "clients": [client_info['public_key'] for client_info in self.clients.values()]
        }
        for server_info in self.servers.values():
            server_socket = server_info['socket']
            try:
                server_socket.sendall(json.dumps(client_update_message).encode('utf-8'))
            except Exception as e:
                print(f"Error sending client_update to server: {e}")

    def broadcast_client_update_to_clients(self):
        # Notify all connected clients about the updated client list
        client_list = {
            "type": "client_list",
            "servers": []
        }
        # Include clients connected to this server
        server_entry = {
            "address": f"{self.server_address[0]}:{self.server_address[1]}",
            "clients": [client_info['public_key'] for client_info in self.clients.values()]
        }
        client_list['servers'].append(server_entry)
        # Include clients from other servers
        servers_seen = set()
        for client_info in self.client_list.values():
            server_address = client_info['server_address']
            if server_address not in servers_seen:
                servers_seen.add(server_address)
                clients = [info['public_key'] for fprint, info in self.client_list.items() if info['server_address'] == server_address]
                client_list['servers'].append({
                    "address": server_address,
                    "clients": clients
                })
        # Send the client list to all connected clients
        for client_info in self.clients.values():
            client_socket = client_info['socket']
            try:
                client_socket.sendall(json.dumps(client_list).encode('utf-8'))
            except Exception as e:
                print(f"Error sending client list to client: {e}")
                self.remove_client(client_socket)

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
            "servers": []
        }
        # Include clients connected to this server
        server_entry = {
            "address": f"{self.server_address[0]}:{self.server_address[1]}",
            "clients": [client_info['public_key'] for client_info in self.clients.values()]
        }
        client_list['servers'].append(server_entry)
        # Include clients from other servers
        servers_seen = set()
        for client_info in self.client_list.values():
            server_address = client_info['server_address']
            if server_address not in servers_seen:
                servers_seen.add(server_address)
                clients = [info['public_key'] for fprint, info in self.client_list.items() if info['server_address'] == server_address]
                client_list['servers'].append({
                    "address": server_address,
                    "clients": clients
                })
        # Send the client list to the requesting client
        client_socket.sendall(json.dumps(client_list).encode('utf-8'))

    def handle_public_chat(self, sender_socket, message, from_server=False):
        data = message.get('data', {})
        sender_fingerprint = data.get('sender')

        # Verify signature and counter
        if not self.verify_signature(sender_fingerprint, message, from_server):
            print("Invalid signature in public chat message.")
            return

        # Broadcast the public chat to all clients connected to this server
        for fingerprint, client_info in self.clients.items():
            client_socket = client_info['socket']
            if client_socket != sender_socket:
                try:
                    client_socket.sendall(json.dumps(message).encode('utf-8'))
                except Exception as e:
                    print(f"Error sending public chat to {fingerprint}: {e}")
                    self.remove_client(client_socket)

        # Forward the message to other servers
        for server_address, server_info in self.servers.items():
            server_socket = server_info['socket']
            if server_socket != sender_socket:
                try:
                    server_socket.sendall(json.dumps(message).encode('utf-8'))
                except Exception as e:
                    print(f"Error forwarding public chat to server {server_address}: {e}")

    def handle_private_chat(self, sender_socket, message, from_server=False):
        data = message.get('data', {})
        participants = data.get('participants', [])
        symm_keys = data.get('symm_keys', [])
        destination_servers = data.get('destination_servers', [])

        sender_fingerprint = participants[0]

        # Verify signature and counter
        if not self.verify_signature(sender_fingerprint, message, from_server):
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
                # Recipient not connected to this server
                # Forward to the destination server
                recipient_info = self.client_list.get(recipient_fingerprint)
                if recipient_info:
                    server_address_str = recipient_info['server_address']
                    server_address_tuple = tuple(server_address_str.split(':'))
                    server_address = (server_address_tuple[0], int(server_address_tuple[1]))
                    server_socket = self.servers.get(server_address, {}).get('socket')
                    if server_socket and server_socket != sender_socket:
                        try:
                            server_socket.sendall(json.dumps(message).encode('utf-8'))
                        except Exception as e:
                            print(f"Error forwarding message to server {server_address}: {e}")
                    else:
                        print(f"Server {server_address} not connected.")
                else:
                    print(f"Recipient {recipient_fingerprint} not found in client list.")

    def verify_signature(self, sender_fingerprint, message, from_server=False):
        if from_server:
            client_info = self.client_list.get(sender_fingerprint)
            if not client_info:
                print(f"Sender with fingerprint {sender_fingerprint} not recognized.")
                return False
            public_key_pem_str = client_info['public_key']
        else:
            client_info = self.clients.get(sender_fingerprint)
            if not client_info:
                print(f"Sender with fingerprint {sender_fingerprint} not recognized.")
                return False
            public_key_pem_str = client_info['public_key']

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
            del self.client_list[fprint]
            print(f"Client with fingerprint {fprint} disconnected.")
            # Send client_update to other servers
            self.broadcast_client_update()
            # Notify other clients about the client disconnection
            self.broadcast_client_update_to_clients()

    # HTTP Server for File Transfer
    class FileUploadHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path == '/api/upload':
                content_length = int(self.headers['Content-Length'])
                # Limit file size to 10 MB
                if content_length > 10 * 1024 * 1024:
                    self.send_response(413)
                    self.end_headers()
                    self.wfile.write(b'Payload Too Large')
                    return
                file_data = self.rfile.read(content_length)
                # Generate a unique file ID
                file_id = base64.urlsafe_b64encode(os.urandom(16)).decode()
                file_path = f"uploads/{file_id}"
                os.makedirs('uploads', exist_ok=True)
                with open(file_path, 'wb') as f:
                    f.write(file_data)
                # Store the file URL
                file_url = f"http://{self.server.server_address[0]}:{self.server.server_address[1]}/{file_id}"
                self.server.parent.files[file_id] = file_path
                # Send response
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                response = {
                    "file_url": file_url
                }
                self.wfile.write(json.dumps(response).encode())
            else:
                self.send_response(404)
                self.end_headers()

        def do_GET(self):
            parsed_path = urlparse(self.path)
            file_id = parsed_path.path.strip('/')
            if file_id in self.server.parent.files:
                file_path = self.server.parent.files[file_id]
                try:
                    with open(file_path, 'rb') as f:
                        file_data = f.read()
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/octet-stream')
                    self.end_headers()
                    self.wfile.write(file_data)
                except Exception as e:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(b'Internal Server Error')
            else:
                self.send_response(404)
                self.end_headers()

    def start_http_server(self):
        handler = self.FileUploadHandler
        handler.server = self  # Pass reference to the server instance
        httpd = HTTPServer(self.http_address, handler)
        httpd.parent = self
        print(f"HTTP server started at {self.http_address}")
        httpd.serve_forever()

# Start the server
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start the server.")
    parser.add_argument("--host", default="localhost", help="Server host address.")
    parser.add_argument("--port", type=int, default=8088, help="Port for client connections.")
    parser.add_argument("--server_port", type=int, default=8090, help="Port for server-to-server connections.")
    parser.add_argument("--http_port", type=int, default=8000, help="Port for HTTP server (file transfers).")
    parser.add_argument("--neighbours", nargs="*", default=[], help="List of neighbour server addresses (e.g., localhost:8091).")

    args = parser.parse_args()

    server = ServerJSON(host=args.host, port=args.port, server_port=args.server_port, http_port=args.http_port, neighbour_addresses=args.neighbours)

    # Keep the main thread alive to prevent the program from exiting
    while True:
        pass
