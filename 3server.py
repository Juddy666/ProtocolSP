import socket
import threading

class Server:
    def __init__(self, host='localhost', port=8081):
        self.address = (host, port)
        self.clients = {} 

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(self.address)
        server_socket.listen(5)
        print(f"Server started at {self.address}")

        while True:
            client_socket, client_address = server_socket.accept()
            print(f"Client {client_address} connected")
            threading.Thread(target=self.request_username, args=(client_socket,)).start()

    def request_username(self, client_socket):
        while True:
            client_socket.send("Enter your username: ".encode('utf-8'))
            username = client_socket.recv(1024).decode('utf-8').strip()

            # uniquness check
            if username in self.clients.values():
                client_socket.send("Please choose a different username.\n".encode('utf-8'))
            else:
                self.clients[client_socket] = username
                print(f"Username '{username}' added for client {client_socket.getpeername()}")
                self.broadcast_message(f"{username} has joined the chat!\n")
                self.send_online_clients()
                break

        threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        # detects whether the message is a direct or group message
        username = self.clients[client_socket]

        while True:
            try:
                message = client_socket.recv(1024).decode('utf-8')
                if message:
                    if message.startswith("@"):
                        # direct messages
                        target_name, msg = message.split(':', 1)
                        target_name = target_name[1:].strip()  # Extract target username
                        self.send_direct_message(client_socket, target_name, msg.strip())
                    else:
                        # group messages (uses broadcast)
                        print(f"Received message from {username}: {message}")
                        self.broadcast_message(client_socket, f"{username}: {message}")
            except Exception as e:
                print(f"Error: {e}")
                self.clients.pop(client_socket)
                client_socket.close()
                self.broadcast_message(None, f"{username} has left the chat.")
                self.send_online_clients()
                break

    def broadcast_message(self, sender_socket, message):
        # sends message to all clients
        for client, username in self.clients.items():
            if client != sender_socket:
                try:
                    client.send(message.encode('utf-8'))
                except Exception as e:
                    print(f"Error sending message to {username}: {e}")
                    client.close()
                    self.clients.pop(client)

    def send_online_clients(self):
        # prints list of clients online
        online_clients = "Online clients: " + ", ".join(self.clients.values())
        self.broadcast_message(None, online_clients)

    def send_direct_message(self, sender_socket, target_username, message):
        # clients can send a direct message to selected clients using the format @username: message
        sender_username = self.clients[sender_socket]
        for client_socket, username in self.clients.items():
            if username == target_username:
                try:
                    client_socket.send(f"[Private message] {sender_username}: {message}".encode('utf-8'))
                    sender_socket.send(f"[Private message to {target_username}]: {message}".encode('utf-8'))
                    return
                except Exception as e:
                    # if client not in userlist, sender will get an error
                    print(f"Error sending private message: {e}")
                    self.remove_client(client_socket)
                    return
        sender_socket.send(f"User {target_username} not found.".encode('utf-8'))

    def remove_client(self, client_socket):
        # removes client from server and userlist
        if client_socket in self.clients:
            client_username = self.clients[client_socket]
            print(f"{client_username} has left the chat.")
            self.broadcast_message(client_socket, f"{client_username} has left the chat.", is_server_message=True)
            del self.clients[client_socket]
            client_socket.close()

if __name__ == "__main__":
    server = Server()
    threading.Thread(target=server.start).start()
