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
                client_socket.send("Please choose another one.\n".encode('utf-8'))
            else:
                self.clients[client_socket] = username
                print(f"Username '{username}' added for client {client_socket.getpeername()}")
                self.broadcast_message(client_socket, f"{username} has joined the chat!")
                self.send_online_clients()
                break

        threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        username = self.clients[client_socket]
        while True:
            try:
                message = client_socket.recv(1024).decode('utf-8')
                if message:
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
        for client, username in self.clients.items():
            if client != sender_socket:
                try:
                    client.send(message.encode('utf-8'))
                except Exception as e:
                    print(f"Error sending message to {username}: {e}")
                    client.close()
                    self.clients.pop(client)

    def send_online_clients(self):
        online_clients = "Online clients: " + ", ".join(self.clients.values())
        self.broadcast_message(None, online_clients)

if __name__ == "__main__":
    server = Server()
    threading.Thread(target=server.start).start()
