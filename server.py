import socket
import threading

class Server:
    def __init__(self, host='localhost', port=8081):
        self.address = (host, port)
        self.clients = []

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(self.address)
        server_socket.listen(5)
        print(f"Server started at {self.address}")

        while True:
            client_socket, client_address = server_socket.accept()
            print(f"Client {client_address} connected")
            self.clients.append(client_socket)
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        while True:
            try:
                message = client_socket.recv(1024).decode('utf-8')
                if message:
                    print(f"Received message from client: {message}")
                    self.broadcast_message(client_socket, message)
            except Exception as e:
                print(f"Error: {e}")
                self.clients.remove(client_socket)
                client_socket.close()
                break

    def broadcast_message(self, sender_socket, message):
        for client in self.clients:
            if client != sender_socket:
                try:
                    print(f"Sending message to client: {message}")
                    client.send(message.encode('utf-8'))
                except Exception as e:
                    print(f"Error sending message: {e}")
                    client.close()
                    self.clients.remove(client)

# Start the server
if __name__ == "__main__":
    server = Server()
    threading.Thread(target=server.start).start()
