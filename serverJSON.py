import socket
import threading
import json

class ServerJSON:
    def __init__(self, host='localhost', port=8088):  
        self.address = (host, port)
        self.clients = []
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
            self.clients.append(client_socket)
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        while True:
            try:
                # Receive and decode message
                message = client_socket.recv(1024).decode('utf-8')
                if message:
                    # Convert the received JSON string into a dictionary
                    json_data = json.loads(message)
                    print(f"Received JSON message: {json_data}")

                    # Broadcast the message to all clients
                    self.broadcast_message(client_socket, json_data)
            except Exception as e:
                print(f"Client disconnected or error occurred: {e}")
                self.clients.remove(client_socket)
                client_socket.close()
                break

    def broadcast_message(self, sender_socket, message_dict):
        # Convert the dictionary into a JSON string
        json_message = json.dumps(message_dict)
        for client in self.clients:
            if client != sender_socket:
                try:
                    # Send the JSON string to other clients
                    client.send(json_message.encode('utf-8'))
                except Exception as e:
                    print(f"Error sending message: {e}")
                    self.clients.remove(client)
                    client.close()

# Start the server
if __name__ == "__main__":
    server = ServerJSON()
    threading.Thread(target=server.start).start()

