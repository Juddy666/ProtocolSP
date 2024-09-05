import socket
import threading

class Client:
    def __init__(self, host='localhost', port=8081):
        self.address = (host, port)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(self.address)

        # Get the username from the user
        self.username = input("Enter your username: ")
        self.client_socket.send(self.username.encode('utf-8'))  # Send the username to the server

        print(f"Connected to server at {self.address}")

    def send_message(self, message):
        self.client_socket.send(message.encode('utf-8'))
        print(f"Sent message: {message}")

    def receive_message(self):
        while True:
            try:
                message = self.client_socket.recv(1024).decode('utf-8')
                if message:
                    print(f"Received message: {message}")
            except Exception as e:
                print(f"Error receiving message: {e}")
                print("Connection lost")
                self.client_socket.close()
                break

# Start the client and allow interaction
if __name__ == "__main__":
    client = Client()
    threading.Thread(target=client.receive_message).start()
    
    while True:
        message = input("Enter message: ")
        client.send_message(message)
