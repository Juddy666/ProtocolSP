import socket
import threading

class Client:
    def __init__(self, host='localhost', port=8081):
        self.address = (host, port)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(self.address)

        self.get_unique_username()

        print(f"Connected to server at {self.address}")

    def get_unique_username(self):
        while True:
            username = input("Enter your username: ")
            self.client_socket.send(username.encode('utf-8'))  

            # Wait for the server's response on whether the username is accepted or not
            response = self.client_socket.recv(1024).decode('utf-8') 

            # If the username is taken, server sends a message, and we re-prompt for username
            if "Username is already taken" in response:
                print(response)  
            else:
                print(f"Username '{username}' accepted") 
                break

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

if __name__ == "__main__":
    client = Client()
    threading.Thread(target=client.receive_message).start()
    
    while True:
        message = input("Enter message (For direct message -> @username: message): ")
        client.send_message(message)