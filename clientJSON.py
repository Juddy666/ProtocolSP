import socket
import threading
import json

class ClientJSON:
    def __init__(self, host='localhost', port=8088):  # Use your Wi-Fi IP and port 8088
        self.address = (host, port)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(self.address)
        print(f"Connected to server at {self.address}")

    def send_message(self, message_dict):
        # Convert the dictionary to a JSON string
        json_message = json.dumps(message_dict)
        self.client_socket.send(json_message.encode('utf-8'))
        print(f"Sent JSON message: {json_message}")

    def receive_message(self):
        while True:
            try:
                # Receive and decode message
                message = self.client_socket.recv(1024).decode('utf-8')
                if message:
                    # Convert the received JSON string into a dictionary
                    json_data = json.loads(message)
                    print(f"Received JSON message: {json_data}")
            except Exception as e:
                print(f"Error receiving message: {e}")
                print("Connection lost")
                self.client_socket.close()
                break

# Start the client and allow interaction
if __name__ == "__main__":
    client = ClientJSON()
    threading.Thread(target=client.receive_message).start()
    
    while True:
        # Input message and wrap it into a dictionary
        message = input("Enter message: ")
        message_dict = {"message": message, "from": "client", "height": "186"}
        client.send_message(message_dict)

