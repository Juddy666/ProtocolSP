import socket
import threading
import json
import base64

class ClientJSON:
    def __init__(self, host='localhost', port=8089):  
        self.address = (host, port)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(self.address)
        print(f"Connected to server at {self.address}")
        self.counter = 0  # Initialize a counter to prevent replay attacks

    def sign_message(self, data):
        # For now, simulate signing with a base64-encoded signature of the data + counter
        combined = f"{data}{self.counter}"
        signature = base64.b64encode(combined.encode()).decode()
        return signature

    def send_message(self, message_dict):
        # Increment the counter for replay attack prevention
        self.counter += 1

        # Create the signed message structure
        signed_message = {
            "type": "signed_data",
            "data": message_dict,
            "counter": self.counter,
            "signature": self.sign_message(str(message_dict))
        }

        # Convert the dictionary to a JSON string and send it
        json_message = json.dumps(signed_message)
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
                    
                    # Extract the type of the message and handle accordingly
                    Mtype = json_data.get('data', {}).get('type')
                    MSender = json_data.get('data', {}).get('sender')
                    MPlaintext = json_data.get('data', {}).get('message')
                    
                    if Mtype == "public_chat":
                        # Original way of handling public messages
                        print(f"Public Chat from {MSender}: {MPlaintext}")
                    elif Mtype == "chat":
                        print("Chat message received but not implemented")
                    else:
                        print("Invalid or unknown message type")
                        
            except Exception as e:
                print(f"Error receiving message: {e}")
                print("Connection lost")
                self.client_socket.close()
                break

    def send_hello_message(self):
        message_dict = {
            "type": "hello",
            "public_key": "example_public_key"
        }
        self.send_message(message_dict)

    def send_public_chat(self, message):
        message_dict = {
            "type": "public_chat",
            "sender": "Jeff",
            "message": message
        }
        self.send_message(message_dict)

    def send_chat_message(self):
        message_dict = {
            "type": "chat",
            "destination_servers": ["example_destination_server"],
            "iv": "example_base64_iv",
            "symm_keys": ["example_base64_aes_key"],
            "chat": "example_base64_encrypted_message"
        }
        self.send_message(message_dict)

    def send_client_list_request(self):
        message_dict = {
            "type": "client_list_request"
        }
        self.send_message(message_dict)

# Start the client and allow interaction
if __name__ == "__main__":
    client = ClientJSON()
    threading.Thread(target=client.receive_message).start()

    while True:
        # Offer different types of messages to send
        print("Choose an option:")
        print("1. Send Hello message")
        print("2. Send Public Chat message")
        print("3. Send Encrypted Chat message")
        print("4. Request Client List")
        
        option = input("Enter your choice: ")

        if option == "1":
            client.send_hello_message()
        elif option == "2":
            message = input("Enter the public chat message: ")
            client.send_public_chat(message)
        elif option == "3":
            client.send_chat_message()
        elif option == "4":
            client.send_client_list_request()
        else:
            print("Invalid option, please try again.")
