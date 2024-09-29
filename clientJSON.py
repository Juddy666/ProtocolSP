import socket
import threading
import json
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

class ClientJSON:
    def __init__(self, host='localhost', port=8089):  
        self.address = (host, port)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(self.address)
        print(f"Connected to server at {self.address}")
        self.counter = 0  # Initialize a counter to prevent replay attacks
        self.private_key, self.public_key = self.generate_rsa_key_pair()  # Generate RSA keys

    def generate_rsa_key_pair(self):
        # Generate RSA private and public keys
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def get_pem_public_key(self):
        # Export the public key in PEM format
        pem_public_key = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_public_key

    def sign_message(self, data):
        # Simulate signing with a base64-encoded signature of the data + counter
        combined = f"{data}{self.counter}"
        signature = base64.b64encode(combined.encode()).decode()
        return signature

    def generate_aes_key_iv(self):
        key = os.urandom(32)  # 256-bit AES key
        iv = os.urandom(16)   # 128-bit IV
        return key, iv

    def aes_encrypt(self, plaintext, key, iv):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        # Pad the plaintext to ensure it's a multiple of the block size (16 bytes)
        padded_plaintext = plaintext + " " * (16 - len(plaintext) % 16)
        ciphertext = encryptor.update(padded_plaintext.encode()) + encryptor.finalize()
        return ciphertext

    def rsa_encrypt_aes_key(self, aes_key, recipient_public_key):
        encrypted_key = recipient_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key

    def load_public_key(self, pem_public_key):
        # Load the public key from the provided PEM string
        public_key = serialization.load_pem_public_key(pem_public_key, backend=default_backend())
        return public_key

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
        # Send the public key in PEM format
        pem_public_key = self.get_pem_public_key()
        message_dict = {
            "type": "hello",
            "public_key": pem_public_key.decode()  # Send the public key
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
        # Get the public RSA key in PEM format (this is the key we will use for encryption)
        pem_public_key = self.get_pem_public_key()

        # Load the public key for encryption
        public_key = self.load_public_key(pem_public_key)
        
        # 1. Generate AES key and IV
        aes_key, iv = self.generate_aes_key_iv()
        
        # 2. Encrypt the chat message using AES
        message = input("Enter the chat message to encrypt: ")
        encrypted_message = self.aes_encrypt(message, aes_key, iv)
        
        # 3. Encrypt the AES key with the RSA public key
        encrypted_aes_key = self.rsa_encrypt_aes_key(aes_key, public_key)
        
        # 4. Encode IV, AES key, and encrypted chat message in base64
        encoded_iv = base64.b64encode(iv).decode()
        encoded_aes_key = base64.b64encode(encrypted_aes_key).decode()
        encoded_encrypted_message = base64.b64encode(encrypted_message).decode()
        
        # 5. Prepare the JSON message structure
        message_dict = {
            "type": "chat",
            "destination_servers": ["example_destination_server"],  # Placeholder for actual server addresses
            "iv": encoded_iv,
            "symm_keys": [encoded_aes_key],  # Only one recipient in this example
            "chat": encoded_encrypted_message
        }
        
        # 6. Send the message
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
