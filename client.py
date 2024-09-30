import socket
import threading
import json
import base64
import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

class ClientJSON:
    def __init__(self, host='localhost', port=8088):
        self.address = (host, port)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(self.address)
        print(f"Connected to server at {self.address}")
        self.counter = 0  # Initialize a counter to prevent replay attacks
        self.private_key, self.public_key = self.generate_rsa_key_pair()  # Generate RSA keys
        self.fingerprint = self.generate_fingerprint(self.public_key)  # Generate fingerprint
        self.known_clients = {}  # Dictionary to store known clients' public keys

        # Automatically send hello message upon connection
        self.send_hello_message()
        self.send_client_list_request()  # Request the client list immediately after connecting

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

    def generate_fingerprint(self, public_key):
        # Generate fingerprint as Base64Encode(SHA-256(exported RSA public key))
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(pem)
        fingerprint = base64.b64encode(digest.finalize()).decode()
        return fingerprint

    def sign_message(self, data):
        # Sign the data + counter using RSA-PSS
        message_bytes = json.dumps(data).encode() + str(self.counter).encode()
        signature = self.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32  # Salt length: 32 bytes
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    def send_message(self, message_dict):
        # Increment the counter for replay attack prevention
        self.counter += 1

        # Create the signed message structure
        signed_message = {
            "type": "signed_data",
            "data": message_dict,
            "counter": self.counter,
            "signature": self.sign_message(message_dict)
        }

        # Convert the dictionary to a JSON string and send it
        json_message = json.dumps(signed_message)
        self.client_socket.sendall(json_message.encode('utf-8'))

    def receive_message(self):
        buffer = ""
        while True:
            try:
                # Receive and decode message
                data = self.client_socket.recv(4096).decode('utf-8')
                if data:
                    buffer += data
                    # Attempt to parse JSON messages
                    while True:
                        try:
                            # Find the end of the JSON object
                            json_obj, index = json.JSONDecoder().raw_decode(buffer)
                            buffer = buffer[index:].lstrip()
                            self.handle_received_message(json_obj)
                        except json.JSONDecodeError:
                            # Not enough data to decode; break and wait for more
                            break
                else:
                    # Connection closed
                    print("Connection closed by the server.")
                    self.client_socket.close()
                    break
            except Exception as e:
                print(f"Error receiving message: {e}")
                print("Connection lost")
                self.client_socket.close()
                break

    def handle_received_message(self, json_data):
        # Extract the type of the message and handle accordingly
        message_type = json_data.get('type')
        if message_type == "client_list":
            self.handle_client_list_response(json_data)
        elif message_type == "signed_data":
            data_type = json_data.get('data', {}).get('type')
            if data_type == "public_chat":
                self.handle_public_chat(json_data)
            elif data_type == "chat":
                self.handle_private_chat(json_data)
            else:
                print("Unknown signed data type received.")
        else:
            print(f"Unknown message type received: {message_type}")

    def handle_client_list_response(self, response):
        # Extract client list from server response
        servers = response.get("servers", [])
        for server in servers:
            address = server.get("address")
            clients = server.get("clients", [])
            print(f"\n--- Client List from Server {address} ---")
            for client_pem in clients:
                client_public_key_pem = client_pem.encode()
                client_public_key = serialization.load_pem_public_key(client_public_key_pem, backend=default_backend())
                fingerprint = self.generate_fingerprint(client_public_key)
                print(f"Client Fingerprint: {fingerprint}")
                # Store the public key in known_clients
                self.known_clients[fingerprint] = client_public_key
            print("--- End of Client List ---\n")

    def handle_public_chat(self, json_data):
        sender_fingerprint = json_data.get('data', {}).get('sender')
        message = json_data.get('data', {}).get('message')
        print(f"\n[Public Chat] {sender_fingerprint}: {message}\n")

    def handle_private_chat(self, json_data):
        encrypted_data = json_data.get('data', {})
        # Verify the signature
        if not self.verify_signature(json_data):
            print("Invalid signature in private chat message.")
            return

        # Check if the message is intended for us
        participants = encrypted_data.get('participants', [])
        if self.fingerprint not in participants:
            # Not intended for us
            return

        try:
            # Since the server sends only one symm_key per recipient, access symm_keys[0]
            encrypted_symm_key_b64 = encrypted_data.get('symm_keys', [])[0]
            encrypted_symm_key = base64.b64decode(encrypted_symm_key_b64)

            # Decrypt the AES key
            aes_key = self.private_key.decrypt(
                encrypted_symm_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Decrypt the message
            iv = base64.b64decode(encrypted_data.get('iv'))
            ciphertext = base64.b64decode(encrypted_data.get('chat'))
            tag = base64.b64decode(encrypted_data.get('tag'))  # Retrieve the tag
            plaintext = self.aes_decrypt(ciphertext, aes_key, iv, tag)  # Pass the tag
            sender_fingerprint = participants[0]  # Sender is the first participant
            print(f"\n[Private Chat] {sender_fingerprint}: {plaintext}\n")
        except Exception as e:
            print(f"Error decrypting private chat message: {e}")

    def verify_signature(self, json_data):
        signature_b64 = json_data.get('signature')
        signature = base64.b64decode(signature_b64)
        counter = json_data.get('counter')
        data = json_data.get('data')
        message_bytes = json.dumps(data).encode() + str(counter).encode()

        # Get sender's public key
        participants = data.get('participants', [])
        if not participants:
            return False
        sender_fingerprint = participants[0]
        sender_public_key = self.get_public_key_by_fingerprint(sender_fingerprint)
        if not sender_public_key:
            print("Sender's public key not found. Requesting client list...")
            self.send_client_list_request()
            time.sleep(1)  # Wait for 1 second to allow the client list to update
            sender_public_key = self.get_public_key_by_fingerprint(sender_fingerprint)
            if not sender_public_key:
                print("Failed to retrieve sender's public key after updating client list.")
                return False

        try:
            sender_public_key.verify(
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

    def get_public_key_by_fingerprint(self, fingerprint):
        return self.known_clients.get(fingerprint)

    def send_hello_message(self):
        # Send the public key in PEM format
        pem_public_key = self.get_pem_public_key().decode()
        message_dict = {
            "type": "hello",
            "public_key": pem_public_key
        }
        self.send_message(message_dict)

    def send_public_chat(self, message):
        message_dict = {
            "type": "public_chat",
            "sender": self.fingerprint,
            "message": message
        }
        self.send_message(message_dict)

    def send_chat_message(self):
        # Get recipient's fingerprint and public key
        receiver_fingerprint = input("Enter the receiver's fingerprint: ")
        receiver_public_key = self.get_public_key_by_fingerprint(receiver_fingerprint)
        if not receiver_public_key:
            print("Receiver's public key not found.")
            return

        message = input("Enter the chat message: ")

        # Generate AES key and IV
        aes_key, iv = self.generate_aes_key_iv()

        # Encrypt the message using AES
        ciphertext, tag = self.aes_encrypt(message, aes_key, iv)

        # Encrypt the AES key with the recipient's public key
        encrypted_aes_key = receiver_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Base64 encode the encrypted AES key, IV, ciphertext, and tag
        encoded_encrypted_aes_key = base64.b64encode(encrypted_aes_key).decode()
        encoded_iv = base64.b64encode(iv).decode()
        encoded_ciphertext = base64.b64encode(ciphertext).decode()
        encoded_tag = base64.b64encode(tag).decode()

        message_dict = {
            "type": "chat",
            "destination_servers": [self.address[0]],  # For simplicity
            "iv": encoded_iv,
            "symm_keys": [encoded_encrypted_aes_key],
            "chat": encoded_ciphertext,
            "tag": encoded_tag,
            "participants": [
                self.fingerprint,
                receiver_fingerprint
            ]
        }

        self.send_message(message_dict)
        print("Encrypted chat message sent.")

    def generate_aes_key_iv(self):
        key = os.urandom(16)  # 128-bit AES key
        iv = os.urandom(16)   # 128-bit IV
        return key, iv

    def aes_encrypt(self, plaintext, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        tag = encryptor.tag
        return ciphertext, tag

    def aes_decrypt(self, ciphertext, key, iv, tag):
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()

    def send_client_list_request(self):
        message_dict = {
            "type": "client_list_request"
        }
        self.client_socket.sendall(json.dumps(message_dict).encode('utf-8'))

    def send_file_upload_request(self):
        # Placeholder for file upload functionality
        print("File upload functionality not implemented.")

# Start the client and allow interaction
if __name__ == "__main__":
    client = ClientJSON()  # Automatically sends hello message and requests client list
    threading.Thread(target=client.receive_message, daemon=True).start()
    time.sleep(0.25) #delay ensures correct order of client prompts
    while True:
        # Offer different types of messages to send
        print("\nChoose an option:")
        print("1. Send Public Chat message")
        print("2. Send Encrypted Chat message")
        print("3. Request Client List")
        print("4. Exit")

        option = input("Enter your choice: ")

        if option == "1":
            message = input("Enter the public chat message: ")
            client.send_public_chat(message)
        elif option == "2":
            client.send_chat_message()
        elif option == "3":
            client.send_client_list_request()
            time.sleep(0.25) #delay ensures correct ordering of client prompts
        elif option == "4":
            print("Exiting client.")
            client.client_socket.close()
            break
        else:
            print("Invalid option, please try again.")
