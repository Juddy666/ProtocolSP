from encryption import generate_rsa_keys, rsa_encrypt, rsa_decrypt, rsa_sign, rsa_verify, aes_encrypt, aes_decrypt
import json
import os
import sys
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256  # Import SHA256
from Crypto.Random import get_random_bytes  # Import get_random_bytes
from base64 import b64encode

# Assuming your existing encryption and signing functions are already imported

def create_chat_json(private_key, public_keys, message, counter, sender_fingerprint, destination_servers):
    # Encrypt the message with AES
    aes_key = get_random_bytes(32)  # Generate a 256-bit AES key
    encrypted_message_aes = aes_encrypt(aes_key, message.encode('utf-8'))

    # Encrypt the AES key with each recipient's public RSA key
    encrypted_symm_keys = [rsa_encrypt(pub_key, aes_key).decode('utf-8') for pub_key in public_keys]

    # Create the list of participants' fingerprints including the sender's fingerprint
    participants = [sender_fingerprint] + [get_fingerprint(pub_key) for pub_key in public_keys]

    # Create the chat object
    chat_obj = {
        "participants": [b64encode(fingerprint.encode('utf-8')).decode('utf-8') for fingerprint in participants],
        "message": encrypted_message_aes.decode('utf-8')
    }

    # Create the full data object
    data = {
        "type": "chat",
        "destination_servers": destination_servers,
        "iv": b64encode(get_random_bytes(16)).decode('utf-8'),  # AES IV is not needed as it's included in encrypted_message_aes
        "symm_keys": encrypted_symm_keys,
        "chat": chat_obj
    }

    # Convert the data object to JSON and sign it
    data_json = json.dumps(data, separators=(',', ':')).encode('utf-8')
    signature = rsa_sign(private_key, data_json).decode('utf-8')

    # Build the final JSON object to be sent
    final_json = {
        "type": "signed_data",
        "data": json.loads(data_json.decode('utf-8')),
        "counter": counter,
        "signature": signature
    }

    return json.dumps(final_json, separators=(',', ':'))

def get_fingerprint(public_key):
    # Calculate SHA-256 hash of the exported public key to get the fingerprint
    sha256 = SHA256.new(public_key)  # No need to encode, since public_key is already bytes
    return sha256.hexdigest()

# Example usage
if __name__ == "__main__":
    message = "Hello, this is a secure message."
    counter = 12345

    # Generate RSA keys for demonstration (in practice, these would be loaded)
    private_key, public_key = generate_rsa_keys()
    recipient_public_keys = [public_key]  # Assuming a single recipient for simplicity

    # Calculate the sender's fingerprint
    sender_fingerprint = get_fingerprint(public_key)

    # Define the destination servers (placeholder addresses)
    destination_servers = ["server1.example.com", "server2.example.com"]

    # Create the chat JSON message
    chat_json = create_chat_json(private_key, recipient_public_keys, message, counter, sender_fingerprint, destination_servers)
    print(chat_json)
