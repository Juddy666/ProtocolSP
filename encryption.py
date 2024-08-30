import os
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

# Generate RSA key pair (for demonstration purposes)
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Encrypt message using RSA with OAEP
def rsa_encrypt(public_key, message):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    encrypted_message = cipher_rsa.encrypt(message)
    return b64encode(encrypted_message)

# Decrypt message using RSA with OAEP
def rsa_decrypt(private_key, encrypted_message):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    decrypted_message = cipher_rsa.decrypt(b64decode(encrypted_message))
    return decrypted_message

# Sign message using RSA with PSS
def rsa_sign(private_key, message):
    rsa_key = RSA.import_key(private_key)
    h = SHA256.new(message)
    signature = pss.new(rsa_key, salt_bytes=32).sign(h)
    return b64encode(signature)

# Verify RSA signature
def rsa_verify(public_key, message, signature):
    rsa_key = RSA.import_key(public_key)
    h = SHA256.new(message)
    verifier = pss.new(rsa_key, salt_bytes=32)
    try:
        verifier.verify(h, b64decode(signature))
        return True
    except (ValueError, TypeError):
        return False

# Encrypt message using AES in GCM mode
def aes_encrypt(aes_key, message):
    iv = get_random_bytes(16)  # Generate random IV
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message)
    return b64encode(iv + ciphertext + tag)

# Decrypt message using AES in GCM mode
def aes_decrypt(aes_key, encrypted_message):
    encrypted_message = b64decode(encrypted_message)
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:-16]
    tag = encrypted_message[-16:]
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return decrypted_message

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <message>")
        return

    message = sys.argv[1].encode('utf-8')

    # Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    # RSA Encryption
    encrypted_message_rsa = rsa_encrypt(public_key, message)
    print(f"Encrypted Message (RSA): {encrypted_message_rsa.decode('utf-8')}")

    # RSA Signing
    signature = rsa_sign(private_key, message)
    print(f"Signature (RSA): {signature.decode('utf-8')}")

    # AES Encryption
    aes_key = get_random_bytes(32)  # Generate a 256-bit AES key
    encrypted_message_aes = aes_encrypt(aes_key, message)
    print(f"Encrypted Message (AES): {encrypted_message_aes.decode('utf-8')}")

    # Simulate receiver decrypting the RSA message
    decrypted_message_rsa = rsa_decrypt(private_key, encrypted_message_rsa)
    print(f"Decrypted Message (RSA): {decrypted_message_rsa.decode('utf-8')}")

    # Simulate receiver verifying the signature
    is_valid_signature = rsa_verify(public_key, message, signature)
    print(f"Signature valid: {is_valid_signature}")

    # Simulate receiver decrypting the AES message
    decrypted_message_aes = aes_decrypt(aes_key, encrypted_message_aes)
    print(f"Decrypted Message (AES): {decrypted_message_aes.decode('utf-8')}")

if __name__ == "__main__":
    main()
