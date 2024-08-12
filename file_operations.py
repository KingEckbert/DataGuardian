import base64
import json
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from tkinter import filedialog


def browse_file(path_var):
    initial_dir = os.getcwd()
    file_path = filedialog.askopenfilename(initialdir=initial_dir)
    if file_path:
        print(f"Selected file: {file_path}")
        path_var.set(file_path)  # Update the StringVar
    else:
        print("No file selected")


def save_keys_to_file(private_key, public_key, private_key_filename="private_key.pem",
                      public_key_filename="public_key.pem"):
    # Serialize the private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize the public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save the private key to a file
    with open(private_key_filename, 'wb') as private_file:
        private_file.write(private_pem)

    # Save the public key to a file
    with open(public_key_filename, 'wb') as public_file:
        public_file.write(public_pem)


def save_encrypted_symmetric_key_to_file(encrypted_symmetric_key, encrypted_key_filename):
    # Convert the encrypted key to a base64 encoded string for file storage
    encoded_key = base64.b64encode(encrypted_symmetric_key).decode('utf-8')

    # Save the encoded key as JSON for easy retrieval and decoding
    with open(encrypted_key_filename, 'w') as file:
        json.dump({'encrypted_key': encoded_key}, file)

    print(f"Encrypted symmetric key saved to {encrypted_key_filename}")


def read_private_key_from_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            private_key = serialization.load_pem_private_key(
                file.read(),
                password=None,
                backend=default_backend()
            )
            return private_key
    except Exception as e:
        print(f"Error reading private key from file: {e}")
        return None


def read_symmetric_key_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            encoded_key = data['encrypted_key']
            symmetric_key = base64.b64decode(encoded_key)
            return symmetric_key
    except Exception as e:
        print(f"Error reading symmetric key from file: {e}")
        return None
