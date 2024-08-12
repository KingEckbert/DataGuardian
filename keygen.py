import hashlib
import json
import os
import bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7



def generate_asymmetric_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Get the corresponding public key
    public_key = private_key.public_key()

    return private_key, public_key


def asymmetric_encrypt(message, public_key):
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message


# Function to decrypt a message using the private key
def asymmetric_decrypt(encrypted_message, private_key):
    try:
        original_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return original_message
    except Exception as e:
        print(f"Error during asymmetric decryption: {e}")
        return None


def generate_symmetric_key():
    return os.urandom(32)  # 32 bytes = 256 bits


def symmetric_encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data


def symmetric_decrypt(data, key):
    iv = data[:16]
    encrypted_data = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data


def decrypt_credentials(decrypted_symmetric_key):
    try:
        # Read the encrypted data from the file
        with open('shadow.txt', 'rb') as file:
            encrypted_data = file.read()

        # Decrypt the data using the symmetric key
        decrypted_data = symmetric_decrypt(encrypted_data, decrypted_symmetric_key)

        # Deserialize the decrypted data
        credential_data = json.loads(decrypted_data.decode('utf-8'))
        print(f'Credential Decryption Success')
        return credential_data
    except Exception as e:
        print(f"Error during decryption: {e}")
        return None


def hash_username(username):
    hashed_username = hashlib.sha256(username.encode('utf-8'))
    return hashed_username.digest()


def save_to_file(data, filename):
    with open(filename, 'wb') as file:
        file.write(data)


def verify_password(pw, hpw):
    return bcrypt.checkpw(pw.encode(), hpw)


# stores a hashed version of password
def hash_password(pw):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pw.encode('utf-8'), salt)


