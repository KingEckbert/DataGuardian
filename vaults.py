import tkinter as tk
from tkinter import filedialog, messagebox
import os
from keygen import symmetric_encrypt, symmetric_decrypt


def encrypt_file(file_path, key):
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
        print("Original Data:", file_data[:64])  # Print first 64 bytes for brevity
        encrypted_data = symmetric_encrypt(file_data, key)
        print("Encrypted Data:", encrypted_data[:64])  # Print first 64 bytes for brevity
        encrypted_file_path = file_path + '.enc'
        with open(encrypted_file_path, 'wb') as file:
            file.write(encrypted_data)
        print("File encrypted successfully!")
    except Exception as e:
        print(f"Encryption Error: {str(e)}")


def decrypt_file(encrypted_file_path, key):
    try:
        with open(encrypted_file_path, 'rb') as file:
            encrypted_data = file.read()
        print("Encrypted Data Read:", encrypted_data[:64])  # Print first 64 bytes for brevity
        decrypted_data = symmetric_decrypt(encrypted_data, key)
        print("Decrypted Data:", decrypted_data[:64])  # Print first 64 bytes for brevity
        decrypted_file_path = encrypted_file_path.replace('.enc', '')
        with open(decrypted_file_path, 'wb') as file:
            file.write(decrypted_data)
        print("File decrypted successfully!")
    except Exception as e:
        print(f"Decryption Error: {str(e)}")


def browse_vault_file():
    return filedialog.askopenfilename()
