To install: Clone repository and install dependencies. Run login.py in a python IDE

Features overview:

Account system:
The user creates an account by providing a username and password.

This is hashed into shadow.txt by the SHA256 hashing algorithm.

The program then takes the hash of the username and password and generates a symmetric key from that hash.

This key is used to encrypt and decrypt files after user authentication.

It is stored as encrypted_symmetric_key.txt

The previous key is encrypted through the use of AES public key encryption.

This algorithm generates private_key.pem and public_key.pem 

The user must provide the correct username and password, the correct shadow file, 

the correct encrypted symmetric key, and the correct private_key.pem 

in order to access the encryption and decryption features of the program.

If any of these files are missing, the user cannot access the encrypted data. 
