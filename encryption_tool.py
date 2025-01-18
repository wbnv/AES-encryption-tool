from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
import base64
import os

def encrypt_message(plaintext, password):
    # Generate a random 16-byte salt
    salt = os.urandom(16)

    # Derive a 32-byte key from the password and salt using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Generate a random 16-byte IV (Initialization Vector)
    iv = os.urandom(16)

    # Initialize the cipher with AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Pad the plaintext to be a multiple of the block size (16 bytes)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # Encrypt the padded plaintext
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Combine the salt, IV, and encrypted data into one encoded string
    combined = salt + iv + encrypted_data
    encrypted_message = base64.b64encode(combined).decode()
    return encrypted_message

def decrypt_message(encrypted_message, password):
    # Decode the Base64-encoded string
    combined = base64.b64decode(encrypted_message)

    # Extract the salt, IV, and ciphertext
    salt = combined[:16]  # First 16 bytes
    iv = combined[16:32]  # Next 16 bytes
    ciphertext = combined[32:]  # Remaining bytes

    # Derive the key from the password and salt using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Initialize the cipher for decryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove the padding to retrieve the original plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()

if __name__ == "__main__":
    try:
        while True:
            print("\nAES Encryption/Decryption Tool")
            print("1. Encrypt a message")
            print("2. Decrypt a message")
            print("3. Exit")
            choice = input("Choose an option (1, 2, or 3): ")

            if choice == "1":
                # Encryption mode
                plaintext = input("Enter the message to encrypt: ")
                password = input("Enter a password for encryption: ")
                encrypted_message = encrypt_message(plaintext, password)
                print(f"\nEncrypted Message: {encrypted_message}")
            
            elif choice == "2":
                # Decryption mode
                encrypted_message = input("Enter the encrypted message: ")
                password = input("Enter the password for decryption: ")
                decrypted_message = decrypt_message(encrypted_message, password)
                print(f"\nDecrypted Message: {decrypted_message}")
            
            elif choice == "3":
                # Exit the program
                print("Goodbye!")
                break

            else:
                print("Invalid option. Please choose 1, 2, or 3.")

    except Exception as e:
        print(f"An error occurred: {e}")




def decrypt_message(encrypted_message, password):
        # Decode the Base64-encoded string
        encrypted_data = base64.b64decode(encrypted_message)

        # Extract the salt, IV, and ciphertext
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]  
        cipertext = encrypted_data[32:]

        # Derive the key from the password and salt using PBKDF2

        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())

        # Initalize the cipher for decryption

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode()

        



