# AES Encryption Tool

This project demonstrates the use of AES encryption in CBC mode with PBKDF2-based key derivation. The tool allows users to encrypt and decrypt messages securely by deriving keys from passwords and using random salts and IVs.

## Features
- **AES-256 Encryption**: Encrypts messages using a 256-bit key derived from user-provided passwords.
- **Key Derivation**: Uses PBKDF2-HMAC-SHA256 to derive keys securely from passwords.
- **Base64 Encoding**: Produces a single, shareable string containing the salt, IV, and ciphertext.

## How It Works
1. The user enters a message and password to encrypt.
2. The tool outputs a Base64-encoded string containing the encrypted data.
3. The user (or another person with the password) can decrypt the string to recover the original message.

## Future Plans
- Implement AES-GCM for authenticated encryption.
- Build a web or GUI-based version of the tool.
- Package the tool for distribution.

## Running the Project
1. Clone the repository.
2. Install the required dependencies: [pip install cryptography]
3. Run the script:

   
