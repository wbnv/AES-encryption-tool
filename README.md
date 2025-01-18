# AES Encryption Tool

This repository contains a simple Python-based tool for encrypting and decrypting messages using AES-256 encryption in CBC mode. The tool uses PBKDF2 for key derivation and Base64 encoding for storing the encrypted output.

---

## Features
- **AES-256 Encryption**: Encrypts plaintext messages securely with a 256-bit key.
- **Key Derivation**: Derives keys using PBKDF2 with SHA-256 hashing.
- **CBC Mode**: Ensures secure block encryption with a random Initialization Vector (IV).
- **Base64 Encoding**: Combines and encodes the salt, IV, and ciphertext into a single string for easy sharing.

---

## How It Works
1. **Encryption**:
   - The tool takes a plaintext message and a password as input.
   - Generates a random salt and IV.
   - Derives an AES encryption key from the password and salt.
   - Encrypts the message and outputs a Base64-encoded string containing the salt, IV, and ciphertext.

2. **Decryption**:
   - The tool takes an encrypted message (Base64 string) and password as input.
   - Extracts the salt, IV, and ciphertext from the string.
   - Derives the AES key using the password and salt.
   - Decrypts the ciphertext to retrieve the original plaintext.

---

## Usage

### Requirements
- Python 3.6+
- Install the required library:
  ```bash
  pip install cryptography
  ```

### Running the Tool
1. Clone the repository:
   ```bash
   git clone https://github.com/your_username/AES-encryption-tool.git
   cd AES-encryption-tool
   ```

2. Run the script:
   ```bash
   python encryption_tool.py
   ```

3. Select an option:
   - **Option 1**: Encrypt a message.
   - **Option 2**: Decrypt a message.
   - **Option 3**: Exit the tool.

### Example
#### Encrypting a Message
1. Choose option `1` (Encrypt a message).
2. Enter the plaintext message: `Hello, World!`
3. Enter a password: `mypassword`
4. The tool outputs:
   ```
   Encrypted Message: TjC9pj2kAwpFuTZISau1PZHWC...
   ```

#### Decrypting a Message
1. Choose option `2` (Decrypt a message).
2. Enter the encrypted message: `TjC9pj2kAwpFuTZISau1PZHWC...`
3. Enter the password: `mypassword`
4. The tool outputs:
   ```
   Decrypted Message: Hello, World!
   ```

---

## Example Use Case
You can encourage users to post their encrypted messages (with passwords) in your comment section, allowing others to decrypt them for fun and learning. Ensure participants avoid using sensitive information.

---

## How to Contribute
1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add your message here"
   ```
4. Push the branch:
   ```bash
   git push origin feature/your-feature-name
   ```
5. Open a pull request.

---

## Disclaimer
This tool is intended for educational purposes only. Do not use it to encrypt or share sensitive information. Always follow best practices for securing sensitive data in production environments.

---

## License
This project is licensed under the MIT License. See the LICENSE file for details.
