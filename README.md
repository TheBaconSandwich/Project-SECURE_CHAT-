# SECURE_CHAT

A Python implementation of an encrypted chat client/server using **AES-256** for message encryption and **Diffie-Hellman (DH)** for secure key exchange.

## Features
- **Diffie-Hellman Key Exchange:** Securely negotiates a shared secret over an open channel.
- **AES-256 Encryption:** Derives a 32-byte key from the shared secret to encrypt messages.
- **CFB Mode:** Uses Cipher Feedback mode with a random IV for every message.

## Usage
1. Install dependencies: `pip install cryptography`
2. Start Server: `python server.py`
3. Start Client: `python client.py`
