import socket
import threading
import hashlib
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# CONFIGURATION
HOST = '127.0.0.1' # Localhost for testing
PORT = 5555

# DIFFIE-HELLMAN CONSTANTS (Must match server)
P = 23
G = 5

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((HOST, PORT))
        print(f"[+] CONNECTED TO SERVER AT {HOST}:{PORT}")
    except ConnectionRefusedError:
        print("[-] CONNECTION FAILED. Is the server running?")
        sys.exit()

    # --- KEY EXCHANGE STEP ---
    # 1. Receive Server's Public Key
    server_public = int(client.recv(1024).decode())
    
    # 2. Generate Client Private & Public Keys
    client_private = 15 # In real life, this would be a large random integer
    client_public = (G ** client_private) % P
    
    # 3. Send Client Public Key to Server
    client.send(str(client_public).encode())
    
    # 4. Calculate Shared Secret
    shared_secret = (server_public ** client_private) % P
    
    # 5. Derive AES Key
    aes_key = hashlib.sha256(str(shared_secret).encode()).digest()
    print(f"[+] SECURE KEY DERIVED. CHANNEL ENCRYPTED.")
    print("--------------------------------------------")

    while True:
        try:
            msg = input("You: ")
            if not msg: break
            
            # Encrypt Message (AES-256-CBC)
            cipher = AES.new(aes_key, AES.MODE_CBC)
            ciphertext = cipher.encrypt(pad(msg.encode(), AES.block_size))
            
            # Send IV + Ciphertext (IV is needed for decryption)
            client.send(cipher.iv + ciphertext)
            
        except KeyboardInterrupt:
            print("\n[+] DISCONNECTING...")
            client.close()
            break

if __name__ == "__main__":
    start_client()
