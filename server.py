import socket
import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def get_derived_key(shared_key, salt):
    # Derive a 32-byte AES key from the DH shared secret
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'handshake data',
        backend=default_backend()
    )
    return kdf.derive(shared_key)

def start_server():
    host = '127.0.0.1'
    port = 5555

    # 1. Generate Diffie-Hellman Parameters & Server Keys
    print("[*] Generating DH parameters (this may take a second)...")
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    server_private_key = parameters.generate_private_key()
    server_public_key = server_private_key.public_key()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"[*] Listening on {host}:{port}")

    conn, addr = server_socket.accept()
    print(f"[*] Connection from {addr}")

    # 2. Handshake: Send Pub Key & Params -> Receive Client Pub Key
    # Serialize parameters and public key to send to client
    pem_params = parameters.parameter_bytes(encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3)
    pem_public = server_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    conn.sendall(len(pem_params).to_bytes(4, 'big'))
    conn.sendall(pem_params)
    conn.sendall(len(pem_public).to_bytes(4, 'big'))
    conn.sendall(pem_public)

    # Receive Client Public Key
    len_client_pub = int.from_bytes(conn.recv(4), 'big')
    client_pub_bytes = conn.recv(len_client_pub)
    client_public_key = serialization.load_pem_public_key(client_pub_bytes, backend=default_backend())

    # 3. Compute Shared Secret & Derive AES Key
    shared_key = server_private_key.exchange(client_public_key)
    salt = b'\x00' * 16 # In prod, exchange a random salt
    aes_key = get_derived_key(shared_key, salt)
    print(f"[*] Secure Channel Established. AES Key Derived.")

    # 4. Chat Loop (Decrypt -> Print -> Input -> Encrypt -> Send)
    while True:
        try:
            # RECEIVE
            iv = conn.recv(16) # Receive IV
            if not iv: break
            enc_msg_len = int.from_bytes(conn.recv(4), 'big')
            encrypted_msg = conn.recv(enc_msg_len)

            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_msg = decryptor.update(encrypted_msg) + decryptor.finalize()
            print(f"Client: {decrypted_msg.decode()}")

            # SEND
            msg = input("You: ")
            iv = os.urandom(16) # New IV for every message
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_msg = encryptor.update(msg.encode()) + encryptor.finalize()
            
            conn.sendall(iv)
            conn.sendall(len(encrypted_msg).to_bytes(4, 'big'))
            conn.sendall(encrypted_msg)
        except Exception as e:
            print(f"[-] Error: {e}")
            break
    conn.close()

if __name__ == "__main__":
    start_server()
