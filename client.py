import socket
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def get_derived_key(shared_key, salt):
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'handshake data',
        backend=default_backend()
    )
    return kdf.derive(shared_key)

def start_client():
    host = '127.0.0.1'
    port = 5555

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print("[*] Connected to server.")

    # 1. Handshake: Receive Params & Server Pub Key
    len_params = int.from_bytes(client_socket.recv(4), 'big')
    pem_params = client_socket.recv(len_params)
    parameters = serialization.load_pem_parameters(pem_params, backend=default_backend())

    len_server_pub = int.from_bytes(client_socket.recv(4), 'big')
    server_pub_bytes = client_socket.recv(len_server_pub)
    server_public_key = serialization.load_pem_public_key(server_pub_bytes, backend=default_backend())

    # 2. Generate Client Keys & Send Public Key
    client_private_key = parameters.generate_private_key()
    client_public_key = client_private_key.public_key()
    
    pem_public = client_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    client_socket.sendall(len(pem_public).to_bytes(4, 'big'))
    client_socket.sendall(pem_public)

    # 3. Compute Shared Secret
    shared_key = client_private_key.exchange(server_public_key)
    salt = b'\x00' * 16 
    aes_key = get_derived_key(shared_key, salt)
    print(f"[*] Secure Channel Established. AES Key Derived.")

    # 4. Chat Loop
    while True:
        try:
            # SEND
            msg = input("You: ")
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_msg = encryptor.update(msg.encode()) + encryptor.finalize()

            client_socket.sendall(iv)
            client_socket.sendall(len(encrypted_msg).to_bytes(4, 'big'))
            client_socket.sendall(encrypted_msg)

            # RECEIVE
            iv = client_socket.recv(16)
            if not iv: break
            enc_msg_len = int.from_bytes(client_socket.recv(4), 'big')
            encrypted_msg = client_socket.recv(enc_msg_len)

            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_msg = decryptor.update(encrypted_msg) + decryptor.finalize()
            print(f"Server: {decrypted_msg.decode()}")
        except Exception as e:
            print(f"[-] Error: {e}")
            break
    client_socket.close()

if __name__ == "__main__":
    start_client()
