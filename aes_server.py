import socket
from OpenSSL import SSL
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.backends import default_backend

# === Configuration ===
PORT = 9000
AES_KEY = b"0123456789ABCDEF"     # 16-byte AES key (must match QNX side)
AES_IV  = b"1234567890ABCDEF"     # 16-byte IV
CMAC_KEY = AES_KEY                # Using same key for CMAC (or generate separate one)

# === SSL Setup ===
context = SSL.Context(SSL.TLSv1_2_METHOD)
context.use_privatekey_file("key.pem")
context.use_certificate_file("cert.pem")

server_socket = socket.socket()
ssl_server = SSL.Connection(context, server_socket)

ssl_server.bind(('0.0.0.0', PORT))
ssl_server.listen(1)
print(f"Waiting for secure connection on port {PORT}...")

conn, addr = ssl_server.accept()
conn.setblocking(True)
print(f"SSL Connection from {addr}")

try:
    while True:
        # Read data from QNX
        data = conn.recv(1024)
        if not data:
            break

        if len(data) <= 16:
            print("Invalid data: Too short to contain CMAC.")
            continue

        # Split: [ciphertext | cmac_tag]
        ciphertext = data[:-16]
        received_cmac = data[-16:]

        # === CMAC Verification ===
        cmac = CMAC(algorithms.AES(CMAC_KEY), backend=default_backend())
        cmac.update(ciphertext)
        try:
            cmac.verify(received_cmac)
            print("CMAC authentication:  Valid")
        except Exception as e:
            print(f"CMAC authentication failed: {e}")
            continue

        # === AES Decrypt ===
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding
        pad_len = padded_plaintext[-1]
        if pad_len > 16:
            print(" Padding error")
            continue
        plaintext = padded_plaintext[:-pad_len]

        print(f"Decrypted Message:\n{plaintext.decode(errors='ignore')}")

except KeyboardInterrupt:
    print("\nServer stopped by user.")
finally:
    conn.shutdown()
    conn.close()
