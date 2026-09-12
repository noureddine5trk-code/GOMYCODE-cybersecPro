"""
server.py — Secure communication channel (server-side)

HYBRID RSA + AES encryption:
1. The server generates an RSA key pair and sends its PUBLIC key to the client. 
2. The client generates a random AES key (session key), encrypts it with
the server's RSA public key, and then sends it. 
3. The server decrypts this AES key using its RSA PRIVATE key. 
4. From this point on, all messages are encrypted/decrypted using AES
(RSA is too slow to encrypt a continuous stream of messages;
AES is fast, which is precisely why it is used after
the key exchange).

AES mode used: EAX. Unlike a "simple" mode like CBC, EAX
encrypts AND authenticates: if a message is modified in transit,
decryption fails instead of silently producing corrupted text.
This is important for the "test" part of the instructions.
"""
import socket
import threading

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

from netutils import send_msg, recv_msg

HOST = "0.0.0.0"
PORT = 5050


def do_handshake(conn: socket.socket) -> bytes:
    """Exchanges keys and returns the shared AES session key.."""
    rsa_key = RSA.generate(2048)
    public_key = rsa_key.publickey().export_key()

    send_msg(conn, public_key)
    print("[+] RSA public key sent to the client")

    encrypted_session_key = recv_msg(conn)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    session_key = cipher_rsa.decrypt(encrypted_session_key)
    print("[+] AES session key received and decrypted")

    return session_key


def encrypt_message(session_key: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    # nonce (16 bytes) + tag (16 bytes) + ciphertext, sent as a single message
    return cipher.nonce + tag + ciphertext


def decrypt_message(session_key: bytes, packet: bytes) -> bytes:
    nonce, tag, ciphertext = packet[:16], packet[16:32], packet[32:]
    cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    # decrypt_and_verify raises a ValueError if the message has been tampered with.
    return cipher.decrypt_and_verify(ciphertext, tag)


def receive_loop(conn: socket.socket, session_key: bytes) -> None:
    while True:
        try:
            packet = recv_msg(conn)
        except ConnectionError:
            print("\n[!] Client disconnected")
            break
        try:
            message = decrypt_message(session_key, packet)
            print(f"\nClient> {message.decode()}\nServeur> ", end="", flush=True)
        except ValueError:
            print("\n[!] ALERT: message rejected (invalid integrity, possible tampering)")


def main() -> None:
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(1)
    print(f"[+] Server listening on {HOST}:{PORT}...")

    conn, addr = server_sock.accept()
    print(f"[+] Connection from {addr}")

    session_key = do_handshake(conn)

    threading.Thread(target=receive_loop, args=(conn, session_key), daemon=True).start()

    try:
        while True:
            text = input("Server> ")
            send_msg(conn, encrypt_message(session_key, text.encode()))
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        conn.close()
        server_sock.close()


if __name__ == "__main__":
    main()
