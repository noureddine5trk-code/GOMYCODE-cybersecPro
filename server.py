"""
server.py — the encrypted chat server (Phase 1).

Hybrid RSA + AES encryption:
  1. The server generates an RSA key pair and sends its PUBLIC key to
     the client.
  2. The client generates a random AES key (the session key), encrypts
     it with the server's public key, and sends it back.
  3. The server decrypts that session key with its PRIVATE key.
  4. From here on, every message is encrypted/decrypted with AES — RSA
     is far too slow to encrypt a continuous stream of messages, which
     is exactly why it's only used once, to exchange the AES key.

AES mode: EAX. Unlike a plain mode such as CBC, EAX both encrypts and
authenticates: if a message is altered in transit, decryption fails
instead of silently returning corrupted data.

This server doesn't care whether the other end is a terminal
(client.py) or a browser (web_client.py) — the protocol is identical
either way.
"""
import socket
import threading

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from netutils import send_msg, recv_msg
from crypto_core import encrypt_message, decrypt_message
import config

HOST = config.HOST
PORT = config.PORT


def do_handshake(conn: socket.socket) -> bytes:
    """Exchange keys and return the shared AES session key."""
    rsa_key = RSA.generate(2048)
    public_key = rsa_key.publickey().export_key()

    send_msg(conn, public_key)
    print("[+] Sent RSA public key to client")

    encrypted_session_key = recv_msg(conn)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    session_key = cipher_rsa.decrypt(encrypted_session_key)
    print("[+] Received and decrypted the AES session key")

    return session_key


def receive_loop(conn: socket.socket, session_key: bytes) -> None:
    while True:
        try:
            packet = recv_msg(conn)
        except ConnectionError:
            print("\n[!] Client disconnected")
            break
        try:
            message = decrypt_message(session_key, packet)
            print(f"\nClient> {message.decode()}\nServer> ", end="", flush=True)
        except ValueError:
            print("\n[!] ALERT: message rejected (integrity check failed, possible tampering)")


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
