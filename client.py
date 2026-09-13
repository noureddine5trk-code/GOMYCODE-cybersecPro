"""
client.py — terminal client for the encrypted chat.

See server.py for the full explanation of the handshake and encryption
scheme (hybrid RSA + AES). web_client.py implements the exact same
handshake, but exposes it through a web page instead of a terminal.
"""
import socket
import threading

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

from netutils import send_msg, recv_msg
from crypto_core import encrypt_message, decrypt_message
import config

HOST = config.HOST
PORT = config.PORT


def do_handshake(sock: socket.socket) -> bytes:
    public_key_pem = recv_msg(sock)
    public_key = RSA.import_key(public_key_pem)
    print("[+] Received the server's RSA public key")

    session_key = get_random_bytes(32)  # random AES-256 key

    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_session_key = cipher_rsa.encrypt(session_key)
    send_msg(sock, encrypted_session_key)
    print("[+] Sent the AES session key (RSA-encrypted)")

    return session_key


def receive_loop(sock: socket.socket, session_key: bytes) -> None:
    while True:
        try:
            packet = recv_msg(sock)
        except ConnectionError:
            print("\n[!] Server disconnected")
            break
        try:
            message = decrypt_message(session_key, packet)
            print(f"\nServer> {message.decode()}\nClient> ", end="", flush=True)
        except ValueError:
            print("\n[!] ALERT: message rejected (integrity check failed, possible tampering)")


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print(f"[+] Connected to server {HOST}:{PORT}")

    session_key = do_handshake(sock)

    threading.Thread(target=receive_loop, args=(sock, session_key), daemon=True).start()

    try:
        while True:
            text = input("Client> ")
            send_msg(sock, encrypt_message(session_key, text.encode()))
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        sock.close()


if __name__ == "__main__":
    main()
