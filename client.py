"""
client.py — Étape 2 de la consigne : canal de communication sécurisé (côté client)
Voir server.py pour le détail du principe (chiffrement hybride RSA + AES).
"""
import socket
import threading

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

from netutils import send_msg, recv_msg

HOST = "127.0.0.1"  # remplace par l'IP du serveur si ce n'est pas la même machine
PORT = 5050


def do_handshake(sock: socket.socket) -> bytes:
    public_key_pem = recv_msg(sock)
    public_key = RSA.import_key(public_key_pem)
    print("[+] Clé publique RSA du serveur reçue")

    session_key = get_random_bytes(32)  # clé AES-256 aléatoire

    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_session_key = cipher_rsa.encrypt(session_key)
    send_msg(sock, encrypted_session_key)
    print("[+] Clé de session AES envoyée (chiffrée en RSA)")

    return session_key


def encrypt_message(session_key: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ciphertext


def decrypt_message(session_key: bytes, packet: bytes) -> bytes:
    nonce, tag, ciphertext = packet[:16], packet[16:32], packet[32:]
    cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def receive_loop(sock: socket.socket, session_key: bytes) -> None:
    while True:
        try:
            packet = recv_msg(sock)
        except ConnectionError:
            print("\n[!] Serveur déconnecté")
            break
        try:
            message = decrypt_message(session_key, packet)
            print(f"\nServeur> {message.decode()}\nClient> ", end="", flush=True)
        except ValueError:
            print("\n[!] ALERTE : message rejeté (intégrité invalide, possible altération)")


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print(f"[+] Connecté au serveur {HOST}:{PORT}")

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
