"""
server.py — Étape 2 de la consigne : canal de communication sécurisé (côté serveur)

Chiffrement HYBRIDE RSA + AES :
  1. Le serveur génère une paire de clés RSA et envoie sa clé PUBLIQUE au client.
  2. Le client génère une clé AES aléatoire (clé de session), la chiffre avec
     la clé publique RSA du serveur, puis l'envoie.
  3. Le serveur déchiffre cette clé AES avec sa clé PRIVÉE RSA.
  4. À partir de là, tous les messages sont chiffrés/déchiffrés en AES
     (RSA est trop lent pour chiffrer un flux de messages en continu ;
     AES est rapide et c'est exactement pour ça qu'on l'utilise après
     l'échange de clé).

Mode AES utilisé : EAX. Contrairement à un mode "simple" comme CBC, EAX
chiffre ET authentifie : si un message est modifié en transit, le
déchiffrement échoue au lieu de rendre un texte corrompu silencieusement.
C'est important pour la partie "test" de la consigne (étape 3).
"""
import socket
import threading

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

from netutils import send_msg, recv_msg

HOST = "0.0.0.0"
PORT = 5050


def do_handshake(conn: socket.socket) -> bytes:
    """Échange les clés et renvoie la clé AES de session partagée."""
    rsa_key = RSA.generate(2048)
    public_key = rsa_key.publickey().export_key()

    send_msg(conn, public_key)
    print("[+] Clé publique RSA envoyée au client")

    encrypted_session_key = recv_msg(conn)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    session_key = cipher_rsa.decrypt(encrypted_session_key)
    print("[+] Clé de session AES reçue et déchiffrée")

    return session_key


def encrypt_message(session_key: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    # nonce (16o) + tag (16o) + ciphertext, envoyés comme un seul message
    return cipher.nonce + tag + ciphertext


def decrypt_message(session_key: bytes, packet: bytes) -> bytes:
    nonce, tag, ciphertext = packet[:16], packet[16:32], packet[32:]
    cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    # decrypt_and_verify lève ValueError si le message a été altéré
    return cipher.decrypt_and_verify(ciphertext, tag)


def receive_loop(conn: socket.socket, session_key: bytes) -> None:
    while True:
        try:
            packet = recv_msg(conn)
        except ConnectionError:
            print("\n[!] Client déconnecté")
            break
        try:
            message = decrypt_message(session_key, packet)
            print(f"\nClient> {message.decode()}\nServeur> ", end="", flush=True)
        except ValueError:
            print("\n[!] ALERTE : message rejeté (intégrité invalide, possible altération)")


def main() -> None:
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(1)
    print(f"[+] Serveur en écoute sur {HOST}:{PORT}...")

    conn, addr = server_sock.accept()
    print(f"[+] Connexion depuis {addr}")

    session_key = do_handshake(conn)

    threading.Thread(target=receive_loop, args=(conn, session_key), daemon=True).start()

    try:
        while True:
            text = input("Serveur> ")
            send_msg(conn, encrypt_message(session_key, text.encode()))
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        conn.close()
        server_sock.close()


if __name__ == "__main__":
    main()
