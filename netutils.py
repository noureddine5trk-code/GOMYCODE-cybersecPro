"""
netutils.py
Utilitaires pour envoyer/recevoir des messages complets sur un socket TCP.

TCP est un flux d'octets continu : il ne garde pas les "limites" entre
deux envois. Si on veut être sûr de recevoir exactement un message (et
pas un mélange de deux messages, ou un message coupé en deux), on
préfixe chaque message par sa longueur, codée sur 4 octets.
"""
import struct


def send_msg(sock, data: bytes) -> None:
    """Envoie `data` précédé de sa longueur (4 octets, big-endian)."""
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)


def recv_exact(sock, n: int) -> bytes:
    """Lit exactement n octets sur le socket (lève une erreur si la connexion tombe)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connexion fermée par le correspondant")
        buf += chunk
    return buf


def recv_msg(sock) -> bytes:
    """Reçoit un message complet, préfixé par sa longueur."""
    header = recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    return recv_exact(sock, length)
