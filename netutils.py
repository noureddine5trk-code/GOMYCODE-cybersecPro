"""
netutils.py — helpers for sending/receiving complete messages over a TCP socket.

TCP is a continuous byte stream: it does not preserve "boundaries"
between separate sends. To be sure we read exactly one message at a time
(not a mix of two messages, or half of one), every message is prefixed
with its length, encoded as 4 bytes.
"""
import struct


def send_msg(sock, data: bytes) -> None:
    """Send `data` prefixed with its length (4 bytes, big-endian)."""
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)


def recv_exact(sock, n: int) -> bytes:
    """Read exactly n bytes from the socket (raises if the connection drops)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed by the peer")
        buf += chunk
    return buf


def recv_msg(sock) -> bytes:
    """Receive one complete, length-prefixed message."""
    header = recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    return recv_exact(sock, length)
