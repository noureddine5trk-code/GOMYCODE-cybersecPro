"""
netutils.py
Utilities for sending and receiving complete messages over a TCP socket.

TCP is a continuous byte stream; it does not preserve boundaries between
separate sends. To ensure that exactly one message is received (rather
than a mix of two messages or a message split in two), each message is
prefixed with its length, encoded as 4 bytes.
"""
import struct


def send_msg(sock, data: bytes) -> None:
    """Sends `data` preceded by its length (4 bytes, big-endian)."""
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)


def recv_exact(sock, n: int) -> bytes:
    """Reads exactly n bytes from the socket (raises an error if the connection drops)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed by the remote host")
        buf += chunk
    return buf


def recv_msg(sock) -> bytes:
    """Receives a complete message, prefixed by its length.."""
    header = recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    return recv_exact(sock, length)
