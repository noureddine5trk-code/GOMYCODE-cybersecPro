"""
crypto_core.py — the encryption engine, shared by every entry point.

Both server.py and web_client.py import these two functions, so the
message format and cipher settings only exist in one place.
"""
from Crypto.Cipher import AES


def encrypt_message(session_key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext with AES-EAX, returning nonce + tag + ciphertext.

    EAX authenticates the data as it encrypts it: any bit flipped in
    transit makes decrypt_message() raise instead of returning garbage.
    """
    cipher = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ciphertext


def decrypt_message(session_key: bytes, packet: bytes) -> bytes:
    """Reverse of encrypt_message(). Raises ValueError if tampered with."""
    nonce, tag, ciphertext = packet[:16], packet[16:32], packet[32:]
    cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
