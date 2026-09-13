"""
web_client.py — web bridge for the encrypted chat.

This module exposes the exact same client handshake as client.py, but through a browser instead of a terminal.
This is a small, intentionally un-hardened Flask app
"""
import socket
import threading
from datetime import datetime

from flask import Flask, request, render_template, redirect, url_for
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

from netutils import send_msg, recv_msg
from crypto_core import encrypt_message, decrypt_message
import config

app = Flask(__name__)
app.secret_key = config.FLASK_SECRET_KEY

sock = None
session_key = None
messages = []  # [{"sender": "you" | "server", "text": str, "time": str}, ...]


def connect_and_handshake() -> None:
    """Identical handshake to client.py — nothing new here."""
    global sock, session_key
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((config.HOST, config.PORT))

    public_key_pem = recv_msg(sock)
    public_key = RSA.import_key(public_key_pem)

    session_key = get_random_bytes(32)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_session_key = cipher_rsa.encrypt(session_key)
    send_msg(sock, encrypted_session_key)

    threading.Thread(target=receive_loop, daemon=True).start()


def receive_loop() -> None:
    """Runs in the background: receives and decrypts messages from the server."""
    while True:
        try:
            packet = recv_msg(sock)
            text = decrypt_message(session_key, packet).decode()
            messages.append({"sender": "server", "text": text, "time": _now()})
        except (ConnectionError, ValueError):
            break


def _now() -> str:
    return datetime.now().strftime("%H:%M")


@app.route("/")
def index():
    return render_template("chat.html", messages=messages)


@app.route("/send", methods=["POST"])
def send():
    text = request.form.get("message", "").strip()
    if text:
        send_msg(sock, encrypt_message(session_key, text.encode()))
        messages.append({"sender": "you", "text": text, "time": _now()})
    return redirect(url_for("index"))


if __name__ == "__main__":
    connect_and_handshake()
    app.run(host=config.WEB_HOST, port=config.WEB_PORT)
