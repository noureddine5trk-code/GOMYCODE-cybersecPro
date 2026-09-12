"""
config.py — shared configuration for the secure chat project.

Centralizing these values means server.py, client.py, and web_client.py
never disagree on where to connect, and there's exactly one place to
change them.
"""
import os

# Address of server.py (the Phase 1 encrypted socket server)
HOST = os.environ.get("CHAT_HOST", "127.0.0.1")
PORT = int(os.environ.get("CHAT_PORT", "5050"))

# Flask web bridge (Phase 2 target)
WEB_HOST = os.environ.get("WEB_HOST", "127.0.0.1")
WEB_PORT = int(os.environ.get("WEB_PORT", "5000"))

# Flask needs a secret key to sign session cookies. Falling back to a
# fixed value keeps local development simple, but it's a real weakness:
# anyone with this source code could forge a session. A proper deployment
# would require FLASK_SECRET_KEY to be set and refuse to start otherwise.
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key-change-me")
