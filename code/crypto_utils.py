import os
from cryptography.fernet import Fernet

BASE_DIR = os.path.dirname(__file__)
DB_FOLDER = os.path.abspath(os.path.join(BASE_DIR, "./db"))

USER_FILE = os.path.join(DB_FOLDER, "user.db")
DATABASE_FILE = os.path.join(DB_FOLDER, "database.db")
KEY_PATH = os.path.join(DB_FOLDER, "secret.key")

def generate_key():
    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    if not os.path.exists(KEY_PATH):
        key = Fernet.generate_key()
        with open(KEY_PATH, "wb") as f:
            f.write(key)

def load_key():
    with open(KEY_PATH, "rb") as f:
        return f.read()

def encrypt_data(data: bytes) -> bytes:
    return Fernet(load_key()).encrypt(data)

def decrypt_data(data: bytes) -> bytes:
    return Fernet(load_key()).decrypt(data)
