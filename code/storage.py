import pickle
from crypto_utils import encrypt_data, decrypt_data


def save_encrypted_object(obj, path):
    raw = pickle.dumps(obj)
    encrypted = encrypt_data(raw)
    with open(path, "wb") as f:
        f.write(encrypted)


def load_encrypted_object(path):
    with open(path, "rb") as f:
        encrypted = f.read()
    decrypted = decrypt_data(encrypted)
    return pickle.loads(decrypted)
