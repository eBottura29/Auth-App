import bcrypt
import os
from storage import save_encrypted_object, load_encrypted_object

BASE_DIR = os.path.dirname(__file__)
DB_FOLDER = os.path.abspath(os.path.join(BASE_DIR, "./db"))

USER_FILE = os.path.join(DB_FOLDER, "user.db")
DATABASE_FILE = os.path.join(DB_FOLDER, "database.db")
KEY_PATH = os.path.join(DB_FOLDER, "secret.key")

DEBUG = True


def init_files():
    if not os.path.exists(DB_FOLDER):
        os.makedirs(DB_FOLDER)

    if not os.path.exists(USER_FILE):
        save_encrypted_object(
            {"logged_in": False, "username": None, "password": None, "session_id": 0},
            USER_FILE,
        )

    if not os.path.exists(DATABASE_FILE):
        save_encrypted_object(
            {
                "last_session_id": 0,
                "users": {"root": bcrypt.hashpw(b"toor", bcrypt.gensalt())},
            },
            DATABASE_FILE,
        )


def sign_in(username, password):
    database = load_encrypted_object(DATABASE_FILE)
    stored_hash = database["users"].get(username)

    if stored_hash is None:
        print("User does not exist.")
        return 2  # Not existing user

    if bcrypt.checkpw(password.encode(), stored_hash):
        user = load_encrypted_object(USER_FILE)
        user["logged_in"] = True
        user["username"] = username
        user["password"] = password  # For demonstration only
        user["session_id"] = database["last_session_id"] + 1
        database["last_session_id"] = user["session_id"]

        save_encrypted_object(user, USER_FILE)
        save_encrypted_object(database, DATABASE_FILE)

        if DEBUG:
            print("Login successful.")
        return 0  # Success
    else:
        print("Incorrect password.")
        return 2  # Incorrect password


def sign_up(username, password):
    if len(password) != 8:
        return 3  # Invalid password length"

    database = load_encrypted_object(DATABASE_FILE)

    if username in database["users"]:
        return 2  # Already exists

    database["users"][username] = password
    database["last_session_id"] += 1

    save_encrypted_object(DATABASE_FILE, database)

    return 0  # Success


def log_out():
    user = load_encrypted_object(USER_FILE)
    user.update(
        {"logged_in": False, "username": None, "password": None, "session_id": 0}
    )

    save_encrypted_object(user, USER_FILE)
    print("You have been logged out.")
    return 0  # Success


def remove_account():
    try:
        user = load_encrypted_object(USER_FILE)
        if not user["logged_in"]:
            return 1  # Not logged in

        username = user["username"]
        db = load_encrypted_object(DATABASE_FILE)

        if username in db["users"]:
            del db["users"][username]
            save_encrypted_object(db, DATABASE_FILE)

        # Log the user out
        user["logged_in"] = False
        user["username"] = None
        user["password"] = None
        user["session_id"] = 0
        save_encrypted_object(user, USER_FILE)

        return 0  # Success
    except Exception as e:
        print(f"[remove_account] Error: {e}")
        return -1  # Error
