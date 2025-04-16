import os
import json
import time
import bcrypt
from cryptography.fernet import Fernet

# Load or create key
def load_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as f:
            f.write(key)
    else:
        with open("secret.key", "rb") as f:
            key = f.read()
    return Fernet(key)

fernet = load_key()

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def encrypt_data(data):
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(token):
    return fernet.decrypt(token.encode()).decode()

def load_users():
    if not os.path.exists("users.json"):
        with open("users.json", "w") as f:
            json.dump({}, f)
    with open("users.json", "r") as f:
        return json.load(f)

def save_users(users):
    with open("users.json", "w") as f:
        json.dump(users, f)

def load_vault():
    if not os.path.exists("vault.json"):
        with open("vault.json", "w") as f:
            json.dump([], f)
    with open("vault.json", "r") as f:
        return json.load(f)

def save_vault(vault):
    with open("vault.json", "w") as f:
        json.dump(vault, f)



