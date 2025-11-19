import base64
import json
import os
import hashlib
from typing import Dict, Any

from cryptography.fernet import Fernet


PBKDF2_ITERATIONS = 200_000


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """
    PBKDF2-HMAC-SHA256 → 32-byte key → base64 for Fernet.
    """
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )
    return base64.urlsafe_b64encode(key)


def encrypt_vault(vault_data: Dict[str, Any], password: str) -> Dict[str, Any]:
    """
    Encrypt vault_data using Fernet derived from master password.
    """
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    token = f.encrypt(json.dumps(vault_data).encode("utf-8"))

    return {
        "kdf": "PBKDF2-HMAC-SHA256",
        "cipher": "Fernet(AES-128-CBC+HMAC)",
        "iterations": PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "vault": token.decode("ascii"),
        "version": 1,
    }


def decrypt_vault(container: Dict[str, Any], password: str) -> Dict[str, Any]:
    """
    Decrypt a vault container dict (created by encrypt_vault) with master password.
    """
    from cryptography.fernet import InvalidToken  # re-export so callers can catch

    salt = base64.b64decode(container["salt"])
    iterations = container.get("iterations", PBKDF2_ITERATIONS)
    key = derive_key(password, salt, iterations)
    f = Fernet(key)
    token = container["vault"].encode("ascii")
    plaintext = f.decrypt(token).decode("utf-8")
    return json.loads(plaintext)


def load_vault_file(path: str, password: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        container = json.load(f)
    return decrypt_vault(container, password)


def save_vault_file(path: str, vault_data: Dict[str, Any], password: str) -> None:
    container = encrypt_vault(vault_data, password)
    temp_path = path + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(container, f, indent=2)
    os.replace(temp_path, path)


def new_empty_vault() -> Dict[str, Any]:
    """
    Initial structure for a new vault. Settings live inside, so they are encrypted too.
    """
    return {
        "version": 1,
        "settings": {
            "window_width": None,
            "window_height": None,
        },
        "entries": [],
    }
