import base64
import json
import os
import hashlib
import secrets
from datetime import datetime
from typing import Dict, Any

from cryptography.fernet import Fernet, InvalidToken

PBKDF2_ITERATIONS = 400_000


def utcnow_iso() -> str:
    """Return UTC time in ISO format."""
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derive a Fernet-compatible key from a password."""
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )
    return base64.urlsafe_b64encode(key)


def encrypt_vault(vault_data: Dict[str, Any], password: str) -> Dict[str, Any]:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    token = f.encrypt(json.dumps(vault_data).encode("utf-8"))

    return {
        "kdf": "PBKDF2-HMAC-SHA256",
        "cipher": "Fernet",
        "iterations": PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "vault": token.decode("ascii"),
        "version": 1,
    }


def decrypt_vault(container: Dict[str, Any], password: str) -> Dict[str, Any]:
    """Decrypts a stored vault. Raises clearer errors for corrupted files."""
    if "salt" not in container or "vault" not in container:
        raise ValueError("Vault file is missing required fields (salt or vault).")

    try:
        salt = base64.b64decode(container["salt"])
    except Exception:
        raise ValueError("Vault file contains an invalid salt value.")

    key = derive_key(password, salt, container.get("iterations", PBKDF2_ITERATIONS))
    f = Fernet(key)

    try:
        decrypted = f.decrypt(container["vault"].encode("ascii"))
    except InvalidToken:
        raise InvalidToken("Failed to decrypt vault — incorrect password or corrupted file.")

    try:
        return json.loads(decrypted.decode("utf-8"))
    except json.JSONDecodeError:
        # <-- small fix: explicit corruption notice instead of cryptic stacktrace
        raise ValueError("Decrypted vault data is invalid JSON — file may be corrupted.")


def load_vault_file(path: str, password: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        try:
            container = json.load(f)
        except json.JSONDecodeError:
            raise ValueError("Vault file is unreadable or corrupted (invalid JSON).")
    return decrypt_vault(container, password)


def save_vault_file(path: str, vault_data: Dict[str, Any], password: str) -> None:
    now = utcnow_iso()
    vault_data.setdefault("created_at", now)
    vault_data["updated_at"] = now
    vault_data.setdefault("vault_id", secrets.token_hex(16))

    container = encrypt_vault(vault_data, password)

    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as f:
        json.dump(container, f, indent=2)
    os.replace(temp, path)

    if os.name == "posix":
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass


def new_empty_vault() -> Dict[str, Any]:
    now = utcnow_iso()
    return {
        "version": 1,
        "vault_id": secrets.token_hex(16),
        "created_at": now,
        "updated_at": now,
        "settings": {
            "window_width": None,
            "window_height": None,
            "clipboard_timeout_ms": 15000,
        },
        "entries": [],
    }
