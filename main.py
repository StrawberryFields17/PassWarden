import base64
import json
import os
import secrets
import string
import hashlib
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox
import urllib.request
import webbrowser

from cryptography.fernet import Fernet, InvalidToken


# ---------- App metadata & files --------------------------------------------

APP_NAME = "PassWarden"
APP_VERSION = "0.1.0"

# When built as EXE, these paths are still fine (relative to main.exe folder)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VAULT_FILENAME = "vault.pw"
VAULT_PATH = os.path.join(BASE_DIR, VAULT_FILENAME)

# URL to a small JSON file in your GitHub repo, see update.json section below
UPDATE_INFO_URL = (
    "https://raw.githubusercontent.com/StrawberryFields17/PassWarden/main/update.json"
)

PBKDF2_ITERATIONS = 200_000


# ---------- Crypto & storage -------------------------------------------------


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )
    return base64.urlsafe_b64encode(key)


def encrypt_vault(vault_data: dict, password: str) -> dict:
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


def decrypt_vault(container: dict, password: str) -> dict:
    salt = base64.b64decode(container["salt"])
    iterations = container.get("iterations", PBKDF2_ITERATIONS)
    key = derive_key(password, salt, iterations)
    f = Fernet(key)
    token = container["vault"].encode("ascii")
    plaintext = f.decrypt(token).decode("utf-8")
    return json.loads(plaintext)


def load_vault_file(path: str, password: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        container = json.load(f)
    return decrypt_vault(container, password)


def save_vault_file(path: str, vault_data: dict, password: str) -> None:
    container = encrypt_vault(vault_data, password)
    temp_path = path + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(container, f, indent=2)
    os.replace(temp_path, path)


def new_empty_vault() -> dict:
    # settings are stored inside the vault => encrypted as well
    return {
        "version": 1,
        "settings": {
            "window_width": 900,
            "window_height": 500,
        },
        "entries": [],
    }


# ---------- Password generator ----------------------------------------------


def generate_password(
    length: int = 20,
    use_lower=True,
    use_upper=True,
    use_digits=True,
    use_symbols=True,
) -> str:
    if not any([use_lower, use_upper, use_digits, use_symbols]):
        raise ValueError("At least one character set must be selected.")

    alphabet = ""
    if use_lower:
        alphabet += string.ascii_lowercase
    if use_upper:
        alphabet += string.ascii_uppercase
    if use_digits:
        alphabet += string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.?/"

    return "".join(secrets.choice(alphabet) for _ in range(length))


def estimate_strength_bits(length: int, alphabet_size: int) -> float:
    import math

    return length * math.log2(alphabet_size)


def classify_strength(bits: float) -> str:
    if bits < 40:
        return "Weak"
    elif bits < 60:
        return "Okay"
    elif bits < 90:
        return "Strong"
    else:
        return "Very strong"


class PasswordGeneratorDialog(tk.Toplevel):
    def __init__(self, parent, on_password_chosen=None):
        super().__init__(parent)
        self.title("Password Generator")
        self.resizable(False, False)
        self.on_password_chosen = on_password_chosen

        self.length_var = tk.IntVar(value(20))
        self.use_lower_var = tk.BooleanVar(value=True)
        self.use_upper_var = tk.BooleanVar(value=True)
        self.use_digits_var = tk.BooleanVar(value=True)
        self.use_symbols_var = tk.BooleanVar(value=True)
        self.generated_var = tk.StringVar(value="")
        self.strength_var = tk.StringVar(value="")

        self._build_ui()
        self.generate()

        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def _build_ui(self):
        main = ttk.Frame(self, padding=12)
        main.grid(row=0, column=0, sticky="nsew")

        ttk.Label(main, text="Generated password:").grid(row=0, column=0, sticky="w")
        entry = ttk.Entry(main, textvariable=self.generated_var, width=40)
        entry.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 4))

        ttk.Label(main, textvariable=self.strength_var).grid(
            row=2, column=0, columnspan=3, sticky="w", pady=(0, 8)
        )

        ttk.Label(main, text="Length:").grid(row=3, column=0, sticky="w")
        length_spin = ttk.Spinbox(
            main, from_=8, to=64, textvariable=self.length_var, width=5
        )
        length_spin.grid(row=3, column=1, sticky="w")

        row = 4
        ttk.Checkbutton(
            main, text="Use lowercase (a-z)", variable=self.use_lower_var
        ).grid(row=row, column=0, columnspan=3, sticky="w")
        row += 1
        ttk.Checkbutton(
            main, text="Use uppercase (A-Z)", variable=self.use_upper_var
        ).grid(row=row, column=0, columnspan=3, sticky="w")
        row += 1
        ttk.Checkbutton(
            main, text="Use digits (0-9)", variable=self.use_digits_var
        ).grid(row=row, column=0, columnspan=3, sticky="w")
        row += 1
        ttk.Checkbutton(
            main,
            text="Use symbols (!@#$%^&*)",
            variable=self.use_symbols_var,
        ).grid(row=row, column=0, columnspan=3, sticky="w")
        row += 1

        btn_frame = ttk.Frame(main)
        btn_frame.grid(row=row, column=0, columnspan=3, pady=(10, 0), sticky="e")

        ttk.Button(btn_frame, text="Regenerate", command=self.generate).grid(
            row=0, column=0, padx=5
        )
        ttk.Button(btn_frame, text="Copy", command=self.copy_to_clipboard).grid(
            row=0, column=1, padx=5
        )
        ttk.Button(btn_frame, text="Use Password", command=self.use_password).grid(
            row=0, column=2, padx=5
        )

    def generate(self):
        try:
            pwd = generate_password(
                length=self.length_var.get(),
                use_lower=self.use_lower_var.get(),
                use_upper=self.use_upper_var.get(),
                use_digits=self.use_digits_var.get(),
                use_symbols=self.use_symbols_var.get(),
            )
        except ValueError as e:
            messagebox.showerror("Error", str(e), parent=self)
            return

        self.generated_var.set(pwd)

        alphabet_size = (
            (26 if self.use_lower_var.get() else 0)
            + (26 if self.use_upper_var.get() else 0)
            + (10 if self.use_digits_var.get() else 0)
            + (26 if self.use_symbols_var.get() else 0)
        )

        bits = estimate_strength_bits(self.length_var.get(), alphabet_size)
        category = classify_strength(bits)
        self.strength_var.set(f"Strength: {category} (~{bits:.0f} bits)")

    def copy_to_clipboard(self):
        pwd = self.generated_var.get()
        if not pwd:
            return
        self.clipboard_clear()
        self.clipboard_append(pwd)
        messagebox.showinfo("Copied", "Password copied to clipboard.", parent=self)

    def use_password(self):
        if self.on_password_chosen:
            self.on_password_chosen(self.generated_var.get())
        self.destroy()


# ---------- Entry editor dialog ---------------------------------------------


class EntryDialog(tk.Toplevel):
    def __init__(self, parent, title, entry=None):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.result = None

        self.name_var = tk.StringVar(value=(entry or {}).get("name", ""))
        self.username_var = tk.StringVar(value=(entry or {}).get("username", ""))
        self.password_var = tk.StringVar(value=(entry or {}).get("password", ""))
        self.url_var = tk.StringVar(value=(entry or {}).get("url", ""))
        self.notes_var = tk.StringVar(value=(entry or {}).get("notes", ""))

        self._build_ui()
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)

    def _build_ui(self):
        main = ttk.Frame(self, padding=12)
        main.grid(row=0, column=0, sticky="nsew")

        row = 0
        ttk.Label(main, text="Name:").grid(row=row, column=0, sticky="e", pady=2)
        ttk.Entry(main, textvariable=self.name_var, width=40).grid(
            row=row, column=1, sticky="w", pady=2
        )
        row += 1

        ttk.Label(main, text="Username:").grid(row=row, column=0, sticky="e", pady=2)
        ttk.Entry(main, textvariable=self.username_var, width=40).grid(
            row=row, column=1, sticky="w", pady=2
        )
        row += 1

        ttk.Label(main, text="Password:").grid(row=row, column=0, sticky="e", pady=2)
        pwd_frame = ttk.Frame(main)
        pwd_frame.grid(row=row, column=1, sticky="w", pady=2)
        ttk.Entry(pwd_frame, textvariable=self.password_var, show="*", width=30).grid(
            row=0, column=0
        )
        ttk.Button(pwd_frame, text="Generate", command=self.open_generator).grid(
            row=0, column=1, padx=(5, 0)
        )
        row += 1

        ttk.Label(main, text="URL:").grid(row=row, column=0, sticky="e", pady=2)
        ttk.Entry(main, textvariable=self.url_var, width=40).grid(
            row=row, column=1, sticky="w", pady=2
        )
        row += 1

        ttk.Label(main, text="Notes:").grid(row=row, column=0, sticky="ne", pady=2)
        notes = tk.Text(main, width=40, height=5)
        notes.grid(row=row, column=1, sticky="w", pady=2)
        notes.insert("1.0", self.notes_var.get())
        self.notes_widget = notes
        row += 1

        btn_frame = ttk.Frame(main)
        btn_frame.grid(row=row, column=0, columnspan=2, pady=(10, 0), sticky="e")
        ttk.Button(btn_frame, text="Cancel", command=self.on_cancel).grid(
            row=0, column=0, padx=5
        )
        ttk.Button(btn_frame, text="Save", command=self.on_ok).grid(
            row=0, column=1, padx=5
        )

    def open_generator(self):
        PasswordGeneratorDialog(self, on_password_chosen=self.password_var.set)

    def on_ok(self):
        name = self.name_var.get().strip()
        if not name:
            messagebox.showerror("Error", "Name is required.", parent=self)
            return
        self.notes_var.set(self.notes_widget.get("1.0", "end").rstrip("\n"))

        self.result = {
            "name": name,
            "username": self.username_var.get().strip(),
            "password": self.password_var.get(),
            "url": self.url_var.get().strip(),
            "notes": self.notes_var.get(),
        }
        self.destroy()

    def on_cancel(self):
        self.result = None
        self.destroy()


# ---------- Master password dialogs -----------------------------------------


class MasterPasswordDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Set master password")
        self.resizable(False, False)
        self.result = None
        self.pass_var = tk.StringVar()
        self.confirm_var = tk.StringVar()

        self._build_ui()
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)

    def _build_ui(self):
        main = ttk.Frame(self, padding=12)
        main.grid(row=0, column=0)

        ttk.Label(
            main,
            text=(
                "Create a master password.\n"
                "If you forget it, your vault cannot be recovered."
            ),
            wraplength=320,
        ).grid(row=0, column=0, columnspan=2, pady=(0, 10))

        ttk.Label(main, text="Master password:").grid(
            row=1, column=0, sticky="e", pady=2
        )
        ttk.Entry(main, textvariable=self.pass_var, show="*", width=30).grid(
            row=1, column=1, pady=2
        )

        ttk.Label(main, text="Confirm:").grid(row=2, column=0, sticky="e", pady=2)
        ttk.Entry(main, textvariable=self.confirm_var, show="*", width=30).grid(
            row=2, column=1, pady=2
        )

        btn_frame = ttk.Frame(main)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=(10, 0), sticky="e")
        ttk.Button(btn_frame, text="Cancel", command=self.on_cancel).grid(
            row=0, column=0, padx=5
        )
        ttk.Button(btn_frame, text="Create", command=self.on_ok).grid(
            row=0, column=1, padx=5
        )

    def on_ok(self):
        p1 = self.pass_var.get()
        p2 = self.confirm_var.get()
        if not p1:
            messagebox.showerror("Error", "Password cannot be empty.", parent=self)
            return
        if p1 != p2:
            messagebox.showerror("Error", "Passwords do not match.", parent=self)
            return
        self.result = p1
        self.destroy()

    def on_cancel(self):
        self.result = None
        self.destroy()


class UnlockDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Unlock vault")
        self.resizable(False, False)
        self.result = None
        self.pass_var = tk.StringVar()

        self._build_ui()
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)

    def _build_ui(self):
        main = ttk.Frame(self, padding=12)
        main.grid(row=0, column=0)

        ttk.Label(
            main,
            text="Enter your master password to unlock the vault.",
            wraplength=320,
        ).grid(row=0, column=0, columnspan=2, pady=(0, 10))

        ttk.Label(main, text="Master password:").grid(
            row=1, column=0, sticky="e", pady=2
        )
        entry = ttk.Entry(main, textvariable=self.pass_var, show="*", width=30)
        entry.grid(row=1, column=1, pady=2)
        entry.focus_set()

        btn_frame = ttk.Frame(main)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=(10, 0), sticky="e")
        ttk.Button(btn_frame, text="Cancel", command=self.on_cancel).grid(
            row=0, column=0, padx=5
        )
        ttk.Button(btn_frame, text="Unlock", command=self.on_ok).grid(
            row=0, column=1, padx=5
        )

    def on_ok(self):
        self.result = self.pass_var.get()
        self.destroy()

    def on_cancel(self):
        self.result = None
        self.destroy()


# ---------- Update checking --------------------------------------------------


def parse_version(v: str):
    return tuple(int(x) for x in v.split("."))


# ---------- Main app ---------------------------------------------------------


class PassWardenApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)

        self.master_password = None
        self.vault = None

        self._init_style()
        if not self._unlock_or_initialize():
            self.destroy()
            return

        # get encrypted settings
        settings = self.vault.setdefault("settings", {})
        width = settings.get("window_width", 900)
        height = settings.get("window_height", 500)
        self.geometry(f"{width}x{height}")

        self._build_ui()
        self.refresh_entries_list()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # auto-check for updates on startup (silent if OK/failed)
        self.after(3000, lambda: self.check_for_updates(silent=True))

    # --- setup & style ---

    def _init_style(self):
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")

    def _unlock_or_initialize(self) -> bool:
        if not os.path.exists(VAULT_PATH):
            dlg = MasterPasswordDialog(self)
            self.wait_window(dlg)
            if dlg.result is None:
                return False
            self.master_password = dlg.result
            self.vault = new_empty_vault()
            save_vault_file(VAULT_PATH, self.vault, self.master_password)
            return True
        else:
            while True:
                dlg = UnlockDialog(self)
                self.wait_window(dlg)
                if dlg.result is None:
                    return False
                password = dlg.result
                try:
                    vault = load_vault_file(VAULT_PATH, password)
                except (InvalidToken, KeyError, json.JSONDecodeError):
                    messagebox.showerror(
                        "Error",
                        "Unable to decrypt vault. Master password is incorrect "
                        "or file is corrupted.",
                        parent=self,
                    )
                    continue
                self.master_password = password
                self.vault = vault
                return True

    # --- UI ---

    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        # menu bar
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="Lock && Exit", command=self.on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(label="Check for updates...", command=self.check_for_updates)
        help_menu.add_separator()
        help_menu.add_command(
            label="About",
            command=lambda: messagebox.showinfo(
                "About",
                f"{APP_NAME} {APP_VERSION}\nLocal encrypted password manager.",
                parent=self,
            ),
        )
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

        main = ttk.Frame(self, padding=8)
        main.grid(row=0, column=0, sticky="nsew")
        main.columnconfigure(0, weight=2)
        main.columnconfigure(1, weight=3)
        main.rowconfigure(1, weight=1)

        toolbar = ttk.Frame(main)
        toolbar.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 5))

        ttk.Button(toolbar, text="Add", command=self.add_entry).grid(row=0, column=0, padx=2)
        ttk.Button(toolbar, text="Edit", command=self.edit_selected_entry).grid(row=0, column=1, padx=2)
        ttk.Button(toolbar, text="Delete", command=self.delete_selected_entry).grid(row=0, column=2, padx=2)
        ttk.Button(toolbar, text="Copy password", command=self.copy_selected_password).grid(row=0, column=3, padx=2)
        ttk.Button(toolbar, text="Password generator", command=self.open_generator).grid(row=0, column=4, padx=2)

        self.tree = ttk.Treeview(
            main,
            columns=("name", "username", "url"),
            show="headings",
            selectmode="browse",
        )
        self.tree.heading("name", text="Name")
        self.tree.heading("username", text="Username")
        self.tree.heading("url", text="URL")
        self.tree.column("name", width=200)
        self.tree.column("username", width=150)
        self.tree.column("url", width=250)
        self.tree.grid(row=1, column=0, sticky="nsew", padx=(0, 5))

        scrollbar = ttk.Scrollbar(main, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=1, column=0, sticky="nse", padx=(0, 0))

        self.tree.bind("<<TreeviewSelect>>", lambda e: self.show_selected_details())

        detail_frame = ttk.LabelFrame(main, text="Details")
        detail_frame.grid(row=1, column=1, sticky="nsew")
        detail_frame.columnconfigure(1, weight=1)
        detail_frame.rowconfigure(5, weight=1)

        self.detail_name = tk.StringVar()
        self.detail_username = tk.StringVar()
        self.detail_url = tk.StringVar()
        self.detail_created = tk.StringVar()
        self.detail_updated = tk.StringVar()

        ttk.Label(detail_frame, text="Name:").grid(row=0, column=0, sticky="e")
        ttk.Label(detail_frame, textvariable=self.detail_name).grid(row=0, column=1, sticky="w")

        ttk.Label(detail_frame, text="Username:").grid(row=1, column=0, sticky="e")
        ttk.Label(detail_frame, textvariable=self.detail_username).grid(row=1, column=1, sticky="w")

        ttk.Label(detail_frame, text="URL:").grid(row=2, column=0, sticky="e")
        ttk.Label(detail_frame, textvariable=self.detail_url).grid(row=2, column=1, sticky="w")

        ttk.Label(detail_frame, text="Created:").grid(row=3, column=0, sticky="e")
        ttk.Label(detail_frame, textvariable=self.detail_created).grid(row=3, column=1, sticky="w")

        ttk.Label(detail_frame, text="Updated:").grid(row=4, column=0, sticky="e")
        ttk.Label(detail_frame, textvariable=self.detail_updated).grid(row=4, column=1, sticky="w")

        ttk.Label(detail_frame, text="Notes:").grid(row=5, column=0, sticky="ne")
        self.detail_notes = tk.Text(detail_frame, width=40, height=8, state="disabled")
        self.detail_notes.grid(row=5, column=1, sticky="nsew")

    # --- vault helpers ---

    def _save_vault(self):
        save_vault_file(VAULT_PATH, self.vault, self.master_password)

    def _get_entries(self):
        return self.vault.setdefault("entries", [])

    def _find_entry_by_id(self, entry_id):
        for e in self._get_entries():
            if e["id"] == entry_id:
                return e
        return None

    # --- actions ---

    def refresh_entries_list(self):
        self.tree.delete(*self.tree.get_children())
        for entry in self._get_entries():
            self.tree.insert(
                "",
                "end",
                iid=entry["id"],
                values=(entry["name"], entry.get("username", ""), entry.get("url", "")),
            )

    def show_selected_details(self):
        selection = self.tree.selection()
        if not selection:
            self.detail_name.set("")
            self.detail_username.set("")
            self.detail_url.set("")
            self.detail_created.set("")
            self.detail_updated.set("")
            self.detail_notes.configure(state="normal")
            self.detail_notes.delete("1.0", "end")
            self.detail_notes.configure(state="disabled")
            return

        entry_id = selection[0]
        entry = self._find_entry_by_id(entry_id)
        if not entry:
            return

        self.detail_name.set(entry["name"])
        self.detail_username.set(entry.get("username", ""))
        self.detail_url.set(entry.get("url", ""))
        self.detail_created.set(entry.get("created", ""))
        self.detail_updated.set(entry.get("updated", ""))
        self.detail_notes.configure(state="normal")
        self.detail_notes.delete("1.0", "end")
        self.detail_notes.insert("1.0", entry.get("notes", ""))
        self.detail_notes.configure(state="disabled")

    def add_entry(self):
        dlg = EntryDialog(self, "Add entry")
        self.wait_window(dlg)
        if dlg.result is None:
            return

        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        entry = dlg.result
        entry["id"] = secrets.token_hex(8)
        entry["created"] = now
        entry["updated"] = now

        self._get_entries().append(entry)
        self._save_vault()
        self.refresh_entries_list()

    def edit_selected_entry(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("No selection", "Select an entry to edit.", parent=self)
            return
        entry_id = selection[0]
        entry = self._find_entry_by_id(entry_id)
        if not entry:
            return

        dlg = EntryDialog(self, "Edit entry", entry=entry)
        self.wait_window(dlg)
        if dlg.result is None:
            return

        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        updated = dlg.result
        entry.update(updated)
        entry["updated"] = now

        self._save_vault()
        self.refresh_entries_list()
        self.show_selected_details()

    def delete_selected_entry(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("No selection", "Select an entry to delete.", parent=self)
            return
        entry_id = selection[0]
        entry = self._find_entry_by_id(entry_id)
        if not entry:
            return
        if not messagebox.askyesno(
            "Confirm delete",
            f"Delete entry '{entry['name']}'?",
            parent=self,
        ):
            return

        self.vault["entries"] = [e for e in self._get_entries() if e["id"] != entry_id]
        self._save_vault()
        self.refresh_entries_list()
        self.show_selected_details()

    def copy_selected_password(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo(
                "No selection", "Select an entry to copy its password.", parent=self
            )
            return
        entry_id = selection[0]
        entry = self._find_entry_by_id(entry_id)
        if not entry:
            return
        pwd = entry.get("password", "")
        if not pwd:
            messagebox.showinfo(
                "No password",
                "This entry does not have a password stored.",
                parent=self,
            )
            return

        self.clipboard_clear()
        self.clipboard_append(pwd)
        messagebox.showinfo("Copied", "Password copied to clipboard.", parent=self)

    def open_generator(self):
        PasswordGeneratorDialog(self)

    # --- update checking ---

    def check_for_updates(self, silent=False):
        try:
            with urllib.request.urlopen(UPDATE_INFO_URL, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            latest = data.get("version")
            download_url = data.get(
                "download_url",
                "https://github.com/StrawberryFields17/PassWarden/releases",
            )
        except Exception as e:
            if not silent:
                messagebox.showinfo(
                    "Check for updates",
                    f"Could not check for updates:\n{e}",
                    parent=self,
                )
            return

        if latest and parse_version(latest) > parse_version(APP_VERSION):
            if messagebox.askyesno(
                "Update available",
                f"A newer version ({latest}) is available.\n"
                f"You are running {APP_VERSION}.\n\n"
                f"Open the download page?",
                parent=self,
            ):
                webbrowser.open(download_url)
        else:
            if not silent:
                messagebox.showinfo(
                    "Up to date",
                    f"{APP_NAME} {APP_VERSION} is the latest version.",
                    parent=self,
                )

    # --- close / settings ---

    def on_close(self):
        # save current window size in encrypted settings
        try:
            size = self.geometry().split("+")[0]
            width, height = size.split("x")
            settings = self.vault.setdefault("settings", {})
            settings["window_width"] = int(width)
            settings["window_height"] = int(height)
        except Exception:
            pass

        self._save_vault()
        self.destroy()


def main():
    app = PassWardenApp()
    app.mainloop()


if __name__ == "__main__":
    main()
