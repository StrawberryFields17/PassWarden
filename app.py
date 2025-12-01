import json
import os
import secrets
from datetime import datetime
from pathlib import Path

import tkinter as tk
from tkinter import ttk, messagebox

import urllib.request
import webbrowser

from cryptography.fernet import InvalidToken

from crypto_utils import load_vault_file, save_vault_file, new_empty_vault
from ui_theme import (
    configure_dark_theme,
    ENTRY_BG,
    ENTRY_FG,
    BG_COLOR,
    SUBTLE_FG,
    ACCENT_COLOR,
    HEADER_BG,
)
from dialogs import EntryDialog, ChangeMasterPasswordDialog
from password_utils import (
    generate_password,
    estimate_entropy_bits,
    estimate_crack_time_seconds,
    format_duration,
    analyze_arbitrary_password,
)

APP_NAME = "PassWarden"
APP_VERSION = "0.3.0"


def get_vault_path() -> str:
    """Return a stable per-user path for the encrypted vault file."""
    if os.name == "nt":
        # Windows: %APPDATA%/PassWarden/vault.pw
        appdata = os.getenv("APPDATA") or os.path.expanduser("~")
        base_dir = Path(appdata) / "PassWarden"
    else:
        # macOS / Linux: ~/.passwarden/vault.pw
        base_dir = Path(os.path.expanduser("~")) / ".passwarden"

    base_dir.mkdir(parents=True, exist_ok=True)
    return str(base_dir / "vault.pw")


VAULT_PATH = get_vault_path()

UPDATE_INFO_URL = (
    "https://raw.githubusercontent.com/StrawberryFields17/PassWarden/main/update.json"
)


def parse_version(v: str):
    return tuple(int(x) for x in v.split("."))


def wipe_string(value: str | None) -> None:
    """
    Best-effort attempt to overwrite sensitive string data.

    Because Python strings are immutable and memory management is handled by the
    interpreter, this cannot guarantee an in-place wipe of the original bytes.
    However, it helps reduce the lifetime and reuse of sensitive values.
    """
    if not value:
        return
    try:
        # Allocate another string of the same length, which may help overwrite
        # previous memory regions when the interpreter reuses them.
        _ = "\0" * len(value)
    except Exception:
        # We deliberately ignore all errors here: this is a best-effort helper.
        pass


class PassWardenApp(tk.Tk):
    def __init__(self):
        super().__init__()

        configure_dark_theme(self)
        self.title(APP_NAME)

        # Safe default geometry so it’s visible
        self.geometry("1100x750+200+80")

        self.master_password: str | None = None
        self.vault: dict | None = None
        self.settings: dict | None = None

        # Placeholder for auth screen frame
        self.auth_frame: ttk.Frame | None = None
        self.search_var: tk.StringVar | None = None

        # These may be created depending on which auth screen is shown
        self.fp_pass_var: tk.StringVar | None = None
        self.fp_confirm_var: tk.StringVar | None = None
        self.ul_pass_var: tk.StringVar | None = None

        # Decide whether to show first-run screen or unlock screen
        if not os.path.exists(VAULT_PATH):
            self._build_first_run_screen()
        else:
            self._build_unlock_screen()

    # ------------------------------------------------------------------
    #  AUTH SCREENS (IN MAIN WINDOW)
    # ------------------------------------------------------------------

    def _clear_auth_frame(self):
        if self.auth_frame is not None:
            self.auth_frame.destroy()
            self.auth_frame = None

    def _build_first_run_screen(self):
        """Shown only when no vault file exists yet."""
        self._clear_auth_frame()

        frame = ttk.Frame(self, padding=32)
        self.auth_frame = frame
        frame.grid(row=0, column=0, sticky="nsew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        # Center grid
        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=2)

        header = ttk.Label(
            frame,
            text="Welcome to PassWarden",
            font=("Segoe UI Semibold", 18),
        )
        header.grid(row=0, column=0, columnspan=2, sticky="w", pady=(10, 4))

        subtitle = ttk.Label(
            frame,
            text="Create a master password to encrypt your vault.",
            foreground=SUBTLE_FG,
            font=("Segoe UI", 11),
        )
        subtitle.grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 20))

        self.fp_pass_var = tk.StringVar()
        self.fp_confirm_var = tk.StringVar()

        row = 2
        ttk.Label(frame, text="Master password:").grid(
            row=row, column=0, sticky="e", pady=8, padx=(0, 12)
        )
        ttk.Entry(frame, textvariable=self.fp_pass_var, show="*", width=40).grid(
            row=row, column=1, sticky="w", pady=8
        )
        row += 1

        ttk.Label(frame, text="Confirm:").grid(
            row=row, column=0, sticky="e", pady=8, padx=(0, 12)
        )
        ttk.Entry(frame, textvariable=self.fp_confirm_var, show="*", width=40).grid(
            row=row, column=1, sticky="w", pady=8
        )
        row += 1

        info = ttk.Label(
            frame,
            text="This password cannot be recovered. If you lose it, your data is lost.",
            foreground=SUBTLE_FG,
            wraplength=480,
            justify="left",
        )
        info.grid(row=row, column=0, columnspan=2, sticky="w", pady=(6, 20))
        row += 1

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=row, column=0, columnspan=2, sticky="e")

        ttk.Button(btn_frame, text="Exit", command=self.on_close).grid(
            row=0, column=0, padx=8
        )
        ttk.Button(
            btn_frame,
            text="Create vault",
            style="Primary.TButton",
            command=self._on_first_run_create,
        ).grid(row=0, column=1, padx=8)

    def _on_first_run_create(self):
        p1 = self.fp_pass_var.get() if self.fp_pass_var is not None else ""
        p2 = self.fp_confirm_var.get() if self.fp_confirm_var is not None else ""

        if not p1:
            messagebox.showerror("Error", "Password cannot be empty.", parent=self)
            return
        if len(p1) < 8:
            messagebox.showerror("Error", "Use at least 8 characters.", parent=self)
            return
        if p1 != p2:
            messagebox.showerror("Error", "Passwords do not match.", parent=self)
            return

        self.master_password = p1
        self.vault = new_empty_vault()
        self.settings = self.vault.setdefault("settings", {})
        save_vault_file(VAULT_PATH, self.vault, self.master_password)

        # Best-effort: clear the entered passwords from the auth screen
        if self.fp_pass_var is not None:
            self.fp_pass_var.set("")
        if self.fp_confirm_var is not None:
            self.fp_confirm_var.set("")

        # Now build the main UI
        self._clear_auth_frame()
        self._post_unlock_setup()

    def _build_unlock_screen(self):
        """Shown when a vault already exists and we need the master password."""
        self._clear_auth_frame()

        frame = ttk.Frame(self, padding=32)
        self.auth_frame = frame
        frame.grid(row=0, column=0, sticky="nsew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=2)

        header = ttk.Label(
            frame,
            text="Unlock PassWarden",
            font=("Segoe UI Semibold", 18),
        )
        header.grid(row=0, column=0, columnspan=2, sticky="w", pady=(10, 4))

        subtitle = ttk.Label(
            frame,
            text="Enter your master password to decrypt your vault.",
            foreground=SUBTLE_FG,
            font=("Segoe UI", 11),
        )
        subtitle.grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 20))

        self.ul_pass_var = tk.StringVar()

        row = 2
        ttk.Label(frame, text="Master password:").grid(
            row=row, column=0, sticky="e", pady=8, padx=(0, 12)
        )
        entry = ttk.Entry(frame, textvariable=self.ul_pass_var, show="*", width=40)
        entry.grid(row=2, column=1, sticky="w", pady=8)
        entry.focus_set()
        row += 1

        info = ttk.Label(
            frame,
            text="If the password is wrong, the vault cannot be decrypted.",
            foreground=SUBTLE_FG,
            wraplength=480,
            justify="left",
        )
        info.grid(row=row, column=0, columnspan=2, sticky="w", pady=(6, 20))
        row += 1

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=row, column=0, columnspan=2, sticky="e")

        ttk.Button(btn_frame, text="Exit", command=self.on_close).grid(
            row=0, column=0, padx=8
        )
        ttk.Button(
            btn_frame,
            text="Unlock",
            style="Primary.TButton",
            command=self._on_unlock,
        ).grid(row=0, column=1, padx=8)

    def _on_unlock(self):
        password = self.ul_pass_var.get() if self.ul_pass_var is not None else ""
        if not password:
            messagebox.showerror("Error", "Password cannot be empty.", parent=self)
            return
        try:
            vault = load_vault_file(VAULT_PATH, password)
        except (InvalidToken, KeyError, json.JSONDecodeError):
            messagebox.showerror(
                "Error",
                "Unable to decrypt vault. Master password is incorrect "
                "or file is corrupted.",
                parent=self,
            )
            return

        self.master_password = password
        self.vault = vault
        self.settings = self.vault.setdefault("settings", {})

        # Best-effort: clear the typed unlock password
        if self.ul_pass_var is not None:
            self.ul_pass_var.set("")

        self._clear_auth_frame()
        self._post_unlock_setup()

    # ------------------------------------------------------------------
    #  MAIN UI AFTER UNLOCK
    # ------------------------------------------------------------------

    def _post_unlock_setup(self):
        """Called once we have a decrypted vault + master password."""
        # Restore saved size if available
        self.settings = self.vault.setdefault("settings", self.settings or {})
        settings = self.settings
        try:
            sw = self.winfo_screenwidth()
            sh = self.winfo_screenheight()
            width = settings.get("window_width") or int(sw * 0.8)
            height = settings.get("window_height") or int(sh * 0.8)
            x = (sw - width) // 2
            y = (sh - height) // 2
            self.geometry(f"{width}x{height}+{x}+{y}")
        except Exception:
            pass

        # Build UI
        self._build_ui()
        self.refresh_entries_list()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        if UPDATE_INFO_URL:
            self.after(3000, lambda: self.check_for_updates(silent=True))

    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        self._build_menu()
        self._build_header()

        notebook = ttk.Notebook(self)
        notebook.grid(row=1, column=0, sticky="nsew")

        self.vault_tab = ttk.Frame(notebook)
        self.tools_tab = ttk.Frame(notebook)

        notebook.add(self.vault_tab, text="Vault")
        notebook.add(self.tools_tab, text="Tools")

        self._build_vault_tab(self.vault_tab)
        self._build_tools_tab(self.tools_tab)

    # ------------------------------------------------------------------
    #  MENU + HEADER
    # ------------------------------------------------------------------

    def _build_menu(self):
        menubar = tk.Menu(self, bg=BG_COLOR, fg="white", tearoff=False)

        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="Lock && exit", command=self.on_close)
        file_menu.add_separator()
        file_menu.add_command(
            label="Change master password...",
            command=self.change_master_password,
        )
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(
            label="Check for updates...", command=self.check_for_updates
        )
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

    def _build_header(self):
        # Top bar (NordPass-ish)
        header = ttk.Frame(self, style="Card.TFrame", padding=(20, 14))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)

        title_row = ttk.Frame(header, style="Card.TFrame")
        title_row.grid(row=0, column=0, sticky="w")

        # Teal dot
        dot = tk.Canvas(
            title_row,
            width=16,
            height=16,
            highlightthickness=0,
            bd=0,
            bg=HEADER_BG,
        )
        dot.grid(row=0, column=0, padx=(0, 10))
        dot.create_oval(2, 2, 14, 14, fill="#32d0c5", outline="")

        title = ttk.Label(
            title_row,
            text="PassWarden",
            font=("Segoe UI Semibold", 15),
        )
        title.grid(row=0, column=1, sticky="w")

        subtitle = ttk.Label(
            header,
            text="Secure password vault — local & encrypted",
            foreground=SUBTLE_FG,
            font=("Segoe UI", 11),
        )
        subtitle.grid(row=1, column=0, sticky="w", pady=(2, 0))

        # Thin accent bar
        accent = tk.Frame(
            header,
            height=2,
            bg=ACCENT_COLOR,
            bd=0,
            highlightthickness=0,
        )
        accent.grid(row=2, column=0, sticky="ew", pady=(10, 0))

    # ------------------------------------------------------------------
    #  VAULT TAB
    # ------------------------------------------------------------------

    def _build_vault_tab(self, parent: ttk.Frame):
        parent.columnconfigure(0, weight=2)
        parent.columnconfigure(1, weight=3)
        parent.rowconfigure(1, weight=1)

        toolbar = ttk.Frame(parent, padding=(10, 8, 10, 4))
        toolbar.grid(row=0, column=0, columnspan=2, sticky="ew")

        ttk.Button(
            toolbar, text="Add", style="Primary.TButton", command=self.add_entry
        ).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(toolbar, text="Edit", command=self.edit_selected_entry).grid(
            row=0, column=1, padx=8
        )
        ttk.Button(toolbar, text="Delete", command=self.delete_selected_entry).grid(
            row=0, column=2, padx=8
        )
        ttk.Button(
            toolbar, text="Copy password", command=self.copy_selected_password
        ).grid(row=0, column=3, padx=8)
        # Search box for filtering entries
        ttk.Label(toolbar, text="Search:").grid(row=0, column=4, padx=(20, 4))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(toolbar, textvariable=self.search_var, width=30)
        search_entry.grid(row=0, column=5, padx=(0, 4))
        search_entry.bind("<KeyRelease>", lambda e: self.apply_search_filter())

        # Entries list
        self.tree = ttk.Treeview(
            parent,
            columns=("name", "username", "url"),
            show="headings",
            selectmode="browse",
        )
        self.tree.heading("name", text="Name")
        self.tree.heading("username", text="Username")
        self.tree.heading("url", text="URL")
        self.tree.column("name", width=240)
        self.tree.column("username", width=180)
        self.tree.column("url", width=280)
        self.tree.grid(row=1, column=0, sticky="nsew", padx=(10, 4), pady=(0, 10))

        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=1, column=0, sticky="nse", padx=(0, 4), pady=(0, 10))

        self.tree.bind("<<TreeviewSelect>>", lambda e: self.show_selected_details())
        self.tree.bind("<Double-1>", lambda e: self.edit_selected_entry())

        detail_frame = ttk.LabelFrame(parent, text="Details", padding=(12, 10))
        detail_frame.grid(
            row=1, column=1, sticky="nsew", padx=(4, 10), pady=(0, 10)
        )
        detail_frame.columnconfigure(1, weight=1)
        detail_frame.rowconfigure(5, weight=1)

        self.detail_name = tk.StringVar()
        self.detail_username = tk.StringVar()
        self.detail_url = tk.StringVar()
        self.detail_created = tk.StringVar()
        self.detail_updated = tk.StringVar()

        ttk.Label(detail_frame, text="Name:").grid(
            row=0, column=0, sticky="e", pady=2
        )
        ttk.Label(detail_frame, textvariable=self.detail_name).grid(
            row=0, column=1, sticky="w", pady=2
        )

        ttk.Label(detail_frame, text="Username:").grid(
            row=1, column=0, sticky="e", pady=2
        )
        ttk.Label(detail_frame, textvariable=self.detail_username).grid(
            row=1, column=1, sticky="w", pady=2
        )

        ttk.Label(detail_frame, text="URL:").grid(
            row=2, column=0, sticky="e", pady=2
        )
        ttk.Label(detail_frame, textvariable=self.detail_url).grid(
            row=2, column=1, sticky="w", pady=2
        )

        ttk.Label(detail_frame, text="Created:").grid(
            row=3, column=0, sticky="e", pady=2
        )
        ttk.Label(detail_frame, textvariable=self.detail_created).grid(
            row=3, column=1, sticky="w", pady=2
        )

        ttk.Label(detail_frame, text="Updated:").grid(
            row=4, column=0, sticky="e", pady=2
        )
        ttk.Label(detail_frame, textvariable=self.detail_updated).grid(
            row=4, column=1, sticky="w", pady=2
        )

        ttk.Label(detail_frame, text="Notes:").grid(
            row=5, column=0, sticky="ne", pady=2
        )
        self.detail_notes = tk.Text(
            detail_frame,
            width=40,
            height=8,
            bg=ENTRY_BG,
            fg=ENTRY_FG,
            insertbackground=ENTRY_FG,
            relief="flat",
            borderwidth=1,
        )
        self.detail_notes.grid(row=5, column=1, sticky="nsew", pady=2)

    # ------------------------------------------------------------------
    #  TOOLS TAB
    # ------------------------------------------------------------------

    def _build_tools_tab(self, parent: ttk.Frame):
        parent.columnconfigure(0, weight=1)
        parent.columnconfigure(1, weight=1)
        parent.rowconfigure(0, weight=1)

        generator_frame = ttk.LabelFrame(
            parent, text="Password generator", padding=(16, 12)
        )
        generator_frame.grid(row=0, column=0, sticky="nsew", padx=(10, 4), pady=10)
        self._build_generator_panel(generator_frame)

        analyzer_frame = ttk.LabelFrame(
            parent, text="Password analyzer", padding=(16, 12)
        )
        analyzer_frame.grid(row=0, column=1, sticky="nsew", padx=(4, 10), pady=10)
        self._build_analyzer_panel(analyzer_frame)

    # ----- Generator panel -----

    def _build_generator_panel(self, frame: ttk.Frame):
        frame.columnconfigure(0, weight=1)

        self.gen_length_var = tk.IntVar(value=20)
        self.gen_use_lower = tk.BooleanVar(value=True)
        self.gen_use_upper = tk.BooleanVar(value=True)
        self.gen_use_digits = tk.BooleanVar(value=True)
        self.gen_use_symbols = tk.BooleanVar(value=True)
        self.gen_password_var = tk.StringVar(value="")
        self.gen_entropy_var = tk.StringVar(value="")
        self.gen_crack_var = tk.StringVar(value="")

        ttk.Label(frame, text="Generated password:").grid(
            row=0, column=0, sticky="w", pady=(0, 4)
        )
        self.gen_entry = ttk.Entry(
            frame, textvariable=self.gen_password_var, width=50
        )
        self.gen_entry.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 8))

        ttk.Label(frame, textvariable=self.gen_entropy_var, foreground=SUBTLE_FG).grid(
            row=2, column=0, columnspan=3, sticky="w", pady=(0, 2)
        )
        ttk.Label(frame, textvariable=self.gen_crack_var, foreground=SUBTLE_FG).grid(
            row=3, column=0, columnspan=3, sticky="w", pady=(0, 10)
        )

        ttk.Label(frame, text="Length:").grid(row=4, column=0, sticky="w")
        self.gen_length_spin = ttk.Spinbox(
            frame,
            from_=8,
            to=64,
            textvariable=self.gen_length_var,
            width=5,
            command=self._gen_on_spin,
        )
        self.gen_length_spin.grid(row=4, column=1, sticky="w")

        self.gen_length_scale = ttk.Scale(
            frame, from_=8, to=64, orient="horizontal", command=self._gen_on_scale
        )
        self.gen_length_scale.set(self.gen_length_var.get())
        self.gen_length_scale.grid(
            row=5, column=0, columnspan=3, sticky="ew", pady=(4, 12)
        )

        row = 6
        ttk.Checkbutton(
            frame,
            text="Use lowercase (a-z)",
            variable=self.gen_use_lower,
            command=self.update_generator,
        ).grid(row=row, column=0, sticky="w")
        row += 1
        ttk.Checkbutton(
            frame,
            text="Use uppercase (A-Z)",
            variable=self.gen_use_upper,
            command=self.update_generator,
        ).grid(row=row, column=0, sticky="w")
        row += 1
        ttk.Checkbutton(
            frame,
            text="Use digits (0-9)",
            variable=self.gen_use_digits,
            command=self.update_generator,
        ).grid(row=row, column=0, sticky="w")
        row += 1
        ttk.Checkbutton(
            frame,
            text="Use symbols (!@#$%^&*)",
            variable=self.gen_use_symbols,
            command=self.update_generator,
        ).grid(row=row, column=0, sticky="w")
        row += 1

        # Clipboard timeout configuration
        timeout_ms = 15000
        if self.settings is not None:
            timeout_ms = int(self.settings.get("clipboard_timeout_ms", timeout_ms))
        timeout_seconds = max(5, timeout_ms // 1000)

        ttk.Label(frame, text="Clipboard auto-clear:").grid(
            row=row, column=0, sticky="w", pady=(10, 0)
        )
        self.clipboard_timeout_var = tk.IntVar(value=timeout_seconds)
        self.clipboard_timeout_spin = ttk.Spinbox(
            frame,
            from_=5,
            to=300,
            textvariable=self.clipboard_timeout_var,
            width=5,
            command=self._on_clipboard_timeout_changed,
        )
        self.clipboard_timeout_spin.grid(row=row, column=1, sticky="w", pady=(10, 0))
        row += 1

        ttk.Label(
            frame,
            text=(
                "Passwords copied to the clipboard will be cleared after this "
                "many seconds (best-effort)."
            ),
            foreground=SUBTLE_FG,
            wraplength=360,
            justify="left",
        ).grid(row=row, column=0, columnspan=3, sticky="w", pady=(4, 0))
        row += 1

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=row, column=0, columnspan=3, sticky="e", pady=(14, 2))

        ttk.Button(btn_frame, text="Regenerate", command=self.update_generator).grid(
            row=0, column=0, padx=8
        )
        ttk.Button(
            btn_frame,
            text="Copy",
            style="Primary.TButton",
            command=self.gen_copy,
        ).grid(row=0, column=1, padx=8)

        self.update_generator()

    def _on_clipboard_timeout_changed(self):
        if self.settings is None:
            return
        try:
            value = int(self.clipboard_timeout_var.get())
        except Exception:
            return
        # Clamp between 5 and 300 seconds
        value = max(5, min(300, value))
        self.clipboard_timeout_var.set(value)
        self.settings["clipboard_timeout_ms"] = value * 1000
        # Persist new setting
        if self.vault is not None and self.master_password is not None:
            self._save_vault()

    def _gen_on_scale(self, value):
        self.gen_length_var.set(int(float(value)))
        self.update_generator()

    def _gen_on_spin(self):
        try:
            value = int(self.gen_length_var.get())
        except Exception:
            return
        value = max(8, min(64, value))
        self.gen_length_var.set(value)
        self.gen_length_scale.set(value)
        self.update_generator()

    def update_generator(self):
        try:
            pwd = generate_password(
                length=self.gen_length_var.get(),
                use_lower=self.gen_use_lower.get(),
                use_upper=self.gen_use_upper.get(),
                use_digits=self.gen_use_digits.get(),
                use_symbols=self.gen_use_symbols.get(),
            )
        except ValueError as e:
            messagebox.showerror("Error", str(e), parent=self)
            return

        self.gen_password_var.set(pwd)

        alphabet_size = (
            (26 if self.gen_use_lower.get() else 0)
            + (26 if self.gen_use_upper.get() else 0)
            + (10 if self.gen_use_digits.get() else 0)
            + (32 if self.gen_use_symbols.get() else 0)
        )
        bits = estimate_entropy_bits(self.gen_length_var.get(), alphabet_size)
        seconds = estimate_crack_time_seconds(bits)

        self.gen_entropy_var.set(f"Entropy: {bits:.1f} bits")
        self.gen_crack_var.set(
            f"Brute force @ 10¹⁰ guesses/s: ≈ {format_duration(seconds)}"
        )

    def _schedule_clipboard_clear(self, expected: str) -> None:
        """
        Schedule a best-effort clipboard clear using the configured timeout.

        The clipboard is only cleared if it still contains the same value that
        was originally copied, to avoid wiping something the user copied later.
        """
        timeout_ms = 15000
        if self.settings is not None:
            timeout_ms = int(self.settings.get("clipboard_timeout_ms", timeout_ms))

        def clear_if_match():
            try:
                current = self.clipboard_get()
            except tk.TclError:
                # Clipboard not available or empty; nothing to do
                return
            if current == expected:
                try:
                    self.clipboard_clear()
                except tk.TclError:
                    # If we can't clear it (e.g. clipboard ownership lost),
                    # we just ignore the error.
                    pass

        self.after(timeout_ms, clear_if_match)

    def gen_copy(self):
        pwd = self.gen_password_var.get()
        if not pwd:
            return
        self.clipboard_clear()
        self.clipboard_append(pwd)
        # Auto-clear clipboard after a short delay if it still holds this password
        self._schedule_clipboard_clear(pwd)

        timeout_ms = 15000
        if self.settings is not None:
            timeout_ms = int(self.settings.get("clipboard_timeout_ms", timeout_ms))
        timeout_seconds = max(1, timeout_ms // 1000)
        messagebox.showinfo(
            "Copied",
            (
                "Password copied to clipboard.\n\n"
                f"Clipboard will auto-clear in about {timeout_seconds} seconds "
                "(best-effort)."
            ),
            parent=self,
        )

    # ----- Analyzer panel -----

    def _build_analyzer_panel(self, frame: ttk.Frame):
        frame.columnconfigure(1, weight=1)

        self.an_pwd_var = tk.StringVar()
        self.an_show_var = tk.BooleanVar(value=False)
        self.an_length_var = tk.StringVar(value="-")
        self.an_alphabet_var = tk.StringVar(value="-")
        self.an_entropy_var = tk.StringVar(value="-")
        self.an_crack_var = tk.StringVar(value="-")

        ttk.Label(frame, text="Password:").grid(
            row=0, column=0, sticky="e", pady=4, padx=(0, 8)
        )
        self.an_entry = ttk.Entry(
            frame, textvariable=self.an_pwd_var, show="*", width=32
        )
        self.an_entry.grid(row=0, column=1, sticky="ew", pady=4)
        self.an_entry.bind("<KeyRelease>", lambda e: self.update_analyzer())

        ttk.Checkbutton(
            frame, text="Show", variable=self.an_show_var, command=self._an_toggle_show
        ).grid(row=0, column=2, sticky="w", pady=4)

        row = 1
        ttk.Label(frame, text="Length:").grid(
            row=row, column=0, sticky="e", pady=2, padx=(0, 8)
        )
        ttk.Label(frame, textvariable=self.an_length_var).grid(
            row=row, column=1, sticky="w", pady=2
        )
        row += 1

        ttk.Label(frame, text="Alphabet size:").grid(
            row=row, column=0, sticky="e", pady=2, padx=(0, 8)
        )
        ttk.Label(frame, textvariable=self.an_alphabet_var).grid(
            row=row, column=1, sticky="w", pady=2
        )
        row += 1

        ttk.Label(frame, text="Entropy:").grid(
            row=row, column=0, sticky="e", pady=2, padx=(0, 8)
        )
        ttk.Label(frame, textvariable=self.an_entropy_var).grid(
            row=row, column=1, sticky="w", pady=2
        )
        row += 1

        ttk.Label(frame, text="Brute force time:").grid(
            row=row, column=0, sticky="e", pady=2, padx=(0, 8)
        )
        ttk.Label(frame, textvariable=self.an_crack_var, wraplength=280).grid(
            row=row, column=1, columnspan=2, sticky="w", pady=2
        )
        row += 1

        ttk.Label(
            frame,
            text="Assuming 10¹⁰ guesses per second\nand ideal brute-force attacker.",
            foreground=SUBTLE_FG,
        ).grid(row=row, column=0, columnspan=3, sticky="w", pady=(8, 0))

    def _an_toggle_show(self):
        self.an_entry.configure(show="" if self.an_show_var.get() else "*")

    def update_analyzer(self):
        pwd = self.an_pwd_var.get()
        analysis = analyze_arbitrary_password(pwd)

        self.an_length_var.set(str(analysis.length))
        self.an_alphabet_var.set(str(analysis.alphabet_size))

        if analysis.length == 0 or analysis.alphabet_size == 0:
            self.an_entropy_var.set("-")
            self.an_crack_var.set("-")
            return

        self.an_entropy_var.set(
            f"{analysis.bits:.1f} bits ({analysis.strength_label})"
        )
        self.an_crack_var.set(analysis.crack_duration_text)

    # ------------------------------------------------------------------
    #  VAULT OPERATIONS
    # ------------------------------------------------------------------

    def _save_vault(self):
        save_vault_file(VAULT_PATH, self.vault, self.master_password)

    def _get_entries(self):
        return self.vault.setdefault("entries", [])

    def _find_entry_by_id(self, entry_id):
        for e in self._get_entries():
            if e["id"] == entry_id:
                return e
        return None

    def refresh_entries_list(self, filter_text: str | None = None):
        self.tree.delete(*self.tree.get_children())
        for entry in self._get_entries():
            if filter_text:
                q = filter_text.lower()
                haystack = " ".join(
                    [
                        entry.get("name", ""),
                        entry.get("username", ""),
                        entry.get("url", ""),
                        entry.get("notes", ""),
                    ]
                ).lower()
                if q not in haystack:
                    continue
            self.tree.insert(
                "",
                "end",
                iid=entry["id"],
                values=(
                    entry["name"],
                    entry.get("username", ""),
                    entry.get("url", ""),
                ),
            )

    def apply_search_filter(self):
        """Filter the entries list based on the search box."""
        if self.search_var is None:
            self.refresh_entries_list()
            return
        query = self.search_var.get().strip()
        if not query:
            self.refresh_entries_list()
        else:
            self.refresh_entries_list(filter_text=query)

    def show_selected_details(self):
        selection = self.tree.selection()
        if not selection:
            self.detail_name.set("")
            self.detail_username.set("")
            self.detail_url.set("")
            self.detail_created.set("")
            self.detail_updated.set("")
            self.detail_notes.delete("1.0", "end")
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
        self.detail_notes.delete("1.0", "end")
        self.detail_notes.insert("1.0", entry.get("notes", ""))

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
            messagebox.showinfo(
                "No selection", "Select an entry to edit.", parent=self
            )
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
            messagebox.showinfo(
                "No selection", "Select an entry to delete.", parent=self
            )
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

        self.vault["entries"] = [
            e for e in self._get_entries() if e["id"] != entry_id
        ]
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
        # Auto-clear clipboard after a short delay if it still holds this password
        self._schedule_clipboard_clear(pwd)

        timeout_ms = 15000
        if self.settings is not None:
            timeout_ms = int(self.settings.get("clipboard_timeout_ms", timeout_ms))
        timeout_seconds = max(1, timeout_ms // 1000)
        messagebox.showinfo(
            "Copied",
            (
                "Password copied to clipboard.\n\n"
                f"Clipboard will auto-clear in about {timeout_seconds} seconds "
                "(best-effort)."
            ),
            parent=self,
        )

    # ------------------------------------------------------------------
    #  CHANGE MASTER PASSWORD
    # ------------------------------------------------------------------

    def change_master_password(self):
        """Let the user update the master password while the vault is unlocked."""
        if self.vault is None or self.master_password is None:
            messagebox.showerror(
                "Error",
                "Vault is not loaded. Unlock the vault first.",
                parent=self,
            )
            return

        dlg = ChangeMasterPasswordDialog(self)
        self.wait_window(dlg)
        if dlg.result is None:
            return

        current = dlg.result["current"]
        new_pw = dlg.result["new"]

        if current != self.master_password:
            messagebox.showerror(
                "Error",
                "Current master password is incorrect.",
                parent=self,
            )
            return

        # Update in memory and re-encrypt vault with new password.
        # We keep the new password in memory (for the session) and best-effort
        # wipe the old value.
        old_master = self.master_password
        self.master_password = new_pw
        if old_master:
            wipe_string(old_master)

        self._save_vault()

        messagebox.showinfo(
            "Master password changed",
            "Your master password has been updated.",
            parent=self,
        )

    # ------------------------------------------------------------------
    #  UPDATES + CLOSE
    # ------------------------------------------------------------------

    def check_for_updates(self, silent=False):
        if not UPDATE_INFO_URL:
            if not silent:
                messagebox.showinfo(
                    "Check for updates",
                    "Update checking is disabled in this build.",
                    parent=self,
                )
            return

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
                "Open the download page?",
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

    def on_close(self):
        # Persist window size for next run
        if self.vault is not None:
            try:
                size = self.geometry().split("+")[0]
                width, height = size.split("x")
                settings = self.vault.setdefault("settings", self.settings or {})
                settings["window_width"] = int(width)
                settings["window_height"] = int(height)
                self.settings = settings
            except Exception:
                pass
            self._save_vault()

        # Best-effort: clear any password variables still hanging around
        for attr in ("ul_pass_var", "fp_pass_var", "fp_confirm_var"):
            var = getattr(self, attr, None)
            if isinstance(var, tk.StringVar):
                var.set("")

        # Best-effort: wipe master password reference
        if self.master_password is not None:
            wipe_string(self.master_password)
            self.master_password = None

        # Drop decrypted vault from memory
        self.vault = None
        self.settings = None

        self.destroy()
