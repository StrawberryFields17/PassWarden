import json
import os
import secrets
from datetime import datetime

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
)
from dialogs import MasterPasswordDialog, UnlockDialog, EntryDialog
from password_utils import (
    generate_password,
    estimate_entropy_bits,
    estimate_crack_time_seconds,
    format_duration,
    analyze_arbitrary_password,
)

APP_NAME = "PassWarden"
APP_VERSION = "0.3.0"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VAULT_FILENAME = "vault.pw"
VAULT_PATH = os.path.join(BASE_DIR, VAULT_FILENAME)

UPDATE_INFO_URL = (
    "https://raw.githubusercontent.com/StrawberryFields17/PassWarden/main/update.json"
)


def parse_version(v: str):
    return tuple(int(x) for x in v.split("."))


class PassWardenApp(tk.Tk):
    def __init__(self):
        super().__init__()

        configure_dark_theme(self)
        self.title(APP_NAME)

        self.master_password = None
        self.vault = None

        if not self._unlock_or_initialize():
            self.destroy()
            return

        settings = self.vault.setdefault("settings", {})
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        width = settings.get("window_width") or int(sw * 0.8)
        height = settings.get("window_height") or int(sh * 0.8)
        x = (sw - width) // 2
        y = (sh - height) // 2
        self.geometry(f"{width}x{height}+{x}+{y}")

        self._build_ui()
        self.refresh_entries_list()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        if UPDATE_INFO_URL:
            self.after(3000, lambda: self.check_for_updates(silent=True))

    # ----- unlock / initialize -----

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

    # ----- UI -----

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

    def _build_menu(self):
        menubar = tk.Menu(self, bg=BG_COLOR, fg="white", tearoff=False)

        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="Lock && exit", command=self.on_close)
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

    def _build_header(self):
        header = ttk.Frame(self, style="Card.TFrame", padding=(18, 12))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)

        # Left section: app title
        title_row = ttk.Frame(header, style="Card.TFrame")
        title_row.grid(row=0, column=0, sticky="w")
        dot = tk.Canvas(title_row, width=14, height=14, highlightthickness=0, bg=header["background"])
        dot.grid(row=0, column=0, padx=(0, 8))
        dot.create_oval(2, 2, 12, 12, fill="#32d0c5", outline="")

        title = ttk.Label(
            title_row,
            text="PassWarden",
            font=("Segoe UI Semibold", 13),
        )
        title.grid(row=0, column=1, sticky="w")

        subtitle = ttk.Label(
            header,
            text="Secure password vault — local & encrypted",
            foreground=SUBTLE_FG,
        )
        subtitle.grid(row=1, column=0, sticky="w", pady=(2, 0))

        # Accent bar at bottom of header
        accent = tk.Frame(self, height=2, bg="#32d0c5", bd=0, highlightthickness=0)
        accent.grid(row=0, column=0, sticky="sew", pady=(0, 0))


    # --- Vault tab ---

    def _build_vault_tab(self, parent: ttk.Frame):
        parent.columnconfigure(0, weight=2)
        parent.columnconfigure(1, weight=3)
        parent.rowconfigure(1, weight=1)

        toolbar = ttk.Frame(parent, padding=(8, 8, 8, 4))
        toolbar.grid(row=0, column=0, columnspan=2, sticky="ew")

        ttk.Button(toolbar, text="Add", style="Primary.TButton", command=self.add_entry).grid(
            row=0, column=0, padx=(0, 6)
        )
        ttk.Button(toolbar, text="Edit", command=self.edit_selected_entry).grid(
            row=0, column=1, padx=6
        )
        ttk.Button(toolbar, text="Delete", command=self.delete_selected_entry).grid(
            row=0, column=2, padx=6
        )
        ttk.Button(toolbar, text="Copy password", command=self.copy_selected_password).grid(
            row=0, column=3, padx=6
        )

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
        self.tree.column("name", width=220)
        self.tree.column("username", width=160)
        self.tree.column("url", width=260)
        self.tree.grid(row=1, column=0, sticky="nsew", padx=(8, 4), pady=(0, 8))

        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=1, column=0, sticky="nse", padx=(0, 4), pady=(0, 8))

        self.tree.bind("<<TreeviewSelect>>", lambda e: self.show_selected_details())

        detail_frame = ttk.LabelFrame(parent, text="Details", padding=(10, 8))
        detail_frame.grid(row=1, column=1, sticky="nsew", padx=(4, 8), pady=(0, 8))
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
        self.detail_notes.grid(row=5, column=1, sticky="nsew")

    # --- Tools tab ---

    def _build_tools_tab(self, parent: ttk.Frame):
        parent.columnconfigure(0, weight=1)
        parent.columnconfigure(1, weight=1)
        parent.rowconfigure(0, weight=1)

        generator_frame = ttk.LabelFrame(parent, text="Password generator", padding=(14, 10))
        generator_frame.grid(row=0, column=0, sticky="nsew", padx=(8, 4), pady=8)
        self._build_generator_panel(generator_frame)

        analyzer_frame = ttk.LabelFrame(parent, text="Password analyzer", padding=(14, 10))
        analyzer_frame.grid(row=0, column=1, sticky="nsew", padx=(4, 8), pady=8)
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

        ttk.Label(frame, text="Generated password:").grid(row=0, column=0, sticky="w")
        self.gen_entry = ttk.Entry(frame, textvariable=self.gen_password_var, width=50)
        self.gen_entry.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(2, 6))

        ttk.Label(frame, textvariable=self.gen_entropy_var, foreground=SUBTLE_FG).grid(
            row=2, column=0, columnspan=3, sticky="w"
        )
        ttk.Label(frame, textvariable=self.gen_crack_var, foreground=SUBTLE_FG).grid(
            row=3, column=0, columnspan=3, sticky="w", pady=(0, 8)
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
        self.gen_length_scale.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(4, 10))

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

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=row, column=0, columnspan=3, sticky="e", pady=(12, 2))

        ttk.Button(btn_frame, text="Regenerate", command=self.update_generator).grid(
            row=0, column=0, padx=6
        )
        ttk.Button(btn_frame, text="Copy", style="Primary.TButton", command=self.gen_copy).grid(
            row=0, column=1, padx=6
        )

        self.update_generator()

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
            + (32 if self.gen_use_symbols.get() else 0)  # rough symbol count
        )
        bits = estimate_entropy_bits(self.gen_length_var.get(), alphabet_size)
        seconds = estimate_crack_time_seconds(bits)

        self.gen_entropy_var.set(f"Entropy: {bits:.1f} bits")
        self.gen_crack_var.set(
            f"Brute force @ 10¹⁰ guesses/s: ≈ {format_duration(seconds)}"
        )

    def gen_copy(self):
        pwd = self.gen_password_var.get()
        if not pwd:
            return
        self.clipboard_clear()
        self.clipboard_append(pwd)
        messagebox.showinfo("Copied", "Password copied to clipboard.", parent=self)

    # ----- Analyzer panel -----

    def _build_analyzer_panel(self, frame: ttk.Frame):
        frame.columnconfigure(1, weight=1)

        self.an_pwd_var = tk.StringVar()
        self.an_show_var = tk.BooleanVar(value=False)
        self.an_length_var = tk.StringVar(value="-")
        self.an_alphabet_var = tk.StringVar(value="-")
        self.an_entropy_var = tk.StringVar(value="-")
        self.an_crack_var = tk.StringVar(value="-")

        ttk.Label(frame, text="Password:").grid(row=0, column=0, sticky="e", pady=2, padx=(0, 8))
        self.an_entry = ttk.Entry(frame, textvariable=self.an_pwd_var, show="*", width=32)
        self.an_entry.grid(row=0, column=1, sticky="ew", pady=2)
        self.an_entry.bind("<KeyRelease>", lambda e: self.update_analyzer())

        ttk.Checkbutton(
            frame, text="Show", variable=self.an_show_var, command=self._an_toggle_show
        ).grid(row=0, column=2, sticky="w")

        row = 1
        ttk.Label(frame, text="Length:").grid(row=row, column=0, sticky="e", pady=2, padx=(0, 8))
        ttk.Label(frame, textvariable=self.an_length_var).grid(
            row=row, column=1, sticky="w", pady=2
        )
        row += 1

        ttk.Label(frame, text="Alphabet size:").grid(row=row, column=0, sticky="e", pady=2, padx=(0, 8))
        ttk.Label(frame, textvariable=self.an_alphabet_var).grid(
            row=row, column=1, sticky="w", pady=2
        )
        row += 1

        ttk.Label(frame, text="Entropy:").grid(row=row, column=0, sticky="e", pady=2, padx=(0, 8))
        ttk.Label(frame, textvariable=self.an_entropy_var).grid(
            row=row, column=1, sticky="w", pady=2
        )
        row += 1

        ttk.Label(frame, text="Brute force time:").grid(
            row=row, column=0, sticky="e", pady=2, padx=(0, 8)
        )
        ttk.Label(frame, textvariable=self.an_crack_var, wraplength=260).grid(
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

        self.an_entropy_var.set(f"{analysis.bits:.1f} bits ({analysis.strength_label})")
        self.an_crack_var.set(analysis.crack_duration_text)

    # ----- Vault helpers & actions -----

    def _save_vault(self):
        save_vault_file(VAULT_PATH, self.vault, self.master_password)

    def _get_entries(self):
        return self.vault.setdefault("entries", [])

    def _find_entry_by_id(self, entry_id):
        for e in self._get_entries():
            if e["id"] == entry_id:
                return e
        return None

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

    # ----- updates -----

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

    # ----- closing -----

    def on_close(self):
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
