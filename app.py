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
from ui_theme import configure_dark_theme, BG_COLOR, ENTRY_BG, ENTRY_FG
from dialogs import (
    MasterPasswordDialog,
    UnlockDialog,
    EntryDialog,
    PasswordGeneratorDialog,
    PasswordAnalysisDialog,
)


APP_NAME = "PassWarden"
APP_VERSION = "0.2.0"  # bumped because of new features

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VAULT_FILENAME = "vault.pw"
VAULT_PATH = os.path.join(BASE_DIR, VAULT_FILENAME)

# This file can live in your repo; or you can disable updates by setting this to None.
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
        self.vault = None  # dict with "entries" & "settings"

        if not self._unlock_or_initialize():
            self.destroy()
            return

        # HiDPI-friendly sizing: default to 80% of screen if nothing saved yet
        settings = self.vault.setdefault("settings", {})
        width = settings.get("window_width")
        height = settings.get("window_height")
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()

        if not width or not height:
            width = int(sw * 0.8)
            height = int(sh * 0.8)

        x = (sw - width) // 2
        y = (sh - height) // 2
        self.geometry(f"{width}x{height}+{x}+{y}")

        self._build_ui()
        self.refresh_entries_list()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        if UPDATE_INFO_URL:
            self.after(3000, lambda: self.check_for_updates(silent=True))

    # ----- unlock/init -----

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

    # ----- UI -----

    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        self._build_menu()

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
        ttk.Button(toolbar, text="Analyze password", command=self.open_analyzer).grid(row=0, column=5, padx=2)

        # Entries list
        self.tree = ttk.Treeview(
            main,
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
        self.tree.grid(row=1, column=0, sticky="nsew", padx=(0, 5))

        scrollbar = ttk.Scrollbar(main, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=1, column=0, sticky="nse", padx=(0, 0))

        self.tree.bind("<<TreeviewSelect>>", lambda e: self.show_selected_details())

        # Details panel
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
        self.detail_notes = tk.Text(
            detail_frame,
            width=40,
            height=8,
            bg=ENTRY_BG,
            fg=ENTRY_FG,
            insertbackground=ENTRY_FG,
            relief="flat",
        )
        self.detail_notes.grid(row=5, column=1, sticky="nsew")

    def _build_menu(self):
        menubar = tk.Menu(self, bg=BG_COLOR, fg="white", tearoff=False)
        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="Lock && exit", command=self.on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(
            label="Check for updates...",
            command=self.check_for_updates,
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

    # ----- vault helpers -----

    def _save_vault(self):
        save_vault_file(VAULT_PATH, self.vault, self.master_password)

    def _get_entries(self):
        return self.vault.setdefault("entries", [])

    def _find_entry_by_id(self, entry_id):
        for e in self._get_entries():
            if e["id"] == entry_id:
                return e
        return None

    # ----- UI actions -----

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

    def open_generator(self):
        PasswordGeneratorDialog(self)

    def open_analyzer(self):
        PasswordAnalysisDialog(self)

    # ----- update check -----

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

    # ----- closing / settings -----

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
