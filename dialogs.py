import tkinter as tk
from tkinter import ttk, messagebox

from ui_theme import BG_COLOR, ENTRY_BG, ENTRY_FG


class MasterPasswordDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Set master password")
        self.resizable(False, False)
        self.configure(bg=BG_COLOR)
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
            text="Create a master password.\nIf you forget it, your vault cannot be recovered.",
            wraplength=340,
        ).grid(row=0, column=0, columnspan=2, pady=(0, 10))

        ttk.Label(main, text="Master password:").grid(row=1, column=0, sticky="e", pady=2)
        ttk.Entry(main, textvariable=self.pass_var, show="*", width=32).grid(
            row=1, column=1, pady=2
        )

        ttk.Label(main, text="Confirm:").grid(row=2, column=0, sticky="e", pady=2)
        ttk.Entry(main, textvariable=self.confirm_var, show="*", width=32).grid(
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
        self.configure(bg=BG_COLOR)
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
            wraplength=340,
        ).grid(row=0, column=0, columnspan=2, pady=(0, 10))

        ttk.Label(main, text="Master password:").grid(row=1, column=0, sticky="e", pady=2)
        entry = ttk.Entry(main, textvariable=self.pass_var, show="*", width=32)
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


class EntryDialog(tk.Toplevel):
    def __init__(self, parent, title, entry=None):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.configure(bg=BG_COLOR)
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
        ttk.Entry(main, textvariable=self.password_var, show="*", width=40).grid(
            row=row, column=1, sticky="w", pady=2
        )
        row += 1

        ttk.Label(main, text="URL:").grid(row=row, column=0, sticky="e", pady=2)
        ttk.Entry(main, textvariable=self.url_var, width=40).grid(
            row=row, column=1, sticky="w", pady=2
        )
        row += 1

        ttk.Label(main, text="Notes:").grid(row=row, column=0, sticky="ne", pady=2)
        notes = tk.Text(
            main,
            width=40,
            height=5,
            bg=ENTRY_BG,
            fg=ENTRY_FG,
            insertbackground=ENTRY_FG,
            relief="flat",
        )
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
