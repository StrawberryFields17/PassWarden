import tkinter as tk
from tkinter import ttk, messagebox

from ui_theme import BG_COLOR, ENTRY_BG, ENTRY_FG, SUBTLE_FG


def center_window(win: tk.Toplevel | tk.Tk, width: int | None = None, height: int | None = None):
    win.update_idletasks()
    if width and height:
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        x = (sw - width) // 2
        y = (sh - height) // 2
        win.geometry(f"{width}x{height}+{x}+{y}")
    else:
        # center current size
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        w = win.winfo_width()
        h = win.winfo_height()
        x = (sw - w) // 2
        y = (sh - h) // 2
        win.geometry(f"+{x}+{y}")


class MasterPasswordDialog(tk.Toplevel):
    """
    Shown only the very first time (when no vault file exists).
    """

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
        center_window(self, width=420, height=210)
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)

    def _build_ui(self):
        main = ttk.Frame(self, padding=16)
        main.grid(row=0, column=0, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)

        header = ttk.Label(
            main,
            text="Create your master password",
            font=("Segoe UI Semibold", 12),
        )
        header.grid(row=0, column=0, columnspan=2, sticky="w")

        subtitle = ttk.Label(
            main,
            text="This password encrypts your vault. If you lose it, your data "
                 "cannot be recovered.",
            foreground=SUBTLE_FG,
            wraplength=380,
        )
        subtitle.grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 14))

        ttk.Label(main, text="Master password:").grid(row=2, column=0, sticky="e", pady=4, padx=(0, 8))
        ttk.Entry(main, textvariable=self.pass_var, show="*", width=32).grid(
            row=2, column=1, sticky="w", pady=4
        )

        ttk.Label(main, text="Confirm:").grid(row=3, column=0, sticky="e", pady=4, padx=(0, 8))
        ttk.Entry(main, textvariable=self.confirm_var, show="*", width=32).grid(
            row=3, column=1, sticky="w", pady=4
        )

        btn_frame = ttk.Frame(main)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=(16, 0), sticky="e")

        ttk.Button(btn_frame, text="Cancel", command=self.on_cancel).grid(
            row=0, column=0, padx=6
        )
        ttk.Button(btn_frame, text="Create", style="Primary.TButton", command=self.on_ok).grid(
            row=0, column=1, padx=6
        )

    def on_ok(self):
        p1 = self.pass_var.get()
        p2 = self.confirm_var.get()
        if not p1:
            messagebox.showerror("Error", "Password cannot be empty.", parent=self)
            return
        if len(p1) < 8:
            messagebox.showerror("Error", "Use at least 8 characters.", parent=self)
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
    """
    Shown on subsequent runs when a vault already exists.
    """

    def __init__(self, parent):
        super().__init__(parent)
        self.title("Unlock PassWarden")
        self.resizable(False, False)
        self.configure(bg=BG_COLOR)
        self.result = None
        self.pass_var = tk.StringVar()

        self._build_ui()
        self.transient(parent)
        self.grab_set()
        center_window(self, width=380, height=170)
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)

    def _build_ui(self):
        main = ttk.Frame(self, padding=16)
        main.grid(row=0, column=0, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)

        header = ttk.Label(
            main,
            text="Unlock your vault",
            font=("Segoe UI Semibold", 12),
        )
        header.grid(row=0, column=0, columnspan=2, sticky="w")

        subtitle = ttk.Label(
            main,
            text="Enter your master password to decrypt your stored passwords.",
            foreground=SUBTLE_FG,
            wraplength=340,
        )
        subtitle.grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 12))

        ttk.Label(main, text="Master password:").grid(row=2, column=0, sticky="e", pady=4, padx=(0, 8))
        entry = ttk.Entry(main, textvariable=self.pass_var, show="*", width=28)
        entry.grid(row=2, column=1, sticky="w", pady=4)
        entry.focus_set()

        btn_frame = ttk.Frame(main)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=(16, 0), sticky="e")

        ttk.Button(btn_frame, text="Cancel", command=self.on_cancel).grid(
            row=0, column=0, padx=6
        )
        ttk.Button(btn_frame, text="Unlock", style="Primary.TButton", command=self.on_ok).grid(
            row=0, column=1, padx=6
        )

    def on_ok(self):
        self.result = self.pass_var.get()
        self.destroy()

    def on_cancel(self):
        self.result = None
        self.destroy()


class EntryDialog(tk.Toplevel):
    """
    Add/edit an entry (still a dialog, but more polished).
    """

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
        center_window(self, width=520, height=320)
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)

    def _build_ui(self):
        main = ttk.Frame(self, padding=16)
        main.grid(row=0, column=0, sticky="nsew")
        main.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(main, text="Name:").grid(row=row, column=0, sticky="e", pady=4, padx=(0, 8))
        ttk.Entry(main, textvariable=self.name_var, width=40).grid(
            row=row, column=1, sticky="ew", pady=4
        )
        row += 1

        ttk.Label(main, text="Username:").grid(row=row, column=0, sticky="e", pady=4, padx=(0, 8))
        ttk.Entry(main, textvariable=self.username_var, width=40).grid(
            row=row, column=1, sticky="ew", pady=4
        )
        row += 1

        ttk.Label(main, text="Password:").grid(row=row, column=0, sticky="e", pady=4, padx=(0, 8))
        ttk.Entry(main, textvariable=self.password_var, show="*", width=40).grid(
            row=row, column=1, sticky="ew", pady=4
        )
        row += 1

        ttk.Label(main, text="URL:").grid(row=row, column=0, sticky="e", pady=4, padx=(0, 8))
        ttk.Entry(main, textvariable=self.url_var, width=40).grid(
            row=row, column=1, sticky="ew", pady=4
        )
        row += 1

        ttk.Label(main, text="Notes:").grid(row=row, column=0, sticky="ne", pady=4, padx=(0, 8))
        notes = tk.Text(
            main,
            width=40,
            height=5,
            bg=ENTRY_BG,
            fg=ENTRY_FG,
            insertbackground=ENTRY_FG,
            relief="flat",
            borderwidth=1,
        )
        notes.grid(row=row, column=1, sticky="nsew", pady=4)
        notes.insert("1.0", self.notes_var.get())
        self.notes_widget = notes
        row += 1

        btn_frame = ttk.Frame(main)
        btn_frame.grid(row=row, column=0, columnspan=2, pady=(16, 0), sticky="e")
        ttk.Button(btn_frame, text="Cancel", command=self.on_cancel).grid(
            row=0, column=0, padx=6
        )
        ttk.Button(btn_frame, text="Save", style="Primary.TButton", command=self.on_ok).grid(
            row=0, column=1, padx=6
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
