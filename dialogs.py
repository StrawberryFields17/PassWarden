import tkinter as tk
from tkinter import ttk, messagebox

from ui_theme import BG_COLOR, ENTRY_BG, ENTRY_FG, SUBTLE_FG


def center_window(win: tk.Toplevel | tk.Tk):
    """Center a window on the screen based on its current size."""
    win.update_idletasks()
    w = win.winfo_width()
    h = win.winfo_height()
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    x = (sw - w) // 2
    y = (sh - h) // 2
    win.geometry(f"{w}x{h}+{x}+{y}")


# ---------------------------------------------------------------------------
#  ENTRY DIALOG (ADD / EDIT VAULT ITEM)
# ---------------------------------------------------------------------------


class EntryDialog(tk.Toplevel):
    """Dialog to add or edit a single vault entry."""

    def __init__(self, parent: tk.Tk, title: str, entry: dict | None = None):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.configure(bg=BG_COLOR)

        self.result: dict | None = None

        entry = entry or {}
        self.name_var = tk.StringVar(value=entry.get("name", ""))
        self.username_var = tk.StringVar(value=entry.get("username", ""))
        self.password_var = tk.StringVar(value=entry.get("password", ""))
        self.url_var = tk.StringVar(value=entry.get("url", ""))
        self.notes_var = tk.StringVar(value=entry.get("notes", ""))

        self._build_ui()
        self.transient(parent)
        self.grab_set()
        center_window(self)
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)

        # Keyboard shortcuts for better UX
        self.bind("<Return>", lambda event: self.on_ok())
        self.bind("<Escape>", lambda event: self.on_cancel())

    def _build_ui(self) -> None:
        main = ttk.Frame(self, padding=18)
        main.grid(row=0, column=0, sticky="nsew")
        main.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(main, text="Name").grid(
            row=row, column=0, sticky="e", pady=4, padx=(0, 10)
        )
        name_entry = ttk.Entry(main, textvariable=self.name_var, width=42)
        name_entry.grid(row=row, column=1, sticky="ew", pady=4)
        self.name_entry = name_entry
        row += 1

        ttk.Label(main, text="Username / email").grid(
            row=row, column=0, sticky="e", pady=4, padx=(0, 10)
        )
        ttk.Entry(main, textvariable=self.username_var, width=42).grid(
            row=row, column=1, sticky="ew", pady=4
        )
        row += 1

        ttk.Label(main, text="Password").grid(
            row=row, column=0, sticky="e", pady=4, padx=(0, 10)
        )
        ttk.Entry(main, textvariable=self.password_var, show="*", width=42).grid(
            row=row, column=1, sticky="ew", pady=4
        )
        row += 1

        ttk.Label(main, text="Website / URL").grid(
            row=row, column=0, sticky="e", pady=4, padx=(0, 10)
        )
        ttk.Entry(main, textvariable=self.url_var, width=42).grid(
            row=row, column=1, sticky="ew", pady=4
        )
        row += 1

        ttk.Label(main, text="Notes").grid(
            row=row, column=0, sticky="ne", pady=4, padx=(0, 10)
        )
        notes = tk.Text(
            main,
            width=42,
            height=6,
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
            row=0, column=0, padx=8
        )
        ttk.Button(
            btn_frame,
            text="Save entry",
            style="Primary.TButton",
            command=self.on_ok,
        ).grid(row=0, column=1, padx=8)

        # Start with the name field focused for quick entry
        self.name_entry.focus_set()

    def on_ok(self) -> None:
        name = self.name_var.get().strip()
        if not name:
            messagebox.showerror(
                "Missing name",
                "Give this entry a name so you can find it later.",
                parent=self,
            )
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

    def on_cancel(self) -> None:
        self.result = None
        self.destroy()


# ---------------------------------------------------------------------------
#  CHANGE MASTER PASSWORD DIALOG
# ---------------------------------------------------------------------------


class ChangeMasterPasswordDialog(tk.Toplevel):
    """
    Dialog to change the master password while the vault is unlocked.
    Validates:
      - current password not empty
      - new password length >= 8
      - new and confirm match
    The app itself checks if 'current' equals the actual master password.
    """

    def __init__(self, parent: tk.Tk):
        super().__init__(parent)
        self.title("Change master password")
        self.resizable(False, False)
        self.configure(bg=BG_COLOR)

        self.result: dict | None = None

        self.current_var = tk.StringVar()
        self.new_var = tk.StringVar()
        self.confirm_var = tk.StringVar()

        self._build_ui()
        self.transient(parent)
        self.grab_set()
        center_window(self)
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)

        # Keyboard shortcuts
        self.bind("<Return>", lambda event: self.on_ok())
        self.bind("<Escape>", lambda event: self.on_cancel())

    def _build_ui(self) -> None:
        main = ttk.Frame(self, padding=18)
        main.grid(row=0, column=0, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)

        header = ttk.Label(
            main,
            text="Update your master password",
            font=("Segoe UI Semibold", 13),
        )
        header.grid(row=0, column=0, columnspan=2, sticky="w")

        subtitle = ttk.Label(
            main,
            text=(
                "Use a long, unique password to keep your vault safe.\n"
                "You’ll need this password next time you unlock PassWarden."
            ),
            foreground=SUBTLE_FG,
            wraplength=420,
            justify="left",
        )
        subtitle.grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 14))

        row = 2
        ttk.Label(main, text="Current password").grid(
            row=row, column=0, sticky="e", pady=6, padx=(0, 10)
        )
        current_entry = ttk.Entry(main, textvariable=self.current_var, show="*", width=34)
        current_entry.grid(row=row, column=1, sticky="w", pady=6)
        self.current_entry = current_entry
        row += 1

        ttk.Label(main, text="New password").grid(
            row=row, column=0, sticky="e", pady=6, padx=(0, 10)
        )
        ttk.Entry(main, textvariable=self.new_var, show="*", width=34).grid(
            row=row, column=1, sticky="w", pady=6
        )
        row += 1

        ttk.Label(main, text="Confirm new password").grid(
            row=row, column=0, sticky="e", pady=6, padx=(0, 10)
        )
        ttk.Entry(main, textvariable=self.confirm_var, show="*", width=34).grid(
            row=row, column=1, sticky="w", pady=6
        )
        row += 1

        helper = ttk.Label(
            main,
            text="Tip: a mix of words, numbers and symbols works best.",
            foreground=SUBTLE_FG,
            wraplength=420,
            justify="left",
        )
        helper.grid(row=row, column=0, columnspan=2, sticky="w", pady=(4, 10))
        row += 1

        btn_frame = ttk.Frame(main)
        btn_frame.grid(row=row, column=0, columnspan=2, pady=(12, 0), sticky="e")

        ttk.Button(btn_frame, text="Cancel", command=self.on_cancel).grid(
            row=0, column=0, padx=8
        )
        ttk.Button(
            btn_frame,
            text="Save new password",
            style="Primary.TButton",
            command=self.on_ok,
        ).grid(row=0, column=1, padx=8)

        # Focus current password field so user can start typing immediately
        self.current_entry.focus_set()

    def on_ok(self) -> None:
        current = self.current_var.get()
        new = self.new_var.get()
        confirm = self.confirm_var.get()

        if not current:
            messagebox.showerror(
                "Current password required",
                "Enter your current master password to continue.",
                parent=self,
            )
            return
        if not new:
            messagebox.showerror(
                "New password required",
                "Choose a new master password.",
                parent=self,
            )
            return
        if len(new) < 8:
            messagebox.showerror(
                "Password too short",
                "For your security, use at least 8 characters.",
                parent=self,
            )
            return
        if new != confirm:
            messagebox.showerror(
                "Passwords don’t match",
                "The new passwords don’t match. Please try again.",
                parent=self,
            )
            return

        self.result = {"current": current, "new": new}
        self.destroy()

    def on_cancel(self) -> None:
        self.result = None
        self.destroy()
