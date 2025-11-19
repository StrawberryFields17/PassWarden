import tkinter as tk
from tkinter import ttk, messagebox

from ui_theme import BG_COLOR, ENTRY_BG, ENTRY_FG, SUBTLE_FG


def center_window(
    win: tk.Toplevel | tk.Tk,
    width: int | None = None,
    height: int | None = None,
) -> None:
    """
    Center a window on the screen.

    If width/height are not given, we use the window's natural size as
    computed by Tk after layouts have been updated.
    """
    win.update_idletasks()

    if width is None or height is None:
        w = win.winfo_width()
        h = win.winfo_height()
    else:
        w, h = width, height

    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    x = (sw - w) // 2
    y = (sh - h) // 2

    win.geometry(f"{w}x{h}+{x}+{y}")


# ---------------------------------------------------------------------------
#  Master password dialog (first run only)
# ---------------------------------------------------------------------------


class MasterPasswordDialog(tk.Toplevel):
    """Shown only when no vault file exists yet."""

    def __init__(self, parent: tk.Tk):
        super().__init__(parent)
        self.title("Set master password")
        self.resizable(False, False)
        self.configure(bg=BG_COLOR)

        self.result: str | None = None
        self.pass_var = tk.StringVar()
        self.confirm_var = tk.StringVar()

        self._build_ui()

        # Modal over main window
        self.transient(parent)
        self.grab_set()
        center_window(self)
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)

    def _build_ui(self) -> None:
        main = ttk.Frame(self, padding=18)
        main.grid(row=0, column=0, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)

        header = ttk.Label(
            main,
            text="Create your master password",
            font=("Segoe UI Semibold", 13),
        )
        header.grid(row=0, column=0, columnspan=2, sticky="w")

        subtitle = ttk.Label(
            main,
            text=(
                "This password encrypts your vault. If you lose it, your data "
                "cannot be recovered."
            ),
            foreground=SUBTLE_FG,
            wraplength=420,
            justify="left",
        )
        subtitle.grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 14))

        ttk.Label(main, text="Master password:").grid(
            row=2, column=0, sticky="e", pady=6, padx=(0, 10)
        )
        ttk.Entry(main, textvariable=self.pass_var, show="*", width=34).grid(
            row=2, column=1, sticky="w", pady=6
        )

        ttk.Label(main, text="Confirm:").grid(
            row=3, column=0, sticky="e", pady=6, padx=(0, 10)
        )
        ttk.Entry(main, textvariable=self.confirm_var, show="*", width=34).grid(
            row=3, column=1, sticky="w", pady=6
        )

        btn_frame = ttk.Frame(main)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=(18, 0), sticky="e")

        ttk.Button(btn_frame, text="Cancel", command=self.on_cancel).grid(
            row=0, column=0, padx=8
        )
        ttk.Button(
            btn_frame,
            text="Create",
            style="Primary.TButton",
            command=self.on_ok,
        ).grid(row=0, column=1, padx=8)

    # ----- callbacks -----

    def on_ok(self) -> None:
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

    def on_cancel(self) -> None:
        self.result = None
        self.destroy()


# ---------------------------------------------------------------------------
#  Unlock dialog (subsequent runs)
# ---------------------------------------------------------------------------


class UnlockDialog(tk.Toplevel):
    """Shown when a vault already exists and we need the master password."""

    def __init__(self, parent: tk.Tk):
        super().__init__(parent)
        self.title("Unlock PassWarden")
        self.resizable(False, False)
        self.configure(bg=BG_COLOR)

        self.result: str | None = None
        self.pass_var = tk.StringVar()

        self._build_ui()
        self.transient(parent)
        self.grab_set()
        center_window(self)
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)

    def _build_ui(self) -> None:
        main = ttk.Frame(self, padding=18)
        main.grid(row=0, column=0, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)

        header = ttk.Label(
            main,
            text="Unlock your vault",
            font=("Segoe UI Semibold", 13),
        )
        header.grid(row=0, column=0, columnspan=2, sticky="w")

        subtitle = ttk.Label(
            main,
            text="Enter your master password to decrypt your stored passwords.",
            foreground=SUBTLE_FG,
            wraplength=380,
            justify="left",
        )
        subtitle.grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 12))

        ttk.Label(main, text="Master password:").grid(
            row=2, column=0, sticky="e", pady=6, padx=(0, 10)
        )
        entry = ttk.Entry(main, textvariable=self.pass_var, show="*", width=32)
        entry.grid(row=2, column=1, sticky="w", pady=6)
        entry.focus_set()

        btn_frame = ttk.Frame(main)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=(18, 0), sticky="e")

        ttk.Button(btn_frame, text="Cancel", command=self.on_cancel).grid(
            row=0, column=0, padx=8
        )
        ttk.Button(
            btn_frame,
            text="Unlock",
            style="Primary.TButton",
            command=self.on_ok,
        ).grid(row=0, column=1, padx=8)

    def on_ok(self) -> None:
        self.result = self.pass_var.get()
        self.destroy()

    def on_cancel(self) -> None:
        self.result = None
        self.destroy()


# ---------------------------------------------------------------------------
#  Add / edit entry dialog
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

    def _build_ui(self) -> None:
        main = ttk.Frame(self, padding=18)
        main.grid(row=0, column=0, sticky="nsew")
        main.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(main, text="Name:").grid(
            row=row, column=0, sticky="e", pady=4, padx=(0, 10)
        )
        ttk.Entry(main, textvariable=self.name_var, width=42).grid(
            row=row, column=1, sticky="ew", pady=4
        )
        row += 1

        ttk.Label(main, text="Username:").grid(
            row=row, column=0, sticky="e", pady=4, padx=(0, 10)
        )
        ttk.Entry(main, textvariable=self.username_var, width=42).grid(
            row=row, column=1, sticky="ew", pady=4
        )
        row += 1

        ttk.Label(main, text="Password:").grid(
            row=row, column=0, sticky="e", pady=4, padx=(0, 10)
        )
        ttk.Entry(main, textvariable=self.password_var, show="*", width=42).grid(
            row=row, column=1, sticky="ew", pady=4
        )
        row += 1

        ttk.Label(main, text="URL:").grid(
            row=row, column=0, sticky="e", pady=4, padx=(0, 10)
        )
        ttk.Entry(main, textvariable=self.url_var, width=42).grid(
            row=row, column=1, sticky="ew", pady=4
        )
        row += 1

        ttk.Label(main, text="Notes:").grid(
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
            text="Save",
            style="Primary.TButton",
            command=self.on_ok,
        ).grid(row=0, column=1, padx=8)

    def on_ok(self) -> None:
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

    def on_cancel(self) -> None:
        self.result = None
        self.destroy()
