import tkinter as tk
from tkinter import ttk, messagebox

from ui_theme import BG_COLOR, ENTRY_BG, ENTRY_FG, SUBTLE_FG
from password_utils import (
    generate_password,
    estimate_entropy_bits,
    estimate_crack_time_seconds,
    format_duration,
    analyze_arbitrary_password,
)


# ---------- Master password dialogs -----------------------------------------


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


# ---------- Entry editor -----------------------------------------------------


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
        pwd_frame = ttk.Frame(main)
        pwd_frame.grid(row=row, column=1, sticky="w", pady=2)
        self.pwd_entry = ttk.Entry(pwd_frame, textvariable=self.password_var, show="*", width=30)
        self.pwd_entry.grid(row=0, column=0)
        ttk.Button(pwd_frame, text="Generate", command=self.open_generator).grid(
            row=0, column=1, padx=(5, 0)
        )
        ttk.Button(pwd_frame, text="Analyze", command=self.analyze_password).grid(
            row=0, column=2, padx=(5, 0)
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

    def open_generator(self):
        PasswordGeneratorDialog(self, on_password_chosen=self.password_var.set)

    def analyze_password(self):
        PasswordAnalysisDialog(self, initial_password=self.password_var.get())

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


# ---------- Password generator ----------------------------------------------


class PasswordGeneratorDialog(tk.Toplevel):
    def __init__(self, parent, on_password_chosen=None):
        super().__init__(parent)
        self.title("Password generator")
        self.resizable(False, False)
        self.configure(bg=BG_COLOR)
        self.on_password_chosen = on_password_chosen

        self.length_var = tk.IntVar(value=20)
        self.use_lower_var = tk.BooleanVar(value=True)
        self.use_upper_var = tk.BooleanVar(value=True)
        self.use_digits_var = tk.BooleanVar(value=True)
        self.use_symbols_var = tk.BooleanVar(value=True)
        self.generated_var = tk.StringVar(value="")
        self.strength_var = tk.StringVar(value="")
        self.crack_time_var = tk.StringVar(value="")

        self._build_ui()
        self.generate()

        self.minsize(420, 260)
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def _build_ui(self):
        main = ttk.Frame(self, padding=12)
        main.grid(row=0, column=0, sticky="nsew")
        main.columnconfigure(0, weight=1)

        ttk.Label(main, text="Generated password:").grid(row=0, column=0, sticky="w")
        entry = ttk.Entry(main, textvariable=self.generated_var, width=44)
        entry.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 4))

        ttk.Label(main, textvariable=self.strength_var, foreground=SUBTLE_FG).grid(
            row=2, column=0, columnspan=3, sticky="w"
        )
        ttk.Label(main, textvariable=self.crack_time_var, foreground=SUBTLE_FG).grid(
            row=3, column=0, columnspan=3, sticky="w", pady=(0, 8)
        )

        # Length controls: spinbox + slider
        ttk.Label(main, text="Length:").grid(row=4, column=0, sticky="w")
        length_spin = ttk.Spinbox(
            main,
            from_=8,
            to=64,
            textvariable=self.length_var,
            width=5,
            command=self._on_length_spin,
        )
        length_spin.grid(row=4, column=1, sticky="w")

        self.length_scale = ttk.Scale(
            main, from_=8, to=64, orient="horizontal", command=self._on_length_scale
        )
        self.length_scale.set(self.length_var.get())
        self.length_scale.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(4, 8))

        row = 6
        ttk.Checkbutton(
            main, text="Use lowercase (a-z)", variable=self.use_lower_var,
            command=self.generate
        ).grid(row=row, column=0, columnspan=3, sticky="w")
        row += 1
        ttk.Checkbutton(
            main, text="Use uppercase (A-Z)", variable=self.use_upper_var,
            command=self.generate
        ).grid(row=row, column=0, columnspan=3, sticky="w")
        row += 1
        ttk.Checkbutton(
            main, text="Use digits (0-9)", variable=self.use_digits_var,
            command=self.generate
        ).grid(row=row, column=0, columnspan=3, sticky="w")
        row += 1
        ttk.Checkbutton(
            main,
            text="Use symbols (!@#$%^&*)",
            variable=self.use_symbols_var,
            command=self.generate,
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
        ttk.Button(btn_frame, text="Use password", command=self.use_password).grid(
            row=0, column=2, padx=5
        )

    def _on_length_scale(self, value):
        self.length_var.set(int(float(value)))
        self.generate()

    def _on_length_spin(self):
        try:
            value = int(self.length_var.get())
        except Exception:
            return
        value = max(8, min(64, value))
        self.length_var.set(value)
        self.length_scale.set(value)
        self.generate()

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
            + (32 if self.use_symbols_var.get() else 0)  # rough for SYMBOLS
        )
        bits = estimate_entropy_bits(self.length_var.get(), alphabet_size)
        seconds = estimate_crack_time_seconds(bits)
        self.strength_var.set(f"Entropy: {bits:.1f} bits")
        self.crack_time_var.set(
            f"Brute force @ 10¹⁰ guesses/s: ≈ {format_duration(seconds)}"
        )

        # keep slider synced
        self.length_scale.set(self.length_var.get())

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


# ---------- Password analysis (user-supplied) --------------------------------


class PasswordAnalysisDialog(tk.Toplevel):
    def __init__(self, parent, initial_password: str = ""):
        super().__init__(parent)
        self.title("Analyze password")
        self.resizable(False, False)
        self.configure(bg=BG_COLOR)

        self.password_var = tk.StringVar(value=initial_password)
        self.length_var = tk.StringVar(value="-")
        self.alphabet_var = tk.StringVar(value="-")
        self.entropy_var = tk.StringVar(value="-")
        self.crack_var = tk.StringVar(value="-")
        self.show_var = tk.BooleanVar(value=False)

        self._build_ui()
        self.update_analysis()
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def _build_ui(self):
        main = ttk.Frame(self, padding=12)
        main.grid(row=0, column=0, sticky="nsew")

        ttk.Label(main, text="Password:").grid(row=0, column=0, sticky="e")
        self.entry = ttk.Entry(main, textvariable=self.password_var, show="*", width=40)
        self.entry.grid(row=0, column=1, sticky="w")
        self.entry.bind("<KeyRelease>", lambda e: self.update_analysis())
        self.entry.focus_set()

        show_cb = ttk.Checkbutton(
            main, text="Show", variable=self.show_var, command=self.toggle_show
        )
        show_cb.grid(row=0, column=2, sticky="w", padx=(6, 0))

        row = 1
        ttk.Label(main, text="Length:").grid(row=row, column=0, sticky="e", pady=2)
        ttk.Label(main, textvariable=self.length_var).grid(
            row=row, column=1, sticky="w", pady=2
        )
        row += 1

        ttk.Label(main, text="Alphabet size:").grid(row=row, column=0, sticky="e", pady=2)
        ttk.Label(main, textvariable=self.alphabet_var).grid(
            row=row, column=1, sticky="w", pady=2
        )
        row += 1

        ttk.Label(main, text="Entropy:").grid(row=row, column=0, sticky="e", pady=2)
        ttk.Label(main, textvariable=self.entropy_var).grid(
            row=row, column=1, sticky="w", pady=2
        )
        row += 1

        ttk.Label(main, text="Brute force time:").grid(
            row=row, column=0, sticky="e", pady=2
        )
        ttk.Label(main, textvariable=self.crack_var, wraplength=320).grid(
            row=row, column=1, columnspan=2, sticky="w", pady=2
        )

        row += 1
        ttk.Label(
            main,
            text="Assuming 10¹⁰ guesses per second\nand ideal brute-force attacker.",
            foreground=SUBTLE_FG,
        ).grid(row=row, column=0, columnspan=3, sticky="w", pady=(8, 0))

    def toggle_show(self):
        self.entry.configure(show="" if self.show_var.get() else "*")

    def update_analysis(self):
        pwd = self.password_var.get()
        analysis = analyze_arbitrary_password(pwd)

        self.length_var.set(str(analysis.length))
        self.alphabet_var.set(str(analysis.alphabet_size))

        if analysis.length == 0 or analysis.alphabet_size == 0:
            self.entropy_var.set("-")
            self.crack_var.set("-")
            return

        self.entropy_var.set(f"{analysis.bits:.1f} bits ({analysis.strength_label})")
        self.crack_var.set(analysis.crack_duration_text)
