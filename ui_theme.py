import tkinter as tk
from tkinter import ttk

# Palette (Tailwind-ish, a bit more “app-y”)
BG_COLOR = "#020617"        # slate-950
SURFACE_BG = "#020617"
PANEL_BG = "#020617"
HEADER_BG = "#0f172a"       # slate-900
FRAME_BG = "#020617"

FG_COLOR = "#e5e7eb"        # gray-200
SUBTLE_FG = "#9ca3af"       # gray-400
ACCENT_COLOR = "#22c55e"    # emerald-500
ACCENT_SECONDARY = "#38bdf8"  # sky-400
ENTRY_BG = "#020617"
ENTRY_FG = FG_COLOR
BORDER_COLOR = "#1f2937"    # slate-800


def configure_dark_theme(root: tk.Tk) -> None:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    root.configure(bg=BG_COLOR)

    default_font = ("Segoe UI", 10)
    heading_font = ("Segoe UI Semibold", 10)
    button_font = ("Segoe UI Semibold", 10)

    # Global
    style.configure(
        ".",
        background=BG_COLOR,
        foreground=FG_COLOR,
        fieldbackground=ENTRY_BG,
        font=default_font,
    )

    # Frames / panels
    style.configure("TFrame", background=SURFACE_BG)
    style.configure("Card.TFrame", background=HEADER_BG, relief="flat")
    style.configure("TLabelframe", background=PANEL_BG, foreground=FG_COLOR)
    style.configure("TLabelframe.Label", background=PANEL_BG, foreground=FG_COLOR, font=heading_font)
    style.configure("TLabel", background=PANEL_BG, foreground=FG_COLOR)

    # Buttons
    style.configure(
        "TButton",
        background=HEADER_BG,
        foreground=FG_COLOR,
        padding=(10, 6),
        relief="flat",
        borderwidth=0,
        font=button_font,
    )
    style.map(
        "TButton",
        background=[("active", "#1e293b")],
        foreground=[("disabled", "#6b7280")],
    )

    # Primary button style
    style.configure(
        "Primary.TButton",
        background=ACCENT_COLOR,
        foreground="#020617",
    )
    style.map(
        "Primary.TButton",
        background=[("active", "#16a34a")],
    )

    # Treeview
    style.configure(
        "Treeview",
        background=FRAME_BG,
        foreground=FG_COLOR,
        fieldbackground=FRAME_BG,
        bordercolor=BORDER_COLOR,
        rowheight=26,
        font=default_font,
    )
    style.configure(
        "Treeview.Heading",
        background=HEADER_BG,
        foreground=FG_COLOR,
        relief="flat",
        font=heading_font,
    )
    style.map(
        "Treeview",
        background=[("selected", ACCENT_SECONDARY)],
        foreground=[("selected", "#020617")],
    )

    # Entries / checkbuttons
    style.configure(
        "TEntry",
        fieldbackground=ENTRY_BG,
        foreground=ENTRY_FG,
        relief="flat",
        borderwidth=1,
        padding=(6, 4),
    )
    style.configure("TCheckbutton", background=PANEL_BG, foreground=FG_COLOR)

    # Notebook tabs
    style.configure(
        "TNotebook",
        background=BG_COLOR,
        borderwidth=0,
    )
    style.configure(
        "TNotebook.Tab",
        background=HEADER_BG,
        foreground=SUBTLE_FG,
        padding=(16, 6),
        font=("Segoe UI Semibold", 10),
    )
    style.map(
        "TNotebook.Tab",
        background=[
            ("selected", "#111827"),
            ("active", "#111827"),
        ],
        foreground=[
            ("selected", FG_COLOR),
        ],
    )

    # Make things crisp at 150% scaling
    try:
        root.tk.call("tk", "scaling", 1.5)
    except tk.TclError:
        pass
