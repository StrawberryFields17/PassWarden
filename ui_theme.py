import tkinter as tk
from tkinter import ttk

# NordPass-ish palette for the whole app
BG_COLOR = "#040816"             # very dark blue background
SURFACE_BG = "#050b1f"
PANEL_BG = "#050b1f"
HEADER_BG = "#071121"

FRAME_BG = SURFACE_BG
FG_COLOR = "#e5f0ff"             # light bluish text
SUBTLE_FG = "#9ca7c5"            # desaturated text

ACCENT_COLOR = "#32d0c5"         # teal accent
ACCENT_SECONDARY = "#4fa9ff"     # soft blue
ENTRY_BG = "#070d1f"
ENTRY_FG = FG_COLOR
BORDER_COLOR = "#17233b"


def configure_dark_theme(root: tk.Tk) -> None:
    """
    Configure a dark, NordPass-like ttk theme with larger, readable fonts.
    Call this once on the root window before creating other widgets.
    """
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    root.configure(bg=BG_COLOR)

    # Bigger base fonts for readability
    base_font = ("Segoe UI", 11)
    heading_font = ("Segoe UI Semibold", 12)
    button_font = ("Segoe UI Semibold", 11)

    # Global defaults
    style.configure(
        ".",
        background=BG_COLOR,
        foreground=FG_COLOR,
        fieldbackground=ENTRY_BG,
        font=base_font,
    )

    # Frames / panels
    style.configure("TFrame", background=SURFACE_BG)
    style.configure("Card.TFrame", background=HEADER_BG, relief="flat")
    style.configure(
        "TLabelframe",
        background=PANEL_BG,
        foreground=FG_COLOR,
        borderwidth=1,
        padding=(8, 6),
    )
    style.configure(
        "TLabelframe.Label",
        background=PANEL_BG,
        foreground=SUBTLE_FG,
        font=heading_font,
        padding=(4, 0),
    )
    style.configure("TLabel", background=PANEL_BG, foreground=FG_COLOR)

    # Buttons
    style.configure(
        "TButton",
        background="#0b172b",
        foreground=FG_COLOR,
        padding=(14, 7),
        relief="flat",
        borderwidth=0,
        font=button_font,
    )
    style.map(
        "TButton",
        background=[("active", "#13223d")],
        foreground=[("disabled", SUBTLE_FG)],  # small fix: consistent disabled color
    )

    style.configure(
        "Primary.TButton",
        background=ACCENT_COLOR,
        foreground="#031014",
    )
    style.map(
        "Primary.TButton",
        background=[("active", "#25b5ac")],
        foreground=[("disabled", "#244e4d")],  # small fix: readable disabled fg
    )

    # Treeview (list of entries)
    style.configure(
        "Treeview",
        background=FRAME_BG,
        foreground=FG_COLOR,
        fieldbackground=FRAME_BG,
        bordercolor=BORDER_COLOR,
        rowheight=30,
        font=base_font,
    )
    style.configure(
        "Treeview.Heading",
        background="#0b172b",
        foreground=SUBTLE_FG,
        relief="flat",
        font=heading_font,
        padding=(6, 4),
    )
    style.map(
        "Treeview",
        background=[("selected", ACCENT_SECONDARY)],
        foreground=[("selected", "#020617")],
    )

    # Entry / checkbutton / notebook
    style.configure(
        "TEntry",
        fieldbackground=ENTRY_BG,
        foreground=ENTRY_FG,
        relief="flat",
        borderwidth=1,
        padding=(8, 5),
    )

    style.configure(
        "TCheckbutton",
        background=PANEL_BG,
        foreground=FG_COLOR,
        padding=(4, 2),
    )

    style.configure("TNotebook", background=BG_COLOR, borderwidth=0)
    style.configure(
        "TNotebook.Tab",
        background="#081326",
        foreground=SUBTLE_FG,
        padding=(20, 8),
        font=("Segoe UI Semibold", 11),
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", "#0e1b33"), ("active", "#0e1b33")],
        foreground=[("selected", FG_COLOR)],
    )

    # We keep scaling modest because fonts are already larger
    try:
        root.tk.call("tk", "scaling", 1.5)
    except tk.TclError:
        pass
