import tkinter as tk
from tkinter import ttk

# NordPass-ish palette
# Dark bluish background + teal accent
BG_COLOR = "#040816"             # very dark blue
SURFACE_BG = "#050b1f"
PANEL_BG = "#050b1f"
HEADER_BG = "#071121"

FRAME_BG = SURFACE_BG
FG_COLOR = "#e5f0ff"             # light bluish text
SUBTLE_FG = "#9ca7c5"            # desaturated text

ACCENT_COLOR = "#32d0c5"         # NordPass-like teal
ACCENT_SECONDARY = "#4fa9ff"     # soft blue
ENTRY_BG = "#070d1f"
ENTRY_FG = FG_COLOR
BORDER_COLOR = "#17233b"


def configure_dark_theme(root: tk.Tk) -> None:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    root.configure(bg=BG_COLOR)

    base_font = ("Segoe UI", 10)
    heading_font = ("Segoe UI Semibold", 10)
    button_font = ("Segoe UI Semibold", 10)

    # Global
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
    style.configure("TLabelframe", background=PANEL_BG, foreground=FG_COLOR, borderwidth=1)
    style.configure(
        "TLabelframe.Label",
        background=PANEL_BG,
        foreground=SUBTLE_FG,
        font=heading_font,
    )
    style.configure("TLabel", background=PANEL_BG, foreground=FG_COLOR)

    # Buttons
    style.configure(
        "TButton",
        background="#0b172b",
        foreground=FG_COLOR,
        padding=(12, 6),
        relief="flat",
        borderwidth=0,
        font=button_font,
    )
    style.map(
        "TButton",
        background=[("active", "#13223d")],
        foreground=[("disabled", "#6b7280")],
    )

    style.configure(
        "Primary.TButton",
        background=ACCENT_COLOR,
        foreground="#031014",
    )
    style.map(
        "Primary.TButton",
        background=[("active", "#25b5ac")],
    )

    # Treeview
    style.configure(
        "Treeview",
        background=FRAME_BG,
        foreground=FG_COLOR,
        fieldbackground=FRAME_BG,
        bordercolor=BORDER_COLOR,
        rowheight=26,
        font=base_font,
    )
    style.configure(
        "Treeview.Heading",
        background="#0b172b",
        foreground=SUBTLE_FG,
        relief="flat",
        font=heading_font,
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
        padding=(6, 4),
    )

    style.configure("TCheckbutton", background=PANEL_BG, foreground=FG_COLOR)

    style.configure(
        "TNotebook",
        background=BG_COLOR,
        borderwidth=0,
    )
    style.configure(
        "TNotebook.Tab",
        background="#081326",
        foreground=SUBTLE_FG,
        padding=(18, 6),
        font=("Segoe UI Semibold", 10),
    )
    style.map(
        "TNotebook.Tab",
        background=[
            ("selected", "#0e1b33"),
            ("active", "#0e1b33"),
        ],
        foreground=[
            ("selected", FG_COLOR),
        ],
    )

    # Crisp at 150% scaling
    try:
        root.tk.call("tk", "scaling", 1.5)
    except tk.TclError:
        pass
