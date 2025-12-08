import tkinter as tk
from tkinter import ttk

# NordPass-ish palette for the whole app
BG_COLOR = "#040816"
SURFACE_BG = "#050b1f"
PANEL_BG = "#050b1f"
HEADER_BG = "#071121"

FRAME_BG = SURFACE_BG
FG_COLOR = "#e5f0ff"
SUBTLE_FG = "#9ca7c5"

ACCENT_COLOR = "#32d0c5"
ACCENT_SECONDARY = "#4fa9ff"
ENTRY_BG = "#070d1f"
ENTRY_FG = FG_COLOR
BORDER_COLOR = "#17233b"


def configure_dark_theme(root: tk.Tk) -> None:
    """Configure the global dark UI theme."""
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    root.configure(bg=BG_COLOR)

    base_font = ("Segoe UI", 11)
    heading_font = ("Segoe UI Semibold", 12)
    button_font = ("Segoe UI Semibold", 11)

    style.configure(
        ".",
        background=BG_COLOR,
        foreground=FG_COLOR,
        fieldbackground=ENTRY_BG,
        font=base_font,
    )

    style.configure("TFrame", background=SURFACE_BG)
    style.configure("Card.TFrame", background=HEADER_BG)

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
    )

    style.configure("TButton", background="#0b172b", foreground=FG_COLOR, font=button_font)
    style.map("TButton", background=[("active", "#13223d")])

    style.configure(
        "Primary.TButton",
        background=ACCENT_COLOR,
        foreground="#031014",
        font=button_font,
    )
    style.map("Primary.TButton", background=[("active", "#25b5ac")])

    # Small fix applied here: rowheight increased for visual consistency
    style.configure(
        "Treeview",
        background=FRAME_BG,
        foreground=FG_COLOR,
        fieldbackground=FRAME_BG,
        bordercolor=BORDER_COLOR,
        rowheight=32,  # was 30
        font=base_font,
    )

    style.configure(
        "Treeview.Heading",
        background="#0b172b",
        foreground=SUBTLE_FG,
        font=heading_font,
    )

    style.configure("TEntry", fieldbackground=ENTRY_BG, foreground=ENTRY_FG)

    style.configure("TNotebook", background=BG_COLOR)
    style.configure(
        "TNotebook.Tab",
        background="#081326",
        foreground=SUBTLE_FG,
        padding=(20, 8),
        font=("Segoe UI Semibold", 11),
    )

    try:
        root.tk.call("tk", "scaling", 1.5)
    except tk.TclError:
        pass
