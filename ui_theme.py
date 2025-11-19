import tkinter as tk
from tkinter import ttk

# Color palette (dark + neon hacker green accent)
BG_COLOR = "#121212"
FRAME_BG = "#1E1E1E"
FG_COLOR = "#F5F5F5"
SUBTLE_FG = "#BBBBBB"
ACCENT_COLOR = "#00FF7F"
ENTRY_BG = "#181818"
ENTRY_FG = FG_COLOR


def configure_dark_theme(root: tk.Tk) -> None:
    """
    Configure a dark modern theme with decent defaults for fonts and colors.
    """
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    root.configure(bg=BG_COLOR)

    default_font = ("Segoe UI", 10)

    style.configure(
        ".",
        background=BG_COLOR,
        foreground=FG_COLOR,
        fieldbackground=ENTRY_BG,
        font=default_font,
    )

    style.configure("TFrame", background=BG_COLOR)
    style.configure("TLabelframe", background=BG_COLOR, foreground=FG_COLOR)
    style.configure("TLabelframe.Label", background=BG_COLOR, foreground=FG_COLOR)
    style.configure("TLabel", background=BG_COLOR, foreground=FG_COLOR)

    style.configure(
        "TButton",
        background=FRAME_BG,
        foreground=FG_COLOR,
        relief="flat",
        padding=6,
    )
    style.map(
        "TButton",
        background=[("active", "#2A2A2A")],
        foreground=[("disabled", "#666666")],
    )

    style.configure(
        "Treeview",
        background=FRAME_BG,
        foreground=FG_COLOR,
        fieldbackground=FRAME_BG,
        bordercolor=BG_COLOR,
        rowheight=26,
    )
    style.map(
        "Treeview",
        background=[("selected", ACCENT_COLOR)],
        foreground=[("selected", "#000000")],
    )

    style.configure(
        "TEntry",
        fieldbackground=ENTRY_BG,
        foreground=ENTRY_FG,
        relief="flat",
    )

    style.configure(
        "TCheckbutton",
        background=BG_COLOR,
        foreground=FG_COLOR,
    )

    # Decent scaling for HiDPI if Tk doesn't do it itself
    try:
        # 1.5 is nice at 150% Windows scaling
        root.tk.call("tk", "scaling", 1.5)
    except tk.TclError:
        pass
