import sys

from app import PassWardenApp


def set_dpi_awareness() -> None:
    """
    Enable DPI-awareness on Windows to prevent blurry scaling.
    Non-Windows platforms simply ignore this.
    """
    if sys.platform != "win32":
        return
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            from ctypes import windll
            windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def main() -> None:
    """Application entrypoint."""
    set_dpi_awareness()
    app = PassWardenApp()
    app.mainloop()


if __name__ == "__main__":
    main()
