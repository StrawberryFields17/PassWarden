import sys

from app import PassWardenApp


def set_dpi_awareness():
    """
    Make the app DPI-aware on Windows so it is crisp at 125/150/200% scaling
    instead of being blurry.
    """
    if sys.platform != "win32":
        return
    try:
        from ctypes import windll
        # Windows 8.1+; PROCESS_SYSTEM_DPI_AWARE = 1
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            from ctypes import windll
            # Older Windows
            windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def main():
    set_dpi_awareness()
    app = PassWardenApp()
    app.mainloop()


if __name__ == "__main__":
    main()
