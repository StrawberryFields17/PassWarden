import sys

from app import PassWardenApp


def set_dpi_awareness() -> None:
    """
    Enable DPI-awareness on Windows to prevent blurry UI scaling.
    Falls back gracefully on older Windows versions.
    """
    if sys.platform != "win32":
        return

    try:
        from ctypes import windll
        # Windows 8.1+ (PROCESS_SYSTEM_DPI_AWARE = 1)
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        # Older Windows fallback
        try:
            from ctypes import windll
            windll.user32.SetProcessDPIAware()
        except Exception:
            # If everything fails, silently ignore.
            pass


def main() -> None:
    """Application entrypoint."""
    set_dpi_awareness()
    app = PassWardenApp()
    app.mainloop()


if __name__ == "__main__":
    # Explicit entrypoint comment for clarity in tooling and PR readers
    main()
