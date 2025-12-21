import faulthandler
import sys

from app import PassWardenApp


def set_dpi_awareness() -> None:
    """
    Enable DPI-awareness on Windows to prevent blurry UI scaling.
    Falls back gracefully on systems where DPI APIs are not available.
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
            pass


def main() -> None:
    """Application entrypoint."""
    # New: emit Python-level crashes/segfault tracebacks to stderr when possible
    try:
        faulthandler.enable()
    except Exception:
        pass

    set_dpi_awareness()
    app = PassWardenApp()
    app.mainloop()


if __name__ == "__main__":
    main()
