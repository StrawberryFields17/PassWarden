import argparse

from app import APP_NAME, APP_VERSION, PassWardenApp


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="passwarden", add_help=True)
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print version info and exit.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.version:
        print(f"{APP_NAME} {APP_VERSION}")
        return

    app = PassWardenApp()
    app.mainloop()


if __name__ == "__main__":
    main()
