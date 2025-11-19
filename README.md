# PassWarden

A simple local desktop password manager written in Python.

- Encrypted vault on disk (AES via `cryptography.Fernet`)
- Key derived from master password using PBKDF2-HMAC-SHA256
- Tkinter desktop GUI
- Built-in secure password generator (length slider, character-type toggles, strength estimate)

## Installation

Clone the repo:

```bash
git clone https://github.com/StrawberryFields17/PassWarden.git
cd PassWarden
