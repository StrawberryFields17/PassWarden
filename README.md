# PassWarden

PassWarden is a small, local-only desktop password manager written in Python.

- Encrypted vault stored on disk (AES-256 via `cryptography.Fernet`)
- Master password → key derived with PBKDF2-HMAC-SHA256
- Modern dark Tkinter GUI inspired by NordPass
- Built-in password generator with entropy + brute-force time estimate
- Password analyzer for any password you type or paste
- Single encrypted vault file (`vault.pw`), no cloud, no telemetry

> **Note:** PassWarden is a hobby / learning project and has not been security-audited.
> Use at your own risk and don’t rely on it as your only line of defence.

---

## Features

### Vault

- Store entries with:
  - Name
  - Username
  - Password
  - URL
  - Free-form notes
- Entries are listed in a sortable table.
- Detail panel shows all fields and notes for the selected entry.
- One master password unlocks the entire vault.

### Authentication flow

- **First run:**  
  You’re greeted with a full-window “Welcome to PassWarden” screen and asked
  to choose a master password (with confirmation).
- **Later runs:**  
  You see an “Unlock PassWarden” screen where you enter your master password.
- The UI for this lives inside the main window (no random pop-ups, better UX).

### Encryption and key derivation

- Vault is stored as a single encrypted file: `vault.pw`.
- Data encryption uses [`cryptography.Fernet`](https://cryptography.io/en/latest/fernet/)
  (AES-128 in CBC mode + HMAC, with authenticated encryption semantics).
- A random salt is generated per vault.
- Secret key is derived from your master password using PBKDF2-HMAC-SHA256
  with a high iteration count.
- The derived key is never stored on disk; only the salt + ciphertext are.

### Password generator

Accessible via the **Tools** tab:

- Adjustable length (8–64) via **spinbox + slider**.
- Toggle character sets:
  - Lowercase letters (a–z)
  - Uppercase letters (A–Z)
  - Digits (0–9)
  - Symbols (!@#$%^&*…)
- Shows:
  - Approximate **entropy** in bits.
  - Estimated **brute-force time** assuming `10¹⁰` guesses/second.
- One-click **Copy** button to put the generated password on the clipboard.

### Password analyzer

Also in the **Tools** tab:

- Paste or type any password.
- Shows:
  - Length
  - Effective alphabet size
  - Entropy in bits with a “weak / okay / strong / very strong” label
  - Estimated brute-force time (at `10¹⁰` guesses/second)
- Optional **“Show”** checkbox to toggle masking.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/StrawberryFields17/PassWarden.git
cd PassWarden
