#!/usr/bin/env python3
"""
CipherLab — multifunctional text encryption/decryption learning toolkit.

Supports:
  Classical ciphers: Caesar, ROT13, Atbash, Affine, Vigenere, Rail Fence,
                     Columnar Transposition
  Encodings: Base64, hexadecimal, binary UTF-8 bytes, URL encoding
  Modern encryption: AES-256-GCM password-based encryption (requires `cryptography`)

Important:
- Encodings are not encryption.
- Classical ciphers are educational and not secure for real secrets.
- AES-GCM requires the optional cryptography package.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import secrets
import sys
from urllib.parse import quote, unquote


def caesar(text: str, shift: int, decrypt: bool = False) -> str:
    if decrypt:
        shift = -shift
    shift %= 26
    out = []
    for ch in text:
        if "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + shift) % 26 + 65))
        elif "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + shift) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)


def rot13(text: str) -> str:
    return caesar(text, 13)


def atbash(text: str) -> str:
    out = []
    for ch in text:
        if "A" <= ch <= "Z":
            out.append(chr(90 - (ord(ch) - 65)))
        elif "a" <= ch <= "z":
            out.append(chr(122 - (ord(ch) - 97)))
        else:
            out.append(ch)
    return "".join(out)


def affine(text: str, a: int, b: int, decrypt: bool = False) -> str:
    a %= 26
    b %= 26
    if hmac.compare_digest(str(decrypt), "True"):
        # Multiplicative inverse exists only when gcd(a, 26) == 1.
        try:
            inverse = pow(a, -1, 26)
        except ValueError as exc:
            raise ValueError("Affine key 'a' must be coprime with 26 (e.g. 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25).") from exc
    else:
        if __import__("math").gcd(a, 26) != 1:
            raise ValueError("Affine key 'a' must be coprime with 26 (e.g. 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25).")
    out = []
    for ch in text:
        if "A" <= ch <= "Z":
            x = ord(ch) - 65
            y = ((inverse * (x - b)) if decrypt else (a * x + b)) % 26
            out.append(chr(y + 65))
        elif "a" <= ch <= "z":
            x = ord(ch) - 97
            y = ((inverse * (x - b)) if decrypt else (a * x + b)) % 26
            out.append(chr(y + 97))
        else:
            out.append(ch)
    return "".join(out)


def vigenere(text: str, key: str, decrypt: bool = False) -> str:
    key_letters = [ord(c.lower()) - 97 for c in key if c.isalpha() and c.lower() in "abcdefghijklmnopqrstuvwxyz"]
    if not key_letters:
        raise ValueError("Vigenere key must contain at least one English letter.")
    out, j = [], 0
    for ch in text:
        if "A" <= ch <= "Z":
            shift = key_letters[j % len(key_letters)] * (-1 if decrypt else 1)
            out.append(chr((ord(ch) - 65 + shift) % 26 + 65))
            j += 1
        elif "a" <= ch <= "z":
            shift = key_letters[j % len(key_letters)] * (-1 if decrypt else 1)
            out.append(chr((ord(ch) - 97 + shift) % 26 + 97))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def rail_fence_encrypt(text: str, rails: int) -> str:
    if rails < 2:
        raise ValueError("Rail Fence requires at least 2 rails.")
    if rails >= len(text):
        return text
    rows = [""] * rails
    row, step = 0, 1
    for ch in text:
        rows[row] += ch
        if row == 0:
            step = 1
        elif row == rails - 1:
            step = -1
        row += step
    return "".join(rows)


def rail_fence_decrypt(text: str, rails: int) -> str:
    if rails < 2:
        raise ValueError("Rail Fence requires at least 2 rails.")
    if rails >= len(text):
        return text
    pattern, row, step = [], 0, 1
    for _ in text:
        pattern.append(row)
        if row == 0:
            step = 1
        elif row == rails - 1:
            step = -1
        row += step
    counts = [pattern.count(r) for r in range(rails)]
    chunks, pos = [], 0
    for count in counts:
        chunks.append(list(text[pos:pos + count]))
        pos += count
    indexes = [0] * rails
    out = []
    for r in pattern:
        out.append(chunks[r][indexes[r]])
        indexes[r] += 1
    return "".join(out)


def columnar_encrypt(text: str, key: str) -> str:
    key = key.strip()
    if not key:
        raise ValueError("Columnar transposition key cannot be empty.")
    # Stable ordering handles repeated characters in the key.
    order = sorted(range(len(key)), key=lambda i: (key[i].lower(), i))
    width = len(key)
    return "".join(text[i::width] for i in order)


def columnar_decrypt(text: str, key: str) -> str:
    key = key.strip()
    if not key:
        raise ValueError("Columnar transposition key cannot be empty.")
    width, n = len(key), len(text)
    rows = (n + width - 1) // width
    remainder = n % width
    # In row-wise input, first 'remainder' columns have one extra character.
    col_lengths = [rows if remainder == 0 or c < remainder else rows - 1 for c in range(width)]
    order = sorted(range(width), key=lambda i: (key[i].lower(), i))
    columns = [""] * width
    pos = 0
    for col in order:
        length = col_lengths[col]
        columns[col] = text[pos:pos + length]
        pos += length
    out = []
    for r in range(rows):
        for c in range(width):
            if r < len(columns[c]):
                out.append(columns[c][r])
    return "".join(out)


def encode_text(text: str, mode: str) -> str:
    data = text.encode("utf-8")
    if mode == "base64":
        return base64.b64encode(data).decode("ascii")
    if mode == "hex":
        return data.hex()
    if mode == "binary":
        return " ".join(f"{byte:08b}" for byte in data)
    if mode == "url":
        return quote(text, safe="")
    raise ValueError("Unknown encoding mode.")


def decode_text(text: str, mode: str) -> str:
    try:
        if mode == "base64":
            data = base64.b64decode(text.strip(), validate=True)
            return data.decode("utf-8")
        if mode == "hex":
            return bytes.fromhex(text.strip()).decode("utf-8")
        if mode == "binary":
            bits = "".join(text.split())
            if not bits or any(c not in "01" for c in bits) or len(bits) % 8:
                raise ValueError("Binary input must contain groups of 8 bits (spaces are optional).")
            return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)).decode("utf-8")
        if mode == "url":
            return unquote(text)
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise ValueError(f"Could not decode input as {mode}: {exc}") from exc
    raise ValueError("Unknown encoding mode.")


def aes_gcm_encrypt(text: str, password: str) -> str:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError("AES-GCM needs the 'cryptography' package. Install it with: python3 -m pip install cryptography") from exc
    if not password:
        raise ValueError("Password cannot be empty.")
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000, dklen=32)
    encrypted = AESGCM(key).encrypt(nonce, text.encode("utf-8"), None)
    payload = b"CS4" + salt + nonce + encrypted
    return base64.urlsafe_b64encode(payload).decode("ascii")


def aes_gcm_decrypt(token: str, password: str) -> str:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError("AES-GCM needs the 'cryptography' package. Install it with: python3 -m pip install cryptography") from exc
    if not password:
        raise ValueError("Password cannot be empty.")
    try:
        payload = base64.urlsafe_b64decode(token.strip().encode("ascii"))
    except Exception as exc:
        raise ValueError("Invalid AES-GCM token: it is not valid URL-safe Base64.") from exc
    if len(payload) < 3 + 16 + 12 + 16 or payload[:3] != b"CS4":
        raise ValueError("Invalid CipherLab AES token or unsupported token version.")
    salt, nonce, ciphertext = payload[3:19], payload[19:31], payload[31:]
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000, dklen=32)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except Exception as exc:
        raise ValueError("Decryption failed: wrong password or modified ciphertext.") from exc


def get_text() -> str:
    print("Enter text on one line. For an empty line, enter nothing.")
    return input("Text: ")


def get_key(prompt: str = "Key: ") -> str:
    return input(prompt)


def ask_shift() -> int:
    while True:
        try:
            return int(input("Shift amount (integer): ").strip())
        except ValueError:
            print("Enter a valid integer.")


def ask_direction() -> str:
    while True:
        choice = input("Direction [E]ncrypt/[D]ecrypt? ").strip().lower()
        if choice in {"e", "encrypt", "encryption"}:
            return "encrypt"
        if choice in {"d", "decrypt", "decryption"}:
            return "decrypt"
        print("Enter E or D.")


def process_menu_choice(choice: str) -> None:
    text = get_text()
    if choice == "1":
        op = ask_direction()
        shift = ask_shift()
        print("\nResult:\n" + caesar(text, shift, op == "decrypt"))
    elif choice == "2":
        print("\nResult:\n" + rot13(text))
    elif choice == "3":
        print("\nResult:\n" + atbash(text))
    elif choice == "4":
        op = ask_direction()
        a = ask_shift()
        b = ask_shift() if input("Enter additive key b? [Y/n]: ").strip().lower() not in {"n", "no"} else 0
        print("\nResult:\n" + affine(text, a, b, op == "decrypt"))
    elif choice == "5":
        op = ask_direction()
        key = get_key("Vigenere keyword: ")
        print("\nResult:\n" + vigenere(text, key, op == "decrypt"))
    elif choice == "6":
        op = ask_direction()
        rails = ask_shift()
        result = rail_fence_encrypt(text, rails) if op == "encrypt" else rail_fence_decrypt(text, rails)
        print("\nResult:\n" + result)
    elif choice == "7":
        op = ask_direction()
        key = get_key("Columnar transposition keyword: ")
        result = columnar_encrypt(text, key) if op == "encrypt" else columnar_decrypt(text, key)
        print("\nResult:\n" + result)
    elif choice in {"8", "9", "10", "11"}:
        modes = {"8": "base64", "9": "hex", "10": "binary", "11": "url"}
        mode = modes[choice]
        op = ask_direction()
        print("\nResult:\n" + (encode_text(text, mode) if op == "encrypt" else decode_text(text, mode)))
    elif choice == "12":
        op = ask_direction()
        password = get_key("Password: ")
        print("\nResult:\n" + (aes_gcm_encrypt(text, password) if op == "encrypt" else aes_gcm_decrypt(text, password)))
    elif choice == "13":
        brute_force(text)
    elif choice == "14":
        print("""
CipherLab supports:
  Classical: Caesar, ROT13, Atbash, Affine, Vigenere, Rail Fence,
             Columnar Transposition
  Encodings: Base64, hexadecimal, binary UTF-8, URL encoding
  Modern encryption: AES-256-GCM (requires `cryptography` package)

Notes:
  - Caesar, ROT13, Atbash, Affine, Vigenere, Rail Fence and Columnar are
    educational/classical methods, not secure for real secrets.
  - Base64/hex/binary/URL are encodings, not encryption.
  - AES-GCM uses a password, random salt/nonce, PBKDF2-HMAC-SHA256,
    and authenticated encryption. Keep your password safe.
  - CipherLab cannot automatically decrypt every unknown cipher.
""")
    else:
        print("Unknown option.")


def brute_force(text: str) -> None:
    print("""
Brute-force Caesar results:
  1. Backward only
  2. Forward only
  3. Both directions
  4. All 26 unique results
""")
    choice = input("Choose [1-4]: ").strip()
    if choice == "1":
        dirs = ("backward",)
    elif choice == "2":
        dirs = ("forward",)
    elif choice == "3":
        dirs = ("forward", "backward")
    elif choice == "4":
        print("\nAll 26 unique candidates:")
        for n in range(26):
            print(f"Backward {n:2}: {caesar(text, n, True)}")
        return
    else:
        print("Invalid choice.")
        return
    for direction in dirs:
        print(f"\n--- {direction.upper()} ---")
        for n in range(26):
            print(f"{direction.capitalize():8} {n:2}: {caesar(text, n, direction == 'backward')}")


def interactive_menu() -> None:
    while True:
        print("""
╔══════════════════════════════════════════════════╗
║                    CIPHERLAB                     ║
╠══════════════════════════════════════════════════╣
║  1. Caesar cipher                                ║
║  2. ROT13                                         ║
║  3. Atbash cipher                                 ║
║  4. Affine cipher                                 ║
║  5. Vigenère cipher                               ║
║  6. Rail Fence transposition                      ║
║  7. Columnar Transposition                        ║
║  8. Base64 encode/decode                          ║
║  9. Hexadecimal encode/decode                     ║
║ 10. Binary (UTF-8 bytes) encode/decode             ║
║ 11. URL encode/decode                             ║
║ 12. AES-256-GCM password encryption/decryption    ║
║ 13. Brute-force Caesar                            ║
║ 14. Help and security notes                       ║
║  0. Exit                                          ║
╚══════════════════════════════════════════════════╝""")
        choice = input("Choose an option: ").strip()
        if choice == "0":
            print("Exiting CipherLab.")
            return
        try:
            if choice in {str(n) for n in range(1, 14)}:
                process_menu_choice(choice)
            elif choice == "14":
                process_menu_choice(choice)
            else:
                print("Choose a listed option.")
        except (ValueError, RuntimeError) as exc:
            print(f"\nError: {exc}")
        input("\nPress Enter to return to the menu...")


def main() -> None:
    parser = argparse.ArgumentParser(description="CipherLab multifunctional text cryptography toolkit.")
    parser.add_argument("--menu", action="store_true", help="Open interactive menu (default).")
    parser.add_argument("--self-test", action="store_true", help="Run basic round-trip tests.")
    args = parser.parse_args()
    if args.self_test:
        assert caesar(caesar("Hello, World!", 5), 5, True) == "Hello, World!"
        assert rot13(rot13("Hello, World!")) == "Hello, World!"
        assert atbash(atbash("Hello, World!")) == "Hello, World!"
        assert affine(affine("Hello, World!", 5, 8), 5, 8, True) == "Hello, World!"
        assert vigenere(vigenere("Attack at dawn!", "LEMON"), "LEMON", True) == "Attack at dawn!"
        for rails in range(2, 6):
            sample = "WEAREDISCOVEREDFLEEATONCE"
            assert rail_fence_decrypt(rail_fence_encrypt(sample, rails), rails) == sample
        for key in ("ZEBRA", "BALLOON", "KEY"):
            sample = "WEAREDISCOVEREDFLEEATONCE"
            assert columnar_decrypt(columnar_encrypt(sample, key), key) == sample
        assert decode_text(encode_text("Hello 🌌", "base64"), "base64") == "Hello 🌌"
        assert decode_text(encode_text("Hello 🌌", "hex"), "hex") == "Hello 🌌"
        assert decode_text(encode_text("Hello 🌌", "binary"), "binary") == "Hello 🌌"
        assert decode_text(encode_text("Hello world!", "url"), "url") == "Hello world!"
        print("Self-test passed.")
        return
    interactive_menu()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nInterrupted.")
        sys.exit(130)
