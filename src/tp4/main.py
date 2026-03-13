#!/usr/bin/env python3
from pwn import remote, context
import base64
import binascii
import re

context.log_level = "error"

HOST = "31.220.95.27"
PORT = 13337

MORSE = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
    '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
    '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
    '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
    '-.--': 'Y', '--..': 'Z',
    '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
    '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9'
}

def decode_morse(s: str) -> str:
    return "".join(MORSE[token] for token in s.split()).lower()

def is_morse(s: str) -> bool:
    return bool(re.fullmatch(r"[.\- ]+", s.strip()))

def is_hex(s: str) -> bool:
    s = s.strip()
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s)) and len(s) % 2 == 0

def decode_hex(s: str) -> str:
    return binascii.unhexlify(s).decode("utf-8", errors="ignore")

def is_base64_candidate(s: str) -> bool:
    s = s.strip()
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", s)) and len(s) >= 8

def decode_base64(s: str) -> str:
    s = s.strip()
    pad = (-len(s)) % 4
    return base64.b64decode(s + "=" * pad).decode("utf-8", errors="ignore")

def smart_decode(s: str) -> str:
    s = s.strip()

    if is_morse(s):
        return decode_morse(s)

    if is_hex(s):
        return decode_hex(s)

    if is_base64_candidate(s):
        return decode_base64(s)

    return s

def main():
    io = remote(HOST, PORT)

    try:
        while True:
            line = io.recvline(timeout=2)
            if not line:
                break

            text = line.decode(errors="ignore").strip()
            print(f"recv: {text}")

            lower = text.lower()

            if "trop lent" in lower or "non oust" in lower:
                break

            if any(word in lower for word in ["flag", "bravo", "congrats", "gg"]):
                print("\n=== MESSAGE FINAL ===")
                print(text)
                break

            # On ne répond QUE si la ligne contient la donnée à décoder
            if "a décoder:" not in lower:
                continue

            blob = text.split(":", 1)[1].strip()
            answer = smart_decode(blob)

            print(f"send: {answer}")
            io.sendline(answer.encode())

    except EOFError:
        print("[*] Connexion fermée par le serveur")
    finally:
        io.close()

if __name__ == "__main__":
    main()
