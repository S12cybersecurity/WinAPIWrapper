#!/usr/bin/env python3
import sys

def make_array(s: str, key: int = 0xAA):
    data = [ord(c) ^ key for c in s] + [0]  # includes NUL terminator
    return ", ".join(f"0x{b:02X}" for b in data)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: make_xor_array.py \"string\" [hex_key]")
        print("Ex.: make_xor_array.py \"My Secret\" AA")
        sys.exit(1)

    s = sys.argv[1]
    key = int(sys.argv[2], 16) if len(sys.argv) >= 3 else 0xAA

    print("constexpr unsigned char enc[] = {")
    print("    " + make_array(s, key))
    print("};")
