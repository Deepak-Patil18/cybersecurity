#!/usr/bin/env python3
"""Usage: python3 entropy.py sample.bin   (prints entropy per 512-byte block, 0-8)"""
import sys, math
from collections import Counter
data = open(sys.argv[1], "rb").read()
def entropy(b):
    n = len(b)
    return max(0.0, -sum(c/n * math.log2(c/n) for c in Counter(b).values())) if n else 0.0
print(f"Overall entropy: {entropy(data):.2f}")
for i in range(0, len(data), 512):
    e = entropy(data[i:i+512])
    flag = "  <-- HIGH (possibly packed/encrypted)" if e > 7.0 else ""
    print(f"offset {i:5d}: {e:4.2f} {'#' * int(e*4)}{flag}")
