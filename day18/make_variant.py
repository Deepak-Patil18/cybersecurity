data = open("sample.bin", "rb").read().replace(b"198.51.100.77", b"198.51.100.88")
open("sample_v2.bin", "wb").write(data)
print("Created sample_v2.bin (same malware, different C2 IP)")
