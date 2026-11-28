#!/usr/bin/env python3
"""CVSS v3.1 base score calculator. Usage: python3 cvss_calc.py "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" """
import sys, math
 
W = {
  "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
  "AC": {"L": 0.77, "H": 0.44},
  "UI": {"N": 0.85, "R": 0.62},
  "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.50}}
 
def roundup(x):
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0
 
def score(vector):
    m = dict(p.split(":") for p in vector.replace("CVSS:3.1/", "").split("/"))
    scope = m["S"]
    iss = 1 - (1 - W["CIA"][m["C"]]) * (1 - W["CIA"][m["I"]]) * (1 - W["CIA"][m["A"]])
    impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    expl = 8.22 * W["AV"][m["AV"]] * W["AC"][m["AC"]] * PR[scope][m["PR"]] * W["UI"][m["UI"]]
    if impact <= 0: return 0.0
    base = roundup(min(impact + expl, 10)) if scope == "U" else roundup(min(1.08 * (impact + expl), 10))
    return base
 
def severity(s):
    return "None" if s == 0 else "Low" if s < 4 else "Medium" if s < 7 else "High" if s < 9 else "Critical"
 
if __name__ == "__main__":
    for v in sys.argv[1:]:
        s = score(v)
        print(f"{s:4.1f}  {severity(s):8}  {v}")
