"""Inc 3a E3 architect: corpus census of MATRIX_DIM owners (text only, comments left out). THROWAWAY.

For every CHARACTERISTIC with a MATRIX_DIM, its kind word and whether the MATRIX_DIM has a leading or
inner 1 (a 1 that is not trailing). For every MEASUREMENT, the same. Prints counts per file class.

Usage: python3 -I i3e3a-corpus-md.py <corpus files dir>
"""
import collections
import glob
import os
import re
import sys

COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
CHAR = re.compile(r'/begin\s+CHARACTERISTIC\s+(\S+)\s+"[^"]*"\s+(\S+)(.*?)/end\s+CHARACTERISTIC', re.S)
MEAS = re.compile(r'/begin\s+MEASUREMENT\s+(\S+)\s+"[^"]*"(.*?)/end\s+MEASUREMENT', re.S)
MD = re.compile(r"\bMATRIX_DIM((?:\s+\d+){1,3})")


def form(nums):
    last = len(nums)
    while last > 1 and nums[last - 1] == "1":
        last -= 1
    return "nontrail1" if "1" in nums[:last] and any(n != "1" for n in nums) else "plain"


def main():
    os.chdir(sys.argv[1])
    char = collections.Counter()
    meas = collections.Counter()
    files = collections.defaultdict(set)
    for f in sorted(glob.glob("*.a2l")):
        t = COMMENT.sub(" ", open(f, encoding="latin-1").read())
        for m in CHAR.finditer(t):
            md = MD.search(m.group(3))
            if md:
                k = (m.group(2), form(md.group(1).split()))
                char[k] += 1
                files[k].add(f)
        for m in MEAS.finditer(t):
            md = MD.search(m.group(2))
            if md:
                nums = md.group(1).split()
                if all(n == "1" for n in nums):
                    k = ("MEASUREMENT", "all1")
                else:
                    k = ("MEASUREMENT", form(nums))
                meas[k] += 1
                files[k].add(f)
    for k, v in sorted(char.items()):
        print("CHARACTERISTIC", k, v, "files", len(files[k]))
    for k, v in sorted(meas.items()):
        print(k, v, "files", len(files[k]))


if __name__ == "__main__":
    main()
