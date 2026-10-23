import sys
p, newf = sys.argv[1], sys.argv[2]
s = open(p, encoding="utf-8", newline="").read()
new = open(newf, encoding="utf-8").read()
start = s.index("**Structure — Flow Execution widget tree (Inc-6).**")
end = s.index("**Structure — Check Editor widget tree (Inc-3")
nl = "\r\n" if "\r\n" in s[start:end] else "\n"
s = s[:start] + new.replace("\n", nl) + s[end:]
open(p, "w", encoding="utf-8", newline="").write(s)
print("ok crlf" if nl == "\r\n" else "ok lf")
