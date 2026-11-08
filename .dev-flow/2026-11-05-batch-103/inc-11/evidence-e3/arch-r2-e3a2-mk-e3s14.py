"""Write the synthetic file of R-A2L-READ.52/3 (E3S-14): one quoted string over 200,000 lines. Synthetic text only.

    python -I e3a2-mk-e3s14.py <out path>
"""
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
body = "\n".join(f"line {k} of one synthetic quoted string" for k in range(1, 200001))
text = (
    'ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MEASUREMENT X ""\n'
    " UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n /begin ANNOTATION\n  /begin ANNOTATION_TEXT\n"
    '   "' + body + '"\n  /end ANNOTATION_TEXT\n /end ANNOTATION\n/end MEASUREMENT\n/end MODULE\n/end PROJECT\n'
)
out.write_text(text, encoding="utf-8")
print(out, out.stat().st_size, "bytes", text.count("\n"), "lines")
