# Security policy

## Supported versions

| Version | Security fixes |
|--------|----------------|
| `1.0.x` | yes |
| `0.x and the 1.0.0 release candidates` | no |

## Reporting a vulnerability

Please report a vulnerability privately, not in a public issue: open the repository's **Security** tab on GitHub and choose **Report a vulnerability** (GitHub private vulnerability reporting).

Include:
- the version (`s19_app/version.py`, or `pip show s19tool`);
- what the vulnerability lets someone do;
- the steps, or a small input file, that show it — synthetic files only, never firmware, A2L or MAC files you are not free to share.

## Scope

s19_app is an offline terminal tool: it opens no network connection. What it must withstand is the content of the files it reads — S19, Intel HEX, A2L, MAC, project manifests (`project.json`), and the change-set, check, CRC config, CRC Designer template, flow, flow set and report filter files — and of text pasted into it, and where it writes, under its work area (`.s19tool/`). Apart from opening a folder in the system file manager and using the system clipboard, the app starts no process; it never runs an external step's command, which is text from the flow file that a person runs outside the app. Examples of a vulnerability: a crafted input file that makes the app write outside its work area, run a command, or paint escape sequences or markup taken from the file; a small file that makes it use unbounded memory or time.
