# tools/version_bump.py
# WRAITH version bump utility
# usage: python3 tools/version_bump.py v3.3
import os, sys

import glob
FILES = (
    ["wraith.py", "HANDOFF.md"] +
    glob.glob("README.md") +
    glob.glob("**/README.md", recursive=True) +
    glob.glob("**/*.md", recursive=True)
)

VERSIONS = ["v3.1", "v3.2", "v3.3", "v3.4", "v4.0", "v4.1", "v5.0"]
def bump_version(new_ver):
    print(f"  [WRAITH] bumping all files to {new_ver}")
    changed = 0
    for fp in FILES:
        if not os.path.exists(fp):
            print(f"  [SKIP] {fp} not found")
            continue
        with open(fp) as f: content = f.read()
        original = content
        for old in VERSIONS:
            if old != new_ver:
                content = content.replace(old, new_ver)
        if content != original:
            with open(fp, "w") as f: f.write(content)
            print(f"  [OK] updated {fp}")
            changed += 1
        else:
            print(f"  [--] no changes in {fp}")
    print(f"  [+] {changed} files updated to {new_ver}")
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("  usage: python3 tools/version_bump.py v3.4")
        sys.exit(1)
    new_ver = sys.argv[1]
    if not new_ver.startswith("v"):
        print("  [!] version must start with v — example: v3.4")
        sys.exit(1)
    bump_version(new_ver)
