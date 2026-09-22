#!/usr/bin/env bash
set -euo pipefail

file="${1:-radmin_probe.c}"
[[ -f "$file" ]] || { echo "File not found: $file" >&2; exit 1; }
cp "$file" "$file.bak"

python3 - "$file" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
s = path.read_text()

# Keep discoveries in the counters/output files, but do not print a new line.
s, n = re.subn(
    r'\s*printf\("\\n\\[found\] %s:%d -> Radmin %s\\n",\s*j->targets\[index\]\.ip,\s*j->port,\s*version\);',
    '',
    s,
)
if n == 0:
    print("warning: no [found] print statement matched", file=sys.stderr)

# Clear the previous terminal line before repainting the progress line.
s, n_progress = re.subn(
    r'printf\("\\r\[progress\] checked:',
    'printf("\\033[2K\\r[progress] checked:',
    s,
)
if n_progress == 0:
    print("warning: no progress printf matched", file=sys.stderr)

path.write_text(s)
PY

echo "Updated $file"
echo "Backup: $file.bak"
