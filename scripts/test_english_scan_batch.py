#!/usr/bin/env python3
"""Pin English-only scan boundaries and diagnostics without per-character Python dispatch."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile

GUARD = Path(__file__).with_name("check_english_only.sh").resolve()
RANGES = [(0x3040, 0x30FF), (0x3400, 0x4DBF), (0x4E00, 0x9FFF),
          (0xAC00, 0xD7AF), (0xF900, 0xFAFF), (0xFF01, 0xFF60), (0x20000, 0x2FA1F)]
FOOTER = "\nTranslate before it lands. `rustfs/backlog` is the one repository in the\norganisation where Chinese is allowed; this is not that repository.\n"

with tempfile.TemporaryDirectory(prefix="gateway-english-scan-") as temporary:
    root = Path(temporary)
    repository = root / "repo"
    repository.mkdir()
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    files = {}

    def write(name, text):
        path = repository / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        files[name] = text

    for index, (low, high) in enumerate(RANGES):
        for side, point in [("before", low - 1), ("low", low), ("high", high), ("after", high + 1)]:
            write(f"range-{index}-{side}.txt", "prefix " + chr(point) + " suffix\n")
    write("ascii.txt", "a" * 5000 + "\n")
    write("unicode.txt", " ".join(chr(point) for point in [0xE9, 0x2014, 0xB7, 0x1F600]) + "\n")
    write("diagnostics.txt", "safe\n  " + chr(0x4E00) + "x" * 100 + "  \n" + (chr(0x3040) + "\n") * 4)
    write("allowed.txt", chr(0x4E00))
    write("scripts/allowances/english-only-allowances.txt", "allowed.txt # authored fixture\n")
    write("model/s3.json", chr(0x4E00))
    write("model/sts.json", chr(0x4E00))
    write("digest.sha256", chr(0x4E00))
    write(".gitignore", "ignored.txt\n")
    write("ignored.txt", chr(0x4E00))
    (repository / "binary.dat").write_bytes(b"\xff\xfe")
    # Mix cached and new files: their actual git ordering is part of the diagnostic contract.
    subprocess.run(["git", "add", "range-0-low.txt", "ascii.txt"], cwd=repository, check=True)
    tracked = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                             cwd=repository, check=True, text=True, capture_output=True).stdout.splitlines()
    expected = []
    for name in tracked:
        if name not in files or name in {"allowed.txt", "model/s3.json", "model/sts.json", "digest.sha256"}:
            continue
        hits = [(number, line) for number, line in enumerate(files[name].splitlines(), 1)
                if any(low <= ord(char) <= high for char in line for low, high in RANGES)]
        if hits:
            expected.append(f"{name}: contains CJK text; everything that lands here is English (AGENTS.md, Language Requirements)\n")
            expected.extend(f"    {number}: {line.strip()[:90]}\n" for number, line in hits[:3])

    # Count Python calls in the embedded scanner, not wall time or unrelated fixture work.
    # A per-character Python predicate on the long ASCII line necessarily exceeds this budget.
    bins = root / "bin"
    bins.mkdir()
    counter = root / "calls"
    wrapper = bins / "python3"
    wrapper.write_text(f"#!{sys.executable}\n" + '''import os, sys
source = sys.stdin.read()
count = 0
def profile(frame, event, arg):
    global count
    if event == "call" and frame.f_code.co_filename == "<english-guard>":
        count += 1
sys.argv = sys.argv[1:]
sys.setprofile(profile)
try:
    exec(compile(source, "<english-guard>", "exec"), {"__name__": "__main__"})
finally:
    sys.setprofile(None)
    with open(os.environ["SCAN_CALLS"], "w") as output:
        output.write(str(count))
''')
    wrapper.chmod(0o755)
    environment = dict(os.environ, GATEWAY_CHECK_ROOT=str(repository), SCAN_CALLS=str(counter),
                       PATH=str(bins) + os.pathsep + os.environ["PATH"])
    result = subprocess.run(["bash", str(GUARD)], env=environment, text=True, capture_output=True)
    assert result.returncode == 1, result
    assert result.stderr == "".join(expected) + FOOTER, result.stderr
    assert result.stdout == "", result.stdout
    calls = int(counter.read_text())
    assert calls <= 100, f"scanner made {calls} Python calls; line scanning must not dispatch per character"

    for name in files:
        if name not in {"allowed.txt", "model/s3.json", "model/sts.json", "digest.sha256", "ignored.txt"}:
            path = repository / name
            if path.suffix == ".txt" and name != "scripts/allowances/english-only-allowances.txt":
                path.write_text("ASCII and " + chr(0x1F600) + "\n")
    clean = subprocess.run(["bash", str(GUARD)], env=environment, text=True, capture_output=True)
    assert clean.returncode == 0 and clean.stderr == "" and clean.stdout == "", clean
print("OK: English scan preserves all range boundaries, exclusions, decode tolerance and exact diagnostics with bounded Python dispatch")
