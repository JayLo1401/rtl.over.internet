#!/usr/bin/env python3
"""Next version from the commits since the last release (same scheme as rtltcp.server / home.control).

Called by .github/workflows/release.yml. Environment:
  BASE_VERSION  version of the last release (tag without "v"), empty if none
  BASE_REF      its tag, empty if none (then all commits count)
  NOTES_PATH    where to write the release notes (Markdown)

Without a previous release the version from app/__init__.py (__version__) is used as is.

Bump (subject line, Conventional Commits style):
  "type!:" or "BREAKING CHANGE" or "[major]"  -> major
  "feat:" or "[minor]"                        -> minor
  anything else                               -> patch

Prints only the new version on stdout, everything else goes to stderr.
"""
import os
import re
import subprocess
import sys

SUBJECT = re.compile(r"^(?P<type>[A-Za-z]+)(?:\([^)]*\))?(?P<bang>!)?:\s*(?P<text>.+)$")
SECTIONS = [("feat", "Neu"), ("fix", "Behoben")]


def log(msg):
    print(msg, file=sys.stderr)


def source_version():
    with open("app/__init__.py", encoding="utf-8") as f:
        m = re.search(r'__version__\s*=\s*"(\d+\.\d+\.\d+)"', f.read())
    return m.group(1) if m else "0.1.0"


def commits(base_ref):
    rng = f"{base_ref}..HEAD" if base_ref else "HEAD"
    out = subprocess.run(
        ["git", "log", rng, "--no-merges", "--format=%s"], check=True, capture_output=True, text=True
    ).stdout
    return [s for s in out.splitlines() if s.strip() and "[skip ci]" not in s]


def main():
    base_ref = os.environ.get("BASE_REF") or ""
    notes_path = os.environ["NOTES_PATH"]
    subjects = commits(base_ref)
    log(f"{len(subjects)} commits since {base_ref or 'start'}")

    if not base_ref:
        version = source_version()
        log(f"first release: {version}")
    else:
        base_version = os.environ.get("BASE_VERSION") or source_version()
        major, minor, patch = (int(x) for x in base_version.split("."))
        bump = "patch"
        for s in subjects:
            m = SUBJECT.match(s)
            if "[major]" in s or (m and m.group("bang")) or "BREAKING CHANGE" in s:
                bump = "major"
                break
            if "[minor]" in s or (m and m.group("type").lower() == "feat"):
                bump = "minor"
        if bump == "major":
            major, minor, patch = major + 1, 0, 0
        elif bump == "minor":
            minor, patch = minor + 1, 0
        else:
            patch += 1
        version = f"{major}.{minor}.{patch}"
        # A higher version in app/__init__.py (e.g. 1.0.0) wins over the computed one.
        if tuple(int(x) for x in source_version().split(".")) > (major, minor, patch):
            version = source_version()
        log(f"{bump}: {base_version} -> {version}")

    grouped = {key: [] for key, _ in SECTIONS}
    other = []
    for s in subjects:
        m = SUBJECT.match(s)
        text = (m.group("text") if m else s).replace("[major]", "").replace("[minor]", "").strip()
        key = m.group("type").lower() if m else ""
        (grouped[key] if key in grouped else other).append(text)
    lines = []
    for key, title in SECTIONS:
        if grouped[key]:
            lines += [f"### {title}", *[f"- {t}" for t in grouped[key]], ""]
    if other:
        lines += ["### Sonstiges", *[f"- {t}" for t in other], ""]
    with open(notes_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) or "Keine Änderungen.\n")

    print(version)


if __name__ == "__main__":
    main()
