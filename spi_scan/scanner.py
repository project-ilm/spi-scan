"""Core scanning logic — text, files, and git history."""
import os, subprocess
from .patterns import COMPILED, ALLOW

def _allowed(line):
    low = line.lower()
    return any(a.lower() in low for a in ALLOW)

def scan_text(text, source="<text>"):
    hits = []
    for i, line in enumerate(text.splitlines(), 1):
        if _allowed(line):
            continue
        for name, sev, rx in COMPILED:
            for m in rx.finditer(line):
                val = m.group(0)
                if any(a.lower() in val.lower() for a in ALLOW):
                    continue
                hits.append({"source": source, "line": i, "type": name,
                             "severity": sev, "match": _redact(val)})
    return hits

def _redact(v):
    if len(v) <= 8: return v[0] + "***"
    return v[:4] + "***" + v[-2:]

def scan_path(root):
    hits = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in (".git","node_modules","__pycache__",".venv")]
        for fn in fns:
            p = os.path.join(dp, fn)
            try:
                with open(p, encoding="utf-8", errors="ignore") as fh:
                    hits += scan_text(fh.read(), os.path.relpath(p, root))
            except Exception:
                pass
    return hits

def scan_git_history(repo):
    """Scan full git history (all commits, all branches) via git log -p."""
    try:
        out = subprocess.run(
            ["git","-C",repo,"log","--all","-p","--no-color"],
            capture_output=True, text=True, timeout=300).stdout
    except Exception as e:
        return [{"source":"git-history","line":0,"type":"error","severity":"LOW","match":str(e)}]
    return scan_text(out, "git-history(--all -p)")
