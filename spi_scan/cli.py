"""spi-scan CLI. Usage:
  spi-scan path <dir>                 scan a working tree
  spi-scan git  <repo>                scan full git history (all branches)
  spi-scan gh   <owner/repo>          scan issues, comments, releases via gh
  spi-scan all  <repo> <owner/repo>   everything
Exit codes: 0 clean, 7 HIGH findings, 0 otherwise (LOW/MEDIUM reported)."""
import sys, json, subprocess
from .scanner import scan_path, scan_git_history, scan_text

def _gh(args):
    return subprocess.run(["gh"]+args, capture_output=True, text=True).stdout

def scan_gh(slug):
    hits = []
    for kind, cmd in [
        ("issues",  ["issue","list","-R",slug,"--state","all","--limit","200","--json","title,body"]),
        ("prs",     ["pr","list","-R",slug,"--state","all","--limit","200","--json","title,body"]),
        ("releases",["release","list","-R",slug]),
    ]:
        out = _gh(cmd)
        if out: hits += scan_text(out, f"gh:{kind}")
    # issue/pr comments
    try:
        ids = subprocess.run(["gh","issue","list","-R",slug,"--state","all",
                              "--limit","200","--json","number","-q",".[].number"],
                             capture_output=True,text=True).stdout.split()
        for n in ids[:100]:
            c = _gh(["issue","view",n,"-R",slug,"--comments"])
            if c: hits += scan_text(c, f"gh:issue#{n}:comments")
    except Exception:
        pass
    return hits

def report(hits):
    by_sev = {"HIGH":[], "MEDIUM":[], "LOW":[]}
    for h in hits: by_sev.get(h["severity"], by_sev["LOW"]).append(h)
    print(json.dumps({"summary":{k:len(v) for k,v in by_sev.items()},
                      "findings":hits}, indent=2))
    return 7 if by_sev["HIGH"] else 0

def main(argv=None):
    a = argv or sys.argv[1:]
    if not a:
        print(__doc__); return 1
    cmd = a[0]; hits=[]
    if cmd=="path" and len(a)>1: hits=scan_path(a[1])
    elif cmd=="git" and len(a)>1: hits=scan_git_history(a[1])
    elif cmd=="gh" and len(a)>1: hits=scan_gh(a[1])
    elif cmd=="all" and len(a)>2:
        hits=scan_path(a[1])+scan_git_history(a[1])+scan_gh(a[2])
    else:
        print(__doc__); return 1
    return report(hits)

if __name__=="__main__": sys.exit(main())
