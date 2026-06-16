# spi-scan

**Sensitive Personal Information scanner** for repositories, their full git
history, and GitHub metadata (issues, PRs, comments, releases).

Project-neutral, general-purpose. Part of [Project ILM](https://github.com/project-ilm),
released for anyone to use. © 1993–2026 Abhishek Choudhary. GPL-3.0-or-later.

## Why
Before transferring, open-sourcing, or releasing a repo, you want to know if any
email, token, key, phone number, home path, or other SPI leaked into the code or
into history. spi-scan checks all of it.

## Install
```bash
pip install spi-scan
```

## Use
```bash
spi-scan path  ./myrepo                  # scan working tree
spi-scan git   ./myrepo                  # scan FULL git history (all branches)
spi-scan gh    owner/repo                # scan issues, PRs, comments, releases
spi-scan all   ./myrepo owner/repo       # everything
```
Output is JSON: a severity summary (HIGH/MEDIUM/LOW) and redacted findings.
Exit code `7` if any HIGH finding, else `0`. Review every hit — false positives
are expected and an allowlist filters common placeholders.

## What it detects
Emails, AWS/GCP keys, GitHub PATs, PyPI/Zenodo/Slack tokens, private keys, JWTs,
phone numbers, IPs, home paths, Aadhaar, credit-card-like numbers, passport-like
IDs. Patterns live in `spi_scan/patterns.py` — extend freely.

## Not a guarantee
spi-scan reduces risk; it does not certify a repo SPI-free. Treat it as a
high-recall first pass, then review.
