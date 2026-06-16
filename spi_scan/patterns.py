"""Detection patterns for sensitive personal information.
Each entry: (name, severity, compiled regex). Severity: HIGH|MEDIUM|LOW.
Tunable + extensible. False positives are expected; review every hit."""
import re
P = [
 ("email",            "MEDIUM", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
 ("aws_access_key",   "HIGH",   r"AKIA[0-9A-Z]{16}"),
 ("aws_secret",       "HIGH",   r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}"),
 ("gcp_key",          "HIGH",   r"AIza[0-9A-Za-z_\-]{35}"),
 ("github_pat",       "HIGH",   r"gh[pousr]_[A-Za-z0-9]{36,}"),
 ("pypi_token",       "HIGH",   r"pypi-AgE[A-Za-z0-9_\-]{50,}"),
 ("zenodo_token",     "HIGH",   r"\b[A-Za-z0-9]{60}\b"),
 ("slack_token",      "HIGH",   r"xox[baprs]-[A-Za-z0-9-]{10,}"),
 ("private_key",      "HIGH",   r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
 ("jwt",              "MEDIUM", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
 ("phone_intl",       "LOW",    r"(?<!\d)\+?\d{1,3}[\s-]?\(?\d{2,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}(?!\d)"),
 ("ipv4",             "LOW",    r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)"),
 ("home_path_unix",   "LOW",    r"/home/[A-Za-z0-9._-]+/"),
 ("home_path_mac",    "LOW",    r"/Users/[A-Za-z0-9._-]+/"),
 ("aadhaar",          "HIGH",   r"(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\d)"),
 ("credit_card",      "HIGH",   r"(?<!\d)(?:\d[ -]?){13,16}(?!\d)"),
 ("passport_in",      "MEDIUM", r"(?<![A-Z0-9])[A-PR-WY][0-9]{7}(?![A-Z0-9])"),
]
# Allowlist: substrings that mark a match as a placeholder/non-secret.
ALLOW = ["your-token","xxxx","paste","example.com","0000-0000-0000-0000",
         "127.0.0.1","0.0.0.0","localhost","pypi-AgEN...","...your",
         "user@","name@","family, given","AKIAIOSFODNN7EXAMPLE"]
COMPILED = [(n, s, re.compile(rx)) for n, s, rx in P]
