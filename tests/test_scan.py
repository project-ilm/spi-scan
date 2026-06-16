from spi_scan.scanner import scan_text
def test_email(): assert any(h["type"]=="email" for h in scan_text("x me@foo.com"))
def test_allow(): assert not scan_text("user@example.com")
def test_pat():   assert any(h["severity"]=="HIGH" for h in scan_text("ghp_"+"a"*36))
