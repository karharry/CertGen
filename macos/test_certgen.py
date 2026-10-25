"""Run: python test_certgen.py  - generates every format and parses it back."""
import os, tempfile
from pathlib import Path

os.environ["CERTGEN_CONFIG"] = tempfile.mkdtemp()
import app as a
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7

c = a.app.test_client()
out = tempfile.mkdtemp()
for fmt in a.FORMATS:
    r = c.post("/api/certs", json=dict(addresses="h-"+fmt.replace("+","-")+".lan" if fmt != "crl" else "10.0.0.5", days=30, fmt=fmt, folder=out, password="pw"))
    assert r.status_code == 200, (fmt, r.json)
    for f in r.json["files"]:
        assert Path(f).stat().st_size > 0
    assert c.post("/api/certs", json=dict(addresses="h-"+fmt.replace("+","-")+".lan" if fmt != "crl" else "10.0.0.5", days=30, fmt=fmt, folder=out)).status_code == 400  # no overwrite
p = lambda n: Path(out, n).read_bytes()
assert x509.load_der_x509_certificate(p("h-der.lan.der")).subject.rfc4514_string() == "CN=h-der.lan"
assert pkcs12.load_key_and_certificates(p("h-pfx.lan.pfx"), b"pw")[1] is not None
assert len(pkcs7.load_der_pkcs7_certificates(p("h-p7c.lan.p7c"))) == 1
assert x509.load_pem_x509_crl(p("10.0.0.5.crl")).issuer.rfc4514_string() == "CN=10.0.0.5"
rid = c.get("/api/certs").json[0]["id"]
r = c.post(f"/api/certs/{rid}/renew", json=dict(days=90, fmt="crt", folder=out))
assert r.status_code == 200, r.json
assert c.post("/api/certs", json=dict(addresses="ok.lan bad!addr", days=1, fmt="crt", folder=out)).status_code == 400
assert len(c.get("/api/history").json) >= 12
r = c.post("/api/run", json=dict(script="echo hello\necho second", timeout=20))
assert r.status_code == 200 and "hello" in r.json["output"] and "second" in r.json["output"] and r.json["exit"] == 0, r.json
assert c.post("/api/run", json=dict(script="x"), headers={"Origin": "http://evil.example"}).status_code == 403
r = c.post("/api/certs", json=dict(name="homelab", addresses="service1.home, service2.home\n*.wild.home 192.168.1.9", days=30, fmt="crt", folder=out))
assert r.status_code == 200, r.json
cert = x509.load_pem_x509_certificate(p("homelab.crt"))
san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
assert [str(v.value) for v in san] == ["service1.home", "service2.home", "*.wild.home", "192.168.1.9"], list(san)
assert cert.subject.rfc4514_string() == "CN=homelab"
rid = c.get("/api/certs").json[0]["id"]
assert c.post(f"/api/certs/{rid}/renew", json=dict(addresses="a.home b.home", days=10, fmt="crt", folder=out)).status_code == 200
san = x509.load_pem_x509_certificate(p("homelab.crt")).extensions.get_extension_for_class(x509.SubjectAlternativeName).value
assert [str(v.value) for v in san] == ["a.home", "b.home"]
print("ok")
