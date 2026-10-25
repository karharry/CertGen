"""Run inside the image: docker run --rm -v "$PWD/test_certgen.py:/srv/test_certgen.py" certgen python test_certgen.py"""
import os, tempfile
from pathlib import Path

os.environ["CERTGEN_CONFIG"] = tempfile.mkdtemp()
data = tempfile.mkdtemp()
os.environ["CERTGEN_DATA"] = data
import app as a
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7
from werkzeug.security import generate_password_hash

c = a.app.test_client()
assert c.get("/api/certs").status_code == 401 and c.get("/api/me").status_code == 401  # login required
assert [r["name"] for r in a.q("SELECT name FROM users")] == ["admin"]  # first run created the default admin
a.q("UPDATE users SET pw=? WHERE name='admin'", generate_password_hash("adminpass1"))
assert c.post("/api/login", json=dict(username="admin", password="nope")).status_code == 401
assert c.post("/api/login", json=dict(username="admin", password="adminpass1")).status_code == 200

out = str(Path(data) / "out")
addr = lambda fmt: "h-" + fmt.replace("+", "-") + ".lan" if fmt != "crl" else "10.0.0.5"
for fmt in a.FORMATS:
    r = c.post("/api/certs", json=dict(addresses=addr(fmt), days=30, fmt=fmt, folder=out, password="pw"))
    assert r.status_code == 200, (fmt, r.json)
    for f in r.json["files"]:
        assert Path(f).stat().st_size > 0
    assert c.post("/api/certs", json=dict(addresses=addr(fmt), days=30, fmt=fmt, folder=out)).status_code == 400  # no overwrite
p = lambda n: Path(out, n).read_bytes()
assert x509.load_der_x509_certificate(p("h-der.lan.der")).subject.rfc4514_string() == "CN=h-der.lan"
assert pkcs12.load_key_and_certificates(p("h-pfx.lan.pfx"), b"pw")[1] is not None
assert len(pkcs7.load_der_pkcs7_certificates(p("h-p7c.lan.p7c"))) == 1
assert x509.load_pem_x509_crl(p("10.0.0.5.crl")).issuer.rfc4514_string() == "CN=10.0.0.5"
assert oct(Path(out, "h-key.lan.key").stat().st_mode & 0o777) == "0o600"

# multi-domain + wildcard, renewal with a changed list
r = c.post("/api/certs", json=dict(name="homelab", addresses="service1.home, service2.home\n*.wild.home 192.168.1.9", days=30, fmt="crt", folder=out))
assert r.status_code == 200, r.json
san = x509.load_pem_x509_certificate(p("homelab.crt")).extensions.get_extension_for_class(x509.SubjectAlternativeName).value
assert [str(v.value) for v in san] == ["service1.home", "service2.home", "*.wild.home", "192.168.1.9"]
rid = c.get("/api/certs").json[0]["id"]
assert c.post(f"/api/certs/{rid}/renew", json=dict(addresses="a.home b.home", days=10, fmt="crt", folder=out)).status_code == 200
san = x509.load_pem_x509_certificate(p("homelab.crt")).extensions.get_extension_for_class(x509.SubjectAlternativeName).value
assert [str(v.value) for v in san] == ["a.home", "b.home"]
assert c.post("/api/certs", json=dict(addresses="ok.lan bad!addr", days=1, fmt="crt", folder=out)).status_code == 400

# folder picker is confined to /data
assert c.post("/api/certs", json=dict(addresses="x.lan", days=1, fmt="crt", folder="/etc")).status_code == 400
assert c.post("/api/certs", json=dict(addresses="x.lan", days=1, fmt="crt", folder=data + "/../etc")).status_code == 400
assert c.get("/api/ls?path=/").status_code == 400 and c.get("/api/ls").json["path"] == data

# command console
r = c.post("/api/run", json=dict(script="echo hello\necho second", timeout=20))
assert r.status_code == 200 and r.json["output"] == "hello\nsecond\n" and r.json["exit"] == 0, r.json
assert c.post("/api/run", json=dict(script="x"), headers={"Origin": "http://evil.example"}).status_code == 403

# users: any admin can add users and delete the others, never themselves; deleted users lose their session
assert c.post("/api/users", json=dict(name="bob", password="short")).status_code == 400
assert c.post("/api/users", json=dict(name="bob", password="bobpass123")).status_code == 200
assert c.post("/api/users", json=dict(name="bob", password="bobpass123")).status_code == 400
b = a.app.test_client()
assert b.post("/api/login", json=dict(username="bob", password="bobpass123")).status_code == 200
users = {u["name"]: u["id"] for u in b.get("/api/users").json}
assert b.delete(f"/api/users/{users['bob']}").status_code == 400  # not yourself
assert c.delete(f"/api/users/{users['admin']}").status_code == 400
assert b.post("/api/password", json=dict(current="wrong", new="newbobpass1")).status_code == 400
assert b.post("/api/password", json=dict(current="bobpass123", new="newbobpass1")).status_code == 200
assert b.delete(f"/api/users/{users['admin']}").status_code == 200  # bob deletes admin
assert c.get("/api/certs").status_code == 401  # admin's session is gone
b2 = a.app.test_client()
assert b2.post("/api/login", json=dict(username="bob", password="newbobpass1")).status_code == 200
hist = b2.get("/api/history").json
assert {h["user"] for h in hist} >= {"admin", "bob"} and any(h["action"] == "user deleted" and h["detail"] == "admin" and h["user"] == "bob" for h in hist)
print("ok")
