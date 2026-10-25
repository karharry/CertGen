"""CertGen (macOS): self-signed certificate generator in a native window."""
import datetime as dt, ipaddress, json, logging, os, re, sqlite3, subprocess, sys, threading
from contextlib import closing
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from flask import Flask, jsonify, request, send_from_directory

RES = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
# state lives in Application Support (a .app bundle must not be written to)
CONFIG = Path(os.environ.get("CERTGEN_CONFIG") or Path.home() / "Library" / "Application Support" / "CertGen")
CONFIG.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s",
                    handlers=[logging.StreamHandler(), logging.FileHandler(CONFIG / "certgen.log")])
FORMATS = ["crt", "cer", "pem", "key", "cert+key", "der", "p12", "pfx", "p7b", "p7c", "crl"]
PEM, DER = serialization.Encoding.PEM, serialization.Encoding.DER

app = Flask(__name__, static_folder=None)


class Bad(Exception):
    pass


@app.errorhandler(Bad)
def _bad(e):
    return jsonify(error=str(e)), 400


# ---------- storage ----------
def now():
    return dt.datetime.now(dt.timezone.utc)


def q(sql, *a):
    with closing(sqlite3.connect(CONFIG / "certgen.db")) as c:
        c.row_factory = sqlite3.Row
        with c:
            cur = c.execute(sql, a)
            return cur.fetchall() if cur.description else cur.lastrowid


q("""CREATE TABLE IF NOT EXISTS certs(id INTEGER PRIMARY KEY, address TEXT, base TEXT, fmt TEXT, days INT,
   folder TEXT, files TEXT, not_after TEXT, created TEXT, renewed INT DEFAULT 0)""")
try:
    q("ALTER TABLE certs ADD COLUMN name TEXT")  # older state files
except sqlite3.OperationalError:
    pass
q("""CREATE TABLE IF NOT EXISTS log(id INTEGER PRIMARY KEY, ts TEXT, action TEXT, detail TEXT)""")


def log(action, detail=""):
    q("INSERT INTO log(ts,action,detail) VALUES(?,?,?)", now().isoformat(timespec="seconds"), action, detail)
    logging.info("%s %s", action, detail)


# ---------- crypto ----------
def parse_addrs(raw):
    items = list(dict.fromkeys(a for a in re.split(r"[,\s]+", raw or "") if a))  # de-duplicated, order kept
    if not items:
        raise Bad("Enter at least one address")
    for a in items:
        if not re.fullmatch(r"[A-Za-z0-9.\-:_*]{1,253}", a):
            raise Bad(f"Invalid address: {a} (hostname, IP or *.wildcard)")
    return items


def san_for(a):
    try:
        return x509.IPAddress(ipaddress.ip_address(a))
    except ValueError:
        return x509.DNSName(a)


def build_cert(cn, addrs, days, key):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    t = now()
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(t - dt.timedelta(minutes=5)).not_valid_after(t + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([san_for(a) for a in addrs]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(x509.KeyUsage(True, False, True, False, False, True, True, False, False), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .sign(key, hashes.SHA256()))


def render(fmt, cert, key, pw):
    """-> {filename suffix: bytes}"""
    kb = key.private_bytes(PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    cb, db_ = cert.public_bytes(PEM), cert.public_bytes(DER)
    enc = serialization.BestAvailableEncryption(pw.encode()) if pw else serialization.NoEncryption()
    p12 = lambda: pkcs12.serialize_key_and_certificates(b"certgen", key, cert, None, enc)
    crl = lambda: (x509.CertificateRevocationListBuilder().issuer_name(cert.subject)
                   .last_update(now()).next_update(now() + dt.timedelta(days=30))
                   .sign(key, hashes.SHA256()).public_bytes(PEM))
    return {"crt": lambda: {".crt": cb}, "cer": lambda: {".cer": db_}, "der": lambda: {".der": db_},
            "pem": lambda: {".pem": cb + kb},  # cert + key in one file (HAProxy-style)
            "key": lambda: {".key": kb}, "cert+key": lambda: {".crt": cb, ".key": kb},
            "p12": lambda: {".p12": p12()}, "pfx": lambda: {".pfx": p12()},
            "p7b": lambda: {".p7b": pkcs7.serialize_certificates([cert], PEM)},
            "p7c": lambda: {".p7c": pkcs7.serialize_certificates([cert], DER)},
            "crl": lambda: {".crl": crl()}}[fmt]()


def safe_dir(p):
    d = Path(p or Path.home()).expanduser().resolve()
    d.mkdir(parents=True, exist_ok=True)
    return d


def emit(fmt, cert, key, folder, base, pw, overwrite):
    out = {base + s: b for s, b in render(fmt, cert, key, pw).items()}
    if not overwrite:
        for n in out:
            if (folder / n).exists():
                raise Bad(f"{n} already exists in that folder")
    for n, b in out.items():
        (folder / n).write_bytes(b)
    return [str(folder / n) for n in out]


def params(d):
    try:
        days = int(d.get("days"))
    except (TypeError, ValueError):
        raise Bad("Validity must be a number of days")
    if not 1 <= days <= 36500:
        raise Bad("Validity must be 1-36500 days")
    if d.get("fmt") not in FORMATS:
        raise Bad("Unknown format")
    return days, d["fmt"], safe_dir(d.get("folder")), d.get("password") or ""


def cert_dir(cid):
    p = CONFIG / "certs" / str(cid)
    p.mkdir(parents=True, exist_ok=True)
    return p


# ---------- routes ----------
@app.before_request
def guard():
    # CSRF / DNS-rebinding guard: /api/run executes commands, so only our own window may call the API
    origin = request.headers.get("Origin")
    if request.method not in ("GET", "HEAD") and origin and urlparse(origin).netloc != request.host:
        return jsonify(error="bad origin"), 403
    if request.host.split(":")[0] not in ("127.0.0.1", "localhost"):
        return jsonify(error="bad host"), 403


@app.get("/")
def index():
    return send_from_directory(RES / "static", "index.html")


@app.get("/api/me")
def me():
    return jsonify(formats=FORMATS, folder=str(Path.home()))


@app.post("/api/run")
def run():
    d = request.get_json(force=True)
    script = d.get("script", "")
    if not script.strip():
        raise Bad("Nothing to run")
    try:
        timeout = min(max(int(d.get("timeout") or 60), 1), 600)
    except ValueError:
        raise Bad("Timeout must be seconds")
    log("command", script[:1000])
    try:  # login shell so PATH matches Terminal.app (a Finder-launched app only has a minimal PATH)
        p = subprocess.run(["/bin/zsh", "-l", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           stdin=subprocess.DEVNULL, timeout=timeout, cwd=Path.home())
        out, code = p.stdout.decode("utf-8", "replace"), p.returncode
    except subprocess.TimeoutExpired as e:
        out, code = (e.stdout or b"").decode("utf-8", "replace") + f"\n[timed out after {timeout}s]", None
    log("command finished", f"exit {code}")
    return jsonify(output=out[-200000:], exit=code)


@app.get("/api/ls")
def ls():
    p = safe_dir(request.args.get("path"))
    dirs = sorted(x.name for x in p.iterdir() if x.is_dir() and not x.name.startswith("."))
    return jsonify(path=str(p), parent=str(p.parent), dirs=dirs)


@app.get("/api/certs")
def certs():
    return jsonify([dict(r, files=json.loads(r["files"])) for r in q("SELECT * FROM certs ORDER BY id DESC")])


@app.post("/api/certs")
def create():
    d = request.get_json(force=True)
    addrs = parse_addrs(d.get("addresses"))
    name = (d.get("name") or "").strip() or addrs[0]
    if not re.fullmatch(r"[A-Za-z0-9._* -]{1,64}", name):
        raise Bad("Name: up to 64 letters, digits, space, . _ -")
    days, fmt, folder, pw = params(d)
    key = rsa.generate_private_key(65537, 2048)
    cert = build_cert(name, addrs, days, key)
    base = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    files = emit(fmt, cert, key, folder, base, pw, overwrite=False)
    cid = q("INSERT INTO certs(name,address,base,fmt,days,folder,files,not_after,created) VALUES(?,?,?,?,?,?,?,?,?)",
            name, ",".join(addrs), base, fmt, days, str(folder), json.dumps(files), cert.not_valid_after_utc.isoformat(timespec="seconds"),
            now().isoformat(timespec="seconds"))
    (cert_dir(cid) / "key.pem").write_bytes(key.private_bytes(PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    log("created", f"{name} [{', '.join(addrs)}] {fmt} {days}d -> {', '.join(files)}")
    return jsonify(id=cid, files=files)


@app.post("/api/certs/<int:cid>/renew")
def renew(cid):
    row = q("SELECT * FROM certs WHERE id=?", cid)
    if not row:
        raise Bad("Not a certificate made by this app")
    row = row[0]
    d = request.get_json(force=True)
    days, fmt, folder, pw = params(d)
    key = serialization.load_pem_private_key((cert_dir(cid) / "key.pem").read_bytes(), None)  # same key, new validity
    addrs = parse_addrs(d.get("addresses") or row["address"])
    cert = build_cert(row["name"] or row["address"].split(",")[0], addrs, days, key)
    files = emit(fmt, cert, key, folder, row["base"], pw, overwrite=True)
    q("UPDATE certs SET address=?,fmt=?,days=?,folder=?,files=?,not_after=?,renewed=renewed+1 WHERE id=?", ",".join(addrs), fmt, days, str(folder),
      json.dumps(files), cert.not_valid_after_utc.isoformat(timespec="seconds"), cid)
    log("renewed", f"{row['name'] or row['address']} [{', '.join(addrs)}] {fmt} {days}d -> {', '.join(files)}")
    return jsonify(files=files)


@app.get("/api/history")
def history():
    return jsonify([dict(r) for r in q("SELECT * FROM log ORDER BY id DESC LIMIT 500")])


def main():
    import webview  # native window (WKWebView); the Flask app serves it on a free local port
    from waitress import create_server
    srv = create_server(app, host="127.0.0.1", port=0)
    threading.Thread(target=srv.run, daemon=True).start()
    webview.create_window("CertGen", f"http://127.0.0.1:{srv.effective_port}", width=1000, height=780, min_size=(480, 520))
    webview.start()


if __name__ == "__main__":
    main()
