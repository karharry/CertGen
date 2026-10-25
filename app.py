"""CertGen (Docker): self-signed certificate generator with a web UI, login and multi-user admin."""
import datetime as dt, ipaddress, json, logging, os, re, secrets, shutil, signal, sqlite3, subprocess, sys, time
from contextlib import closing
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from flask import Flask, jsonify, request, send_from_directory, session
from waitress import serve
from werkzeug.security import check_password_hash, generate_password_hash

RES = Path(__file__).parent
CONFIG = Path(os.environ.get("CERTGEN_CONFIG", "/config"))  # db, log, session secret, private keys kept for renewal
DATA_ROOT = Path(os.environ.get("CERTGEN_DATA", "/data")).resolve()  # certificate files are written here
CONFIG.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s",
                    handlers=[logging.StreamHandler(), logging.FileHandler(CONFIG / "certgen.log")])
FORMATS = ["crt", "cer", "pem", "key", "cert+key", "der", "p12", "pfx", "p7b", "p7c", "crl"]
PEM, DER = serialization.Encoding.PEM, serialization.Encoding.DER

app = Flask(__name__, static_folder=None)
secret = CONFIG / "secret"
if not secret.exists():
    secret.write_text(secrets.token_hex(32))
    os.chmod(secret, 0o600)
app.secret_key = secret.read_text()
app.config.update(SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_HTTPONLY=True)


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


q("""CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT UNIQUE, pw TEXT, created TEXT)""")
q("""CREATE TABLE IF NOT EXISTS certs(id INTEGER PRIMARY KEY, name TEXT, address TEXT, base TEXT, fmt TEXT, days INT,
   folder TEXT, files TEXT, not_after TEXT, created TEXT, created_by TEXT, renewed INT DEFAULT 0)""")
q("""CREATE TABLE IF NOT EXISTS log(id INTEGER PRIMARY KEY, ts TEXT, user TEXT, action TEXT, detail TEXT)""")


def log(action, detail=""):
    user = getattr(request, "user", "system")
    q("INSERT INTO log(ts,user,action,detail) VALUES(?,?,?,?)", now().isoformat(timespec="seconds"), user, action, detail)
    logging.info("%s %s %s", user, action, detail)


if not q("SELECT 1 FROM users"):  # first run: default admin with a generated password, shown once in the container log
    pw = secrets.token_urlsafe(12)
    q("INSERT INTO users(name,pw,created) VALUES('admin',?,?)", generate_password_hash(pw), now().isoformat(timespec="seconds"))
    logging.info("=" * 56 + "\nFIRST RUN: log in as  admin  /  %s   (change it in Settings)\n" + "=" * 56, pw)


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
    d = Path(p or DATA_ROOT).expanduser().resolve()
    if d != DATA_ROOT and DATA_ROOT not in d.parents:
        raise Bad(f"Folder must be inside {DATA_ROOT}")
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
        if n.endswith((".key", ".pem", ".p12", ".pfx")):
            os.chmod(folder / n, 0o600)
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


# ---------- auth ----------
@app.before_request
def guard():
    # CSRF guard: a state-changing request must come from our own page (SameSite=Strict cookie is the second layer)
    origin = request.headers.get("Origin")
    if request.method not in ("GET", "HEAD") and origin and urlparse(origin).netloc != request.host:
        return jsonify(error="bad origin"), 403
    request.user = "anonymous"
    if request.path in ("/", "/api/login"):
        return
    row = q("SELECT name FROM users WHERE id=?", session.get("uid", 0))
    if not row:  # also kicks out a user who was deleted while logged in
        session.clear()
        return jsonify(error="login required"), 401
    request.user = row[0]["name"]


@app.get("/")
def index():
    return send_from_directory(RES / "static", "index.html")


@app.post("/api/login")
def login():
    d = request.get_json(force=True)
    row = q("SELECT * FROM users WHERE name=?", d.get("username", ""))
    if not (row and check_password_hash(row[0]["pw"], d.get("password", ""))):
        time.sleep(0.7)  # shortcut: slows guessing only, no lockout; add rate limiting if exposed beyond a trusted LAN
        request.user = str(d.get("username", ""))[:64]
        log("login failed")
        return jsonify(error="Wrong username or password"), 401
    session["uid"] = row[0]["id"]
    request.user = row[0]["name"]
    log("login")
    return jsonify(ok=True)


@app.post("/api/logout")
def logout():
    log("logout")
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    return jsonify(user=request.user, formats=FORMATS, folder=str(DATA_ROOT))


@app.post("/api/password")
def password():
    d = request.get_json(force=True)
    row = q("SELECT * FROM users WHERE name=?", request.user)[0]
    if not check_password_hash(row["pw"], d.get("current", "")):
        raise Bad("Current password is wrong")
    if len(d.get("new", "")) < 8:
        raise Bad("New password must be at least 8 characters")
    q("UPDATE users SET pw=? WHERE id=?", generate_password_hash(d["new"]), row["id"])
    log("password changed")
    return jsonify(ok=True)


@app.get("/api/users")
def users():
    return jsonify([dict(r) for r in q("SELECT id,name,created FROM users ORDER BY name")])


@app.post("/api/users")
def add_user():
    d = request.get_json(force=True)
    name = d.get("name", "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", name):
        raise Bad("Username: 1-32 letters, digits, . _ -")
    if len(d.get("password", "")) < 8:
        raise Bad("Password must be at least 8 characters")
    if q("SELECT 1 FROM users WHERE name=?", name):
        raise Bad("User exists")
    q("INSERT INTO users(name,pw,created) VALUES(?,?,?)", name, generate_password_hash(d["password"]), now().isoformat(timespec="seconds"))
    log("user created", name)
    return jsonify(ok=True)


@app.delete("/api/users/<int:uid>")
def del_user(uid):
    row = q("SELECT name FROM users WHERE id=?", uid)
    if not row:
        raise Bad("No such user")
    if uid == session["uid"]:
        raise Bad("You cannot delete the user you are logged in as")
    q("DELETE FROM users WHERE id=?", uid)
    log("user deleted", row[0]["name"])
    return jsonify(ok=True)


# ---------- command console ----------
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
    try:
        p = subprocess.run([shutil.which("bash") or "/bin/sh", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           stdin=subprocess.DEVNULL, timeout=timeout, cwd=DATA_ROOT)
        out, code = p.stdout.decode("utf-8", "replace"), p.returncode
    except subprocess.TimeoutExpired as e:
        out, code = (e.stdout or b"").decode("utf-8", "replace") + f"\n[timed out after {timeout}s]", None
    log("command finished", f"exit {code}")
    return jsonify(output=out[-200000:], exit=code)


# ---------- certs ----------
@app.get("/api/ls")
def ls():
    p = safe_dir(request.args.get("path"))
    dirs = sorted(x.name for x in p.iterdir() if x.is_dir() and not x.name.startswith("."))
    return jsonify(path=str(p), parent=str(p if p == DATA_ROOT else p.parent), dirs=dirs)


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
    cid = q("INSERT INTO certs(name,address,base,fmt,days,folder,files,not_after,created,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)",
            name, ",".join(addrs), base, fmt, days, str(folder), json.dumps(files),
            cert.not_valid_after_utc.isoformat(timespec="seconds"), now().isoformat(timespec="seconds"), request.user)
    kp = cert_dir(cid) / "key.pem"
    kp.write_bytes(key.private_bytes(PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chmod(kp, 0o600)
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
    cert = build_cert(row["name"] or addrs[0], addrs, days, key)
    files = emit(fmt, cert, key, folder, row["base"], pw, overwrite=True)
    q("UPDATE certs SET address=?,fmt=?,days=?,folder=?,files=?,not_after=?,renewed=renewed+1 WHERE id=?", ",".join(addrs), fmt, days,
      str(folder), json.dumps(files), cert.not_valid_after_utc.isoformat(timespec="seconds"), cid)
    log("renewed", f"{row['name'] or row['address']} [{', '.join(addrs)}] {fmt} {days}d -> {', '.join(files)}")
    return jsonify(files=files)


@app.get("/api/history")
def history():
    return jsonify([dict(r) for r in q("SELECT * FROM log ORDER BY id DESC LIMIT 500")])


def main():
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))  # PID 1 ignores SIGTERM by default: stop in <1s instead of a 10s kill
    port = int(os.environ.get("CERTGEN_PORT", 8080))
    logging.info("CertGen listening on :%s, config %s, data %s", port, CONFIG, DATA_ROOT)
    serve(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
