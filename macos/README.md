# CertGen (macOS)

Self-signed certificate generator in a native window (Python + Flask + pywebview/WKWebView).

- Build: `./build-mac.sh` -> `dist/CertGen.app` (arm64 or Intel, whichever Mac you build on; ad-hoc signed).
- Run from source: `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/python app.py`.
- Test: `.venv/bin/python test_certgen.py`.
- State (certificate list, history, private keys needed for renewal) lives in `~/Library/Application Support/CertGen`.
  Back that folder up if you want to keep the ability to renew.
- First launch of a copied/downloaded build: macOS Gatekeeper may block it because it is not notarized. Right-click the app,
  choose Open, then Open again (or `xattr -cr CertGen.app`).

Features: one certificate for one or many addresses (hostnames, IPs, `*.wildcards`), validity in days, 11 output formats
(crt, cer, pem, key, cert+key, der, p12, pfx, p7b, p7c, crl), folder picker, renewal of certificates made here, History tab,
and a Terminal tab that runs a script (multi-line = batch) in zsh.

Notes: `pem` = cert + private key in one file. `cer`/`der`/`p7c` are binary DER; `crt`/`p7b`/`crl` are PEM text.
`crl` is an empty CRL signed by the cert. p12/pfx password is optional and not stored.
Renewal reuses the stored private key with a new validity, and lets you change the address list.
The Terminal tab uses a login zsh (so your PATH matches Terminal.app), starts in your home folder and cannot ask for input.
Every action is logged in History. `.venv/bin/pip install pillow && .venv/bin/python make_icon.py` regenerates `icon.icns`.

macOS may refuse to trust TLS certificates valid for more than 825 days, so prefer 825 days or less for certificates you
want browsers and apps on this Mac to accept.

## Create certificates with Terminal only (no CertGen)

macOS ships `openssl` (LibreSSL). One command creates the key and the certificate; list every domain/IP in `subjectAltName`.
The common name (`/CN=...`) is just a label, the SAN list is what matches. Create the folder first: `mkdir -p ~/certs && cd ~/certs`.

```sh
# A. Single domain, valid 365 days
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 -keyout nas.key -out nas.crt -subj "/CN=nas.home.lan" -addext "subjectAltName=DNS:nas.home.lan"

# B. Multiple domains (and an IP) in one certificate
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 -keyout homelab.key -out homelab.crt -subj "/CN=homelab" -addext "subjectAltName=DNS:service1.home,DNS:service2.home,DNS:service3.home,IP:192.168.1.10"

# C. Wildcard. "*.home.lan" does NOT cover the bare "home.lan", so list both if you need both
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 -keyout wild.key -out wild.crt -subj "/CN=*.home.lan" -addext "subjectAltName=DNS:*.home.lan,DNS:home.lan"

# Optional: bundle certificate + private key into a .pfx/.p12
openssl pkcs12 -export -inkey homelab.key -in homelab.crt -out homelab.pfx -passout pass:your-password
```

Differences from CertGen: `openssl` writes a separate `.crt` and `.key` (and `.pfx` with the extra command), it has no
renewal, history or folder picker, and the other formats (`.p7b`, `.crl`, `.der`...) need extra `openssl` commands.

## Useful Terminal commands

Paths assume your certificates are in `~/certs`. They work in Terminal or in the app's Terminal tab (which cannot ask for
input, so `sudo` and password prompts will not work there; run those in Terminal.app).

```sh
# 1. Show a certificate's subject, validity and SHA-256 fingerprint
openssl x509 -in ~/certs/homelab.crt -noout -subject -dates -fingerprint -sha256

# 2. Show every domain/IP the certificate covers (Subject Alternative Names)
openssl x509 -in ~/certs/homelab.crt -noout -text | grep -A1 "Alternative Name"

# 3. Trust a self-signed certificate for your user (macOS asks for your password)
security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db ~/certs/homelab.crt

# 4. Trust it for the whole Mac (needs admin; run in Terminal.app)
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/certs/homelab.crt

# 5. Import a .pfx/.p12 with its private key into your login keychain
security import ~/certs/homelab.pfx -k ~/Library/Keychains/login.keychain-db -P 'your-password'

# 6. Trust every .crt in a folder at once
for f in ~/certs/*.crt; do security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db "$f"; done

# 7. Show when each certificate in a folder expires
for f in ~/certs/*.crt; do echo "$f: $(openssl x509 -in "$f" -noout -enddate)"; done

# 8. Flag certificates in a folder that expire within 30 days
for f in ~/certs/*.crt; do openssl x509 -in "$f" -noout -checkend 2592000 >/dev/null && echo "$f ok" || echo "$f EXPIRES within 30 days"; done

# 9. Find a trusted certificate's SHA-1, then remove it (also add sudo and the System keychain path for system-wide ones)
security find-certificate -a -c homelab -Z ~/Library/Keychains/login.keychain-db | grep -E "SHA-1|labl"
security delete-certificate -Z PASTE_SHA1_HERE ~/Library/Keychains/login.keychain-db

# 10. Get a file's SHA-256 hash, e.g. to confirm a copied certificate is identical
shasum -a 256 ~/certs/homelab.crt
```

## License

MIT, see [LICENSE](../LICENSE).
