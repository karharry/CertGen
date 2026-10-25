# CertGen (Docker)

Self-signed certificate generator with a web UI, login and multiple admin users (Python + Flask + waitress).

## Run it

```sh
mkdir -p config data            # create them yourself so they belong to you, not root
docker compose up -d --build    # UI on http://<host>:6479
docker compose logs | grep "FIRST RUN"
```

- **Port:** `6479:8080` (host:container) on the default bridge network, no host networking. Change the left number in `docker-compose.yml`.
- **`/config`** (bound to `./config`): database, log (`certgen.log`), session secret and the private keys kept for renewal. Back it up.
- **`/data`** (bound to `./data`): where certificate files are saved. The folder picker and the Terminal tab are confined to it.
- **Restart policy:** `unless-stopped`. A healthcheck is built in (`docker ps` shows `healthy`).
- **User:** the container runs as `PUID:PGID` (default `1000:1000`) so files in `./data` belong to you. For another user run
  `PUID=$(id -u) PGID=$(id -g) docker compose up -d`, and make sure `./config` and `./data` are owned by that user.
- Plain `docker run` works too: `docker run -d --name certgen --user 1000:1000 -p 6479:8080 -v $PWD/config:/config -v $PWD/data:/data --restart unless-stopped certgen`.

## Login and users

- The first time the container starts with an empty `/config` it creates the user `admin` with a **generated password**, printed once in the
  container log: `docker compose logs | grep "FIRST RUN"`. Log in, then change it in **Settings**.
- Every user is an admin. **Settings** lets you change your own password (min 8 characters), add admin users and delete users.
  An admin can delete any other user but never the account they are logged in with. A deleted user is logged out immediately.
- History records which user did what and when: logins (also failed ones), certificates created and renewed, commands run,
  password changes, users added and deleted.
- Lost every password? Delete the users and restart; a new `admin` and a new generated password appear in the log:

```sh
docker compose exec certgen python -c "import sqlite3; c = sqlite3.connect('/config/certgen.db'); c.execute('DELETE FROM users'); c.commit()"
docker compose restart
docker compose logs | grep "FIRST RUN"
```

## Features

One certificate for one or many addresses (hostnames, IPs, `*.wildcards`), validity in days, 11 output formats
(crt, cer, pem, key, cert+key, der, p12, pfx, p7b, p7c, crl), folder picker, renewal of certificates made here (keeps the
key, lets you change the address list), History tab, and a Terminal tab that runs a script (multi-line = batch) in the
container's bash.

Notes: `pem` = cert + private key in one file. `cer`/`der`/`p7c` are binary DER; `crt`/`p7b`/`crl` are PEM text.
`crl` is an empty CRL signed by the cert. p12/pfx password is optional and not stored. Key, pem, p12 and pfx files are written `0600`.
The Terminal tab starts in `/data`, runs as the container user, has `openssl` installed and cannot ask for input.
Login only slows down guessing (no lockout): keep it on a trusted network or behind a reverse proxy, and let the proxy pass the
original `Host` header (requests whose `Origin` differs from `Host` are rejected). It serves plain HTTP; terminate TLS in the proxy.
Run the tests inside the image: `docker run --rm -v "$PWD/test_certgen.py:/srv/test_certgen.py" certgen python test_certgen.py`.

## Create certificates with the shell only (no CertGen)

Run these in the Terminal tab, or with `docker compose exec certgen bash`, or on any Linux/macOS host with `openssl`.
List every domain/IP in `subjectAltName`; the common name is just a label.

```sh
mkdir -p /data/certs && cd /data/certs

# A. Single domain, valid 365 days
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 -keyout nas.key -out nas.crt -subj "/CN=nas.home.lan" -addext "subjectAltName=DNS:nas.home.lan"

# B. Multiple domains (and an IP) in one certificate
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 -keyout homelab.key -out homelab.crt -subj "/CN=homelab" -addext "subjectAltName=DNS:service1.home,DNS:service2.home,DNS:service3.home,IP:192.168.1.10"

# C. Wildcard. "*.home.lan" does NOT cover the bare "home.lan", so list both if you need both
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 -keyout wild.key -out wild.crt -subj "/CN=*.home.lan" -addext "subjectAltName=DNS:*.home.lan,DNS:home.lan"

# Optional: bundle certificate + private key into a .pfx/.p12
openssl pkcs12 -export -inkey homelab.key -in homelab.crt -out homelab.pfx -passout pass:your-password
```

Differences from CertGen: `openssl` writes a separate `.crt` and `.key`, has no renewal, history, users or folder picker, and other
formats (`.p7b`, `.crl`, `.der`...) need extra commands (see 7 and 8 below).

## Useful commands

Commands 1-8 and 10 work in the Terminal tab (paths use `/data/certs`); command 9 and the host commands below run on the Docker host.

```sh
# 1. Show a certificate's subject, validity and SHA-256 fingerprint
openssl x509 -in /data/certs/homelab.crt -noout -subject -dates -fingerprint -sha256

# 2. Show every domain/IP the certificate covers (Subject Alternative Names)
openssl x509 -in /data/certs/homelab.crt -noout -ext subjectAltName

# 3. Check that a certificate and a private key belong together (prints "match")
diff <(openssl x509 -in /data/certs/homelab.crt -noout -pubkey) <(openssl pkey -in /data/certs/homelab.key -pubout) && echo match

# 4. Show when each certificate in a folder expires
for f in /data/certs/*.crt; do echo "$f: $(openssl x509 -in "$f" -noout -enddate)"; done

# 5. Flag certificates in a folder that expire within 30 days
for f in /data/certs/*.crt; do openssl x509 -in "$f" -noout -checkend 2592000 >/dev/null && echo "$f ok" || echo "$f EXPIRES within 30 days"; done

# 6. Make a .pfx from a .crt and .key
openssl pkcs12 -export -inkey /data/certs/homelab.key -in /data/certs/homelab.crt -out /data/certs/homelab.pfx -passout pass:your-password

# 7. Convert a PEM certificate to DER (.der/.cer)
openssl x509 -in /data/certs/homelab.crt -outform der -out /data/certs/homelab.der

# 8. Make a .p7b (PKCS#7 bundle) from a certificate
openssl crl2pkcs7 -nocrl -certfile /data/certs/homelab.crt -out /data/certs/homelab.p7b

# 9. (host) Trust the certificate on a Debian/Ubuntu host
sudo cp ./data/certs/homelab.crt /usr/local/share/ca-certificates/homelab.crt && sudo update-ca-certificates

# 10. Get a file's SHA-256 hash, e.g. to confirm a copied certificate is identical
sha256sum /data/certs/homelab.crt
```

Host-side Docker helpers: `docker compose logs -f` (live log), `docker compose exec certgen bash` (shell in the container),
`docker compose stop` / `docker compose down` (stop it; `./config` and `./data` stay), `docker compose up -d --build` (rebuild after changes).

## License

MIT, see [LICENSE](LICENSE).
