# CertGen

Create self-signed certificates in a few clicks: one certificate for one domain or many, with the validity and file format you
choose, saved where you want. CertGen runs as a **Windows** app, a **macOS** app, or a **Docker** container with a web UI.

| Platform | What you get | Compatibility |
|---|---|---|
| **Windows** | `CertGen.exe`, a portable single file in its own window | Windows 10/11, 64-bit (tested on Windows 11). Needs the Microsoft Edge WebView2 Runtime, which is built into Windows 11 and most up-to-date Windows 10 installs. |
| **macOS** | `CertGen.app` in its own window | Apple Silicon (M1 or newer), macOS 11 or later (tested on an M4 Mac mini). Intel Macs: [build from source](macos/README.md). |
| **Docker** | `karharry/certgen` image with a web UI, login and multiple admin users | Linux `amd64` and `arm64` images (`amd64` tested). Any Docker host with Compose. |

## Features

- **One certificate, many domains.** Give it a name (for example `homelab`) and list any mix of hostnames, IP addresses and
  `*.wildcards` (`service1.home`, `service2.home`, `192.168.1.10`, `*.lab.home`). They all go into the certificate's Subject
  Alternative Names.
- **You choose the validity**, from 1 day to 100 years.
- **You choose the format**: `crt`, `cer`, `pem`, `key`, `cert+key` (two files), `der`, `p12`, `pfx`, `p7b`, `p7c`, `crl` (see the table below).
- **You choose where it is saved**, with a folder picker (in Docker, folders inside the mounted `/data` volume).
- **Renew** any certificate made by CertGen: same private key, new validity, and you can change the address list and format.
- **History** of every action (what was done, when, and in Docker by which user).
- **Terminal tab**: run a command or a multi-line batch in PowerShell (Windows), zsh (macOS) or the container's bash (Docker).
- **Docker extras**: login with a generated admin password on first start, change your password, add more admin users, delete
  other users (never yourself), per-user history, bridge-network port `6479:8080`, `/config` and `/data` volumes, `unless-stopped` restart, health check.

### Formats

| Format | Contains | Typical use |
|---|---|---|
| `crt` | certificate, PEM text | nginx, Apache, most Linux tools; importing as a trusted certificate |
| `cer` | certificate, binary DER | Windows certificate import, Java and .NET tools |
| `der` | certificate, binary DER | Same as `cer`, for tools that expect `.der` |
| `key` | private key, PEM (PKCS#8) | Pair with a `crt` on servers that want separate files |
| `cert+key` | `.crt` and `.key`, two files | nginx, Apache, Caddy, Traefik, most self-hosted apps |
| `pem` | certificate and private key in one file | HAProxy and tools that want a single bundle |
| `p12` / `pfx` | certificate and private key, PKCS#12, optional password | IIS, Windows, Java keystores, macOS Keychain, mail clients |
| `p7b` | certificate bundle, PKCS#7 PEM | Windows and Java certificate stores (no private key) |
| `p7c` | certificate bundle, PKCS#7 DER | Same as `p7b`, binary form |
| `crl` | an empty certificate revocation list signed by the certificate | Tools that insist on a CRL |

Certificates use RSA 2048 with SHA-256, are marked for TLS server use, and carry the key usage needed to sign. They are
self-signed: to avoid browser warnings, add the certificate to the trusted store of each device (the platform READMEs list the commands).
Note that macOS may refuse to trust TLS certificates valid longer than 825 days.

## Install and run

### Windows

1. Download `CertGen-1.0-windows.zip` from the [Releases](../../releases) page and unzip it anywhere.
2. Run `CertGen.exe`. Windows SmartScreen may warn because the app is not code-signed: choose **More info**, then **Run anyway**.
3. The app keeps its data (certificate list, history, private keys for renewal) in a `certgen-config` folder next to the exe.
   To move the app, move that folder with it. Do not put it in a protected folder such as `Program Files`.

### macOS

1. Download `CertGen-1.0-macos-arm64.zip` from the [Releases](../../releases) page, unzip it and drag `CertGen.app` to Applications.
2. The first time, right-click the app and choose **Open**, then **Open** again (the app is not notarized). If macOS still
   blocks it, run `xattr -cr /Applications/CertGen.app` once in Terminal.
3. The app keeps its data in `~/Library/Application Support/CertGen`. Back it up if you want to keep renewing certificates.

### Docker

```sh
mkdir certgen && cd certgen
curl -O https://raw.githubusercontent.com/karharry/CertGen/main/docker/docker-compose.yml
mkdir -p config data              # create them yourself so they belong to you, not root
docker compose pull && docker compose up -d
docker compose logs | grep "FIRST RUN"      # the generated admin password
```

Open `http://<host>:6479`, log in as `admin` with that password, and change it under **Settings**. Certificates are saved to
`./data`, the database and keys to `./config`. The container runs as `PUID:PGID` (default `1000:1000`); see the
[Docker README](docker/README.md) for users, reverse proxies, recovering a lost password and the full command reference.
To build the image yourself instead: `docker compose up -d --build` from the `docker` folder.

## Using it

1. **New**: enter a name (optional) and the addresses, set the validity, pick a format and a folder, and press **Create certificate**.
2. **Certificates** lists what CertGen made. **Renew** reissues one with a new validity (and optionally new addresses or format).
3. **History** shows everything that was done. **Terminal** runs commands, for example to inspect or trust the certificate.

## Build from source

| Platform | Command | Needs |
|---|---|---|
| Windows | `build-windows.bat` in [`windows/`](windows/) | Python 3.9+, builds `dist\CertGen.exe` |
| macOS | `./build-mac.sh` in [`macos/`](macos/) | Python 3.9+, Xcode command line tools, builds `dist/CertGen.app` |
| Docker | `docker compose up -d --build` in [`docker/`](docker/) | Docker with Compose |

Each folder has its own `test_certgen.py` and README (with PowerShell, Terminal or shell commands to inspect, convert and trust certificates).

## Security notes

- Private keys of the certificates you create are kept in the data folder (`certgen-config`, `Application Support/CertGen`, or the Docker `/config` volume) so they can be renewed. Protect that folder.
- The Terminal tab runs real commands as the app's user. In Docker, only logged-in admins can use it; the container serves plain HTTP and login only slows down guessing, so keep it on a trusted network or behind a reverse proxy that terminates TLS.
- Self-signed certificates prove nothing to third parties; use them for your own lab, LAN and development.

## Repository layout

```
windows/   Windows app source and build script
macos/     macOS app source and build script
docker/    Docker image, compose file and web UI with login
.github/   Workflow that builds and pushes the Docker image to Docker Hub
```

## License

MIT, see [LICENSE](LICENSE).
