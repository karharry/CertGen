# CertGen (Windows)

Self-signed certificate generator in a native window (Python + Flask + pywebview/WebView2).

- Build: `build-windows.bat` -> `dist\CertGen.exe` (portable; state in `certgen-config\` next to the exe).
- Run from source: `pip install -r requirements.txt && python app.py`.
- Test: `python test_certgen.py`.

Notes: `pem` = cert + private key in one file. `cer`/`der`/`p7c` are binary DER; `crt`/`p7b`/`crl` are PEM text.
`crl` is an empty CRL signed by the cert. p12/pfx password is optional and not stored.
Renewal reuses the stored private key (kept in `certgen-config\certs`) with a new validity.
The Terminal tab runs a script (multi-line = batch) in PowerShell. Every action is logged in History.
`python make_icon.py` regenerates `icon.ico`.

## Create certificates with PowerShell only (no CertGen)

`New-SelfSignedCertificate` is built into Windows. It creates the certificate and private key in your certificate store
(`Cert:\CurrentUser\My`); then export it to files. The first `-DnsName` becomes the certificate's common name, and every
`-DnsName` entry is added as a Subject Alternative Name. Create the folder first: `New-Item -ItemType Directory C:\certs -Force`.

```powershell
# A. Single domain, valid 365 days
$cert = New-SelfSignedCertificate -DnsName nas.home.lan -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(365) -KeyExportPolicy Exportable -KeyAlgorithm RSA -KeyLength 2048 -FriendlyName nas

# B. Multiple domains in one certificate (just list them, comma-separated)
$cert = New-SelfSignedCertificate -DnsName service1.home, service2.home, service3.home -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(365) -KeyExportPolicy Exportable -KeyAlgorithm RSA -KeyLength 2048 -FriendlyName homelab

# C. Wildcard domain. "*.home.lan" does NOT cover the bare "home.lan", so list both if you need both
$cert = New-SelfSignedCertificate -DnsName '*.home.lan', 'home.lan' -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(365) -KeyExportPolicy Exportable -KeyAlgorithm RSA -KeyLength 2048 -FriendlyName wildcard

# Then export whichever one you created ($cert holds the last one):
Export-Certificate -Cert $cert -FilePath C:\certs\homelab.cer                  # public certificate only
Export-PfxCertificate -Cert $cert -FilePath C:\certs\homelab.pfx -Password (ConvertTo-SecureString 'your-password' -AsPlainText -Force)   # certificate + private key

# Optional: remove it from the store once exported (the files stay)
Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)"
```

Differences from CertGen: PowerShell exports only `.cer` and `.pfx` (CertGen offers 11 formats, a chosen output folder,
renewal and history), and it can't write a plain `.key`. Use the trust commands below to make Windows accept the certificate.

## Useful PowerShell commands

Paths below assume your certificates are in `C:\certs`. They work in any PowerShell or in the app's Terminal tab
(which runs as your user, not elevated, and cannot ask for input, so put passwords in the command).

```powershell
# 1. Show a certificate's subject, validity and thumbprint (works for .crt, .cer, .pfx)
Get-PfxCertificate -FilePath C:\certs\homelab.crt | Format-List Subject, NotBefore, NotAfter, Thumbprint

# 2. Show every domain/IP the certificate covers (Subject Alternative Names)
(Get-PfxCertificate C:\certs\homelab.crt).Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' } | ForEach-Object { $_.Format($true) }

# 3. Trust a self-signed certificate for your user (no admin needed; Windows may show a confirmation prompt)
Import-Certificate -FilePath C:\certs\homelab.crt -CertStoreLocation Cert:\CurrentUser\Root

# 4. Trust it for the whole machine (run PowerShell as Administrator)
Import-Certificate -FilePath C:\certs\homelab.crt -CertStoreLocation Cert:\LocalMachine\Root

# 5. Install a .pfx/.p12 with its private key, e.g. for IIS (run as Administrator)
Import-PfxCertificate -FilePath C:\certs\homelab.pfx -CertStoreLocation Cert:\LocalMachine\My -Password (ConvertTo-SecureString 'your-password' -AsPlainText -Force)

# 6. Trust every .crt in a folder at once
Get-ChildItem C:\certs\*.crt | ForEach-Object { Import-Certificate -FilePath $_.FullName -CertStoreLocation Cert:\CurrentUser\Root }

# 7. See which files in a folder expire soonest
Get-ChildItem C:\certs\*.crt | ForEach-Object { $c = Get-PfxCertificate $_.FullName; [pscustomobject]@{ File = $_.Name; Expires = $c.NotAfter; DaysLeft = ($c.NotAfter - (Get-Date)).Days } } | Sort-Object DaysLeft

# 8. List trusted certificates that expire within 30 days
Get-ChildItem Cert:\CurrentUser\Root | Where-Object NotAfter -lt (Get-Date).AddDays(30) | Select-Object Subject, NotAfter, Thumbprint

# 9. Remove a trusted certificate by thumbprint (copy it from command 1 or 8)
Get-ChildItem Cert:\CurrentUser\Root | Where-Object Thumbprint -eq 'PASTE_THUMBPRINT_HERE' | Remove-Item

# 10. Get a file's SHA-256 hash, e.g. to confirm a copied certificate is identical
Get-FileHash C:\certs\homelab.crt -Algorithm SHA256
```

## License

MIT, see [LICENSE](../LICENSE).
