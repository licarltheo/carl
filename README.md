# Carl

Modular post-exploitation framework. One binary, every surface.

## Modules
- **lsass** — Windows credential dump (NTLM/Kerberos)
- **keepass** — KeePass kdbx + master password extraction
- **wifi** — Saved WiFi profiles + cleartext keys
- **browser** — Chrome/Edge/Firefox credential & cookie stores
- **vpn** — AnyConnect / OpenVPN / WireGuard / FortiClient
- **smb** — Lateral move over SMB
- **ssh** — SSH key harvest + lateral ssh
- **rdp** — RDP credential + session hijack
- **ad** — Active Directory recon (users, SPNs, ACLs, trusts)
- **cloud** — AWS/GCP/Azure key + IMDS exfil

## Build
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
```

## License
MIT
