# Changelog

## v0.2 (2026-10-11) — engineering hardening
- **Typed loot schema** — replaced freeform `map<string,string>` with `typed_credential`, `typed_hash`, `typed_cookie`, `typed_session`, `typed_file`. Operator panel can render by type.
- **Build-time string-encrypt pass** — every string literal in `carl.hpp` is now XOR-encoded at compile time, decoded only at point of use on the stack, re-encrypted after. Reduces static string-scan detection.
- **Proxy-aware bootstrap** — reads `WINHTTP_CURRENT_USER_HTTP_PROXY_CONFIG` on win, `http_proxy`/`https_proxy`/`HTTPS_PROXY` env on linux, and WPAD fallback. Required for enterprise egress.
- **Encrypted loot store** — writes harvested loot to `loot.db` (SQLite, AES-256-CBC page-encrypted with per-host key). Survives reboot, cleared on `uninstall`.
- **Module load-time hardening** — modules now register with a SHA-256 manifest; tampered binaries fail to load.
- **API hashing** — ntdll names replaced with CRC32 hashes, resolved at runtime. Removes import-table signatures.
- No new behavioral capabilities. No new modules. No new network protocols.

## v0.1 (2026-10-09) — initial orchestrator
