# Built-in modules

`nxtsec plugins list` shows every module; `nxtsec plugins show <name>` shows its manifest and docs.
These three seed modules exist to exercise the assessment engine end to end. The full recon,
network, web and forensics engines arrive in Phases 8–13.

| Module | Targets | Risk | Permissions | What it does |
|---|---|---|---|---|
| `dns.resolve` | domain, hostname, IP, URL | low | NETWORK_ACCESS | A/AAAA via the OS resolver; PTR for addresses. Flags names that resolve outside scope. |
| `network.tcp_connect` | IP, domain, hostname, URL | medium | NETWORK_ACCESS | TCP connect to a short port list: `open`, `closed`, `filtered`, `unreachable`. |
| `forensics.hash` | file | passive | READ_ONLY, LOCAL_FILES | MD5/SHA-1/SHA-256/SHA-512 of a file or tree, read-only. |
| `dns.records` | domain, hostname, URL | low | NETWORK_ACCESS | Enumerate A/AAAA/CNAME/MX/NS/TXT/SOA/CAA; derive mail-exchanger/name-server/alias edges; flag SPF/DMARC gaps. |
| `ip.info` | IP, domain, hostname, URL | low | NETWORK_ACCESS | Classify each address (global/private/loopback/…) and resolve PTR records. |
| `tls.certificate` | domain, hostname, IP, URL | low | NETWORK_ACCESS | Inspect the presented X.509 certificate: expiry, trust, hostname match, key strength. |

### `network.tcp_connect`
Options: `ports` (default `22,80,443`, or the URL's port; ranges like `8000-8010`; max 1024),
`timeout` (seconds per connect, 0.1–30, default 3; Windows needs ~1–2 s to report a refused port). Hostnames are resolved and checked by the
DNS pivot guard before any connection. At most 8 resolved addresses are probed. This is a
connectivity check, not a port scanner; broad discovery belongs to the Nmap integration.

### `dns.resolve`
Options: `timeout` (0.5–60, default 5). A name that doesn't resolve is reported as a result
(`errors`), not a module failure.

### `forensics.hash`
Options: `max_files` (default 10000). Never follows symlinks (recorded as `file.symlink`), never
opens FIFOs or devices (recorded as `file.skipped`), and does not modify file timestamps.
MD5/SHA-1 are computed with `usedforsecurity=False`, for identification only.


### `dns.records`
Options: `timeout` (0.5–60, default 5). Uses the system resolver unless `dns.nameservers`
is set in config. Emits `dns.record` and `relation` observations and raises **informational/low**
findings for a domain's own mail-security posture: no SPF record, a permissive SPF `all`
qualifier (`+all`/`?all`), or no DMARC policy at `_dmarc.<domain>`. These describe the owner's
own configuration; the module sends only ordinary DNS queries.

### `ip.info`
Options: `timeout` (0.5–60, default 5). Classification is offline (`ipaddress`). Hostnames are
resolved first (through the scope resolution guard). ASN and geolocation enrichment is deferred
to the OSINT engine (Phase 12).

### `tls.certificate`
Options: `port` (default 443, or the URL's port), `timeout` (1–60, default 10). Connects to the
scope-checked address, completes a TLS handshake with SNI, and reads the leaf certificate. It
verifies the chain against the system trust store; on failure it re-reads the certificate
unverified and records the reason, so an untrusted endpoint is still reported rather than hidden.
Findings (about the operator's own endpoint): expired certificate (high), expiring within 30 days
(medium), untrusted/self-signed chain (medium), hostname mismatch (medium), and weak key —
RSA < 2048 or EC < 256 bits (medium). It performs certificate inspection only and sends no
application data.

> **Deferred to a later Phase 8 increment:** HTTP metadata (headers, `robots.txt`,
> `security.txt`, technology fingerprinting), certificate-transparency subdomain discovery, and
> RDAP/WHOIS. These need the target HTTP client and outbound access to public APIs; they are
> tracked as a known gap.
