# Normalized data model

Modules never return raw tool output. Every result is a set of typed
observations (`nxtsec/core/observations.py`), findings and evidence, so the
database, correlation engine, reporters and CLI all speak one language.

Each observation serializes with a `type` discriminator. Current types:

| `type` | Meaning |
|---|---|
| `notice` | Operator-facing note (neither data nor a finding) |
| `dns.record` | One DNS record (name, rtype, value, ttl) |
| `relation` | Directed edge between assets (e.g. `domain -mail_exchanger-> host`) |
| `net.port` | TCP/UDP port state |
| `ip.info` | IP address classification and PTR records |
| `http.response` | HTTP exchange metadata *(reserved; module pending)* |
| `tech` | Detected technology *(reserved; module pending)* |
| `tls.certificate` | X.509 certificate details |
| `ct.certificate` | Certificate-transparency entry *(reserved; module pending)* |
| `subdomain` | Discovered subdomain *(reserved; module pending)* |
| `rdap` | RDAP/WHOIS object *(reserved; module pending)* |
| `web.robots_txt`, `web.security_txt` | Parsed well-known files *(reserved; module pending)* |
| `file.hash`, `file.entry` | Forensic file hash / non-regular entry |

Reserved types are defined now so the storage, correlation and reporting
layers are stable before the modules that emit them land. A module emits
observations with `ModuleResult.add(*observations)`.
