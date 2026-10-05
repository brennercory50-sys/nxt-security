# Tool registry

NXT-Security integrates external tools but never installs them. `nxtsec tools` detects each one:

| Status | Meaning |
|---|---|
| INSTALLED | Found and its version was recognized (or it ran successfully) |
| MISSING | Not on PATH, or the configured `tools.<name>.path` is not executable |
| OUTDATED | Found, but below the minimum supported version |
| BROKEN | Found, but the version command failed or could not run |
| UNSUPPORTED | Not available on this platform (e.g. Docker on Termux) |

Built-in tools: python, git (required); nmap, tshark, dig, whois, curl, openssl, yara, docker (optional).
Each has a description, category, binary, version command, install method per platform,
documentation link, capabilities and risk level (`nxtsec tools info <name>`).

```sh
nxtsec tools                # same as `tools check`
nxtsec tools list [--json]  # metadata only
nxtsec tools check nmap git # exit 1 if a required tool is not INSTALLED
nxtsec tools info nmap
```

Point at a tool outside PATH in `config/local.yaml`:
```yaml
tools:
  nmap: { path: "C:/Program Files (x86)/Nmap/nmap.exe" }
```
Version detection runs through the safe command runner (argv only, 15s timeout).
