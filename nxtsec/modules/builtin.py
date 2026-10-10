"""Registry of modules that ship with NXT-Security."""

from __future__ import annotations

from nxtsec.modules.dns.records import DnsRecords
from nxtsec.modules.dns.resolve import DnsResolve
from nxtsec.modules.forensics.hashes import FileHash
from nxtsec.modules.network.ip_info import IpInfoModule
from nxtsec.modules.network.tcp_connect import TcpConnect
from nxtsec.modules.web.certificate import TlsCertificate
from nxtsec.plugins.base import Plugin
from nxtsec.plugins.registry import PluginRegistry

BUILTIN_PLUGINS: tuple[type[Plugin], ...] = (
    DnsResolve,
    DnsRecords,
    TcpConnect,
    IpInfoModule,
    FileHash,
    TlsCertificate,
)


def register_builtins(registry: PluginRegistry) -> None:
    for plugin in BUILTIN_PLUGINS:
        registry.register(plugin)
