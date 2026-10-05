"""Plugin discovery and registration.

Sources:
* built-in modules registered in code;
* installed packages exposing the ``nxtsec.plugins`` entry-point group.

Loading a plugin never executes it; it only validates the manifest.
"""

from __future__ import annotations

import logging
from importlib.metadata import entry_points

from nxtsec.core.errors import PluginError
from nxtsec.plugins.base import Plugin, PluginManifest

log = logging.getLogger("nxtsec.plugins")
ENTRY_POINT_GROUP = "nxtsec.plugins"


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, type[Plugin]] = {}
        self.load_errors: dict[str, str] = {}

    def register(self, cls: type[Plugin]) -> type[Plugin]:
        if not isinstance(cls, type) or not issubclass(cls, Plugin):
            raise PluginError(f"{cls!r} is not a Plugin subclass")
        manifest = getattr(cls, "manifest", None)
        if not isinstance(manifest, PluginManifest):
            raise PluginError(f"{cls.__name__} has no valid manifest")
        if manifest.name in self._plugins and self._plugins[manifest.name] is not cls:
            raise PluginError(f"duplicate plugin name: {manifest.name}")
        self._plugins[manifest.name] = cls
        return cls

    def discover_entry_points(self) -> None:
        for ep in entry_points(group=ENTRY_POINT_GROUP):
            try:
                self.register(ep.load())
            except Exception as exc:  # noqa: BLE001 - one bad plugin must not break the rest
                self.load_errors[ep.name] = str(exc)
                log.warning("plugin failed to load", extra={"module": ep.name})

    def get(self, name: str) -> type[Plugin]:
        try:
            return self._plugins[name]
        except KeyError:
            raise PluginError(f"unknown plugin: {name}") from None

    def manifests(self) -> list[PluginManifest]:
        return sorted((c.manifest for c in self._plugins.values()), key=lambda m: m.name)

    def __len__(self) -> int:
        return len(self._plugins)
