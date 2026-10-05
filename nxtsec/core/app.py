"""Application context: the single place subsystems are wired together."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

from nxtsec.config.settings import Settings, load_settings
from nxtsec.database.store import Database, open_database
from nxtsec.events.bus import EventBus
from nxtsec.logging.setup import configure_logging
from nxtsec.plugins.registry import PluginRegistry
from nxtsec.safety.scope import Scope


@dataclass
class App:
    settings: Settings
    bus: EventBus = field(default_factory=EventBus)

    @classmethod
    def create(cls, config_path: Path | None = None, *, log_to_file: bool = True) -> App:
        settings = load_settings(config_path)
        configure_logging(
            str(settings.get("logging.level", "INFO")),
            console=bool(settings.get("logging.console", True)),
            json_console=bool(settings.get("logging.json", False)),
            log_dir=settings.log_dir if log_to_file and settings.get("logging.file") else None,
        )
        return cls(settings)

    @cached_property
    def db(self) -> Database:
        return open_database(self.settings.database_url)

    @cached_property
    def scope(self) -> Scope:
        path = self.settings.scope_file
        return Scope.load(path) if path.is_file() else Scope.empty()

    @cached_property
    def plugins(self) -> PluginRegistry:
        reg = PluginRegistry()
        reg.discover_entry_points()
        return reg
