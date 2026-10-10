"""Application context: the single place subsystems are wired together."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

from nxtsec.config.settings import Settings, load_settings
from nxtsec.database.store import Database, open_database
from nxtsec.events.bus import EventBus
from nxtsec.evidence.store import EvidenceStore
from nxtsec.findings.service import FindingService
from nxtsec.integrations.tools import ToolRegistry
from nxtsec.jobs.engine import AssessmentEngine
from nxtsec.logging.setup import configure_logging
from nxtsec.modules.builtin import register_builtins
from nxtsec.platform.detect import PlatformInfo, detect_platform
from nxtsec.plugins.policy import Policy
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
            console_level=str(settings.get("logging.console_level", "WARNING")),
            json_console=bool(settings.get("logging.json", False)),
            log_dir=settings.log_dir if log_to_file and settings.get("logging.file") else None,
        )
        return cls(settings)

    @cached_property
    def db(self) -> Database:
        return open_database(self.settings.database_url)

    def load_scope(self) -> Scope:
        """Read the scope file fresh (the engine calls this at plan and run time)."""
        path = self.settings.scope_file
        return Scope.load(path) if path.is_file() else Scope.empty()

    @cached_property
    def scope(self) -> Scope:
        return self.load_scope()

    @cached_property
    def plugins(self) -> PluginRegistry:
        reg = PluginRegistry()
        register_builtins(reg)
        reg.discover_entry_points()
        return reg

    @cached_property
    def policy(self) -> Policy:
        return Policy.from_settings(self.settings)

    @cached_property
    def evidence(self) -> EvidenceStore:
        return EvidenceStore(self.settings.evidence_dir, self.db, self.settings.operator)

    @cached_property
    def engine(self) -> AssessmentEngine:
        return AssessmentEngine(
            db=self.db,
            registry=self.plugins,
            scope_loader=self.load_scope,
            policy=self.policy,
            bus=self.bus,
            evidence=self.evidence,
            operator=self.settings.operator,
        )

    @cached_property
    def findings(self) -> FindingService:
        return FindingService(self.db, self.settings.operator)

    @cached_property
    def platform(self) -> PlatformInfo:
        return detect_platform()

    @cached_property
    def tools(self) -> ToolRegistry:
        return ToolRegistry(
            overrides=self.settings.get("tools") or {},
            system=self.platform.system,
        )
