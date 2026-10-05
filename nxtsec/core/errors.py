"""Exception hierarchy. Every framework error derives from NxtSecError."""

from __future__ import annotations


class NxtSecError(Exception):
    """Base class for all NXT-Security errors."""


class ConfigError(NxtSecError):
    """Configuration is missing, malformed or invalid."""


class TargetError(NxtSecError):
    """A target string could not be parsed or validated."""


class ScopeViolation(NxtSecError):
    """An operation was attempted against a target outside the authorized scope."""


class CommandError(NxtSecError):
    """An external command could not be executed safely."""


class CommandTimeout(CommandError):
    """An external command exceeded its timeout and was killed."""


class PathViolation(NxtSecError):
    """A path escaped its permitted base directory."""


class PluginError(NxtSecError):
    """A plugin is malformed, failed to load, or requested disallowed permissions."""


class DatabaseError(NxtSecError):
    """The persistence layer failed."""


class JobError(NxtSecError):
    """An assessment job is in the wrong state or could not be scheduled."""


class Cancelled(NxtSecError):
    """Raised inside a module when the operator cancelled the assessment."""
