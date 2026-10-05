"""Platform adapters (Windows, Linux, macOS, Android/Termux)."""

from nxtsec.platform.detect import PlatformInfo, detect_platform

__all__ = ["PlatformInfo", "detect_platform"]
