# Plugins

```python
from nxtsec.core.models import TargetType
from nxtsec.plugins import ModuleResult, Permission, Plugin, PluginManifest, RiskLevel

class HttpTitle(Plugin):
    manifest = PluginManifest(
        name="web.title", version="0.1.0", description="Fetch page title",
        category="web", author="me",
        permissions=frozenset({Permission.NETWORK_ACCESS}),
        risk_level=RiskLevel.LOW,
        target_types=frozenset({TargetType.URL}),
    )

    def run(self, target, ctx):
        ctx.require(Permission.NETWORK_ACCESS)
        ...
        return ModuleResult(observations=[{"title": "..."}])
```

Register an installed plugin via `pyproject.toml`:
```toml
[project.entry-points."nxtsec.plugins"]
web_title = "my_pkg.module:HttpTitle"
```

Manifests are validated at load time: semver version, lowercase name, and `HIGH` risk requires
`LAB_ONLY_VALIDATION`. A plugin that fails to load is reported by `nxtsec plugins list` and does
not affect the others. A `nxtsec plugin create` scaffold arrives in Phase 21.
