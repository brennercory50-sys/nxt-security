"""``nxtsec`` command-line entry point.

Commands are registered here from ``nxtsec.cli.commands``. Engines from later
phases (recon, findings, report, ...) register their own groups when they are
implemented; nothing is exposed before it works.
"""

from __future__ import annotations

from pathlib import Path

import click

from nxtsec import __version__
from nxtsec.cli.commands.config_cmd import config
from nxtsec.cli.commands.findings_cmd import findings
from nxtsec.cli.commands.jobs_cmd import jobs
from nxtsec.cli.commands.logs_cmd import logs
from nxtsec.cli.commands.plugins_cmd import plugins
from nxtsec.cli.commands.recon_cmd import recon
from nxtsec.cli.commands.report_cmd import report
from nxtsec.cli.commands.scan_cmd import scan
from nxtsec.cli.commands.scope_cmd import scope
from nxtsec.cli.commands.system import doctor, version
from nxtsec.cli.commands.target_cmd import target
from nxtsec.cli.commands.tools_cmd import tools


@click.group(context_settings={"help_option_names": ["-h", "--help"], "max_content_width": 100})
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Path to an alternate config.yaml.",
)
@click.option("--no-log-file", is_flag=True, help="Do not write the rotating JSON log file.")
@click.version_option(__version__, "-V", "--version", prog_name="nxtsec")
@click.pass_context
def cli(ctx: click.Context, config_path: Path | None, no_log_file: bool) -> None:
    """NXT-Security: authorized security research platform.

    Only operate against systems you own or are explicitly authorized to test.
    """
    ctx.ensure_object(dict).update(config=config_path, no_log_file=no_log_file)


for _cmd in (
    version,
    doctor,
    config,
    scope,
    target,
    scan,
    recon,
    jobs,
    findings,
    report,
    tools,
    plugins,
    logs,
):
    cli.add_command(_cmd)


def main() -> None:
    cli(obj={})


if __name__ == "__main__":
    main()
