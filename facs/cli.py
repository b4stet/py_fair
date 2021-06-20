import click
from facs.command.resources import ResourcesCommand
from facs.command.systems import SystemsCommand
from facs.command.tools import ToolsCommand
from facs.command.logs import LogsCommand
from facs.command.acquisition import AcquisitionCommand
from facs.command.carving import CarvingCommand
from facs.command.preprocessing import PreprocessingCommand
from facs.command.processing import ProcessingCommand

from facs.bo.evtx import EvtxBo
from facs.bo.registry import RegistryBo
from facs.bo.report_timeline import ReportTimelineBO

evtx_bo = EvtxBo()
registry_bo = RegistryBo()
report_timeline_bo = ReportTimelineBO()

cli = click.Group('cli', context_settings=dict(terminal_width=120))
cli.add_command(AcquisitionCommand().get_commands())
cli.add_command(LogsCommand().get_commands())
cli.add_command(ResourcesCommand().get_commands())
cli.add_command(CarvingCommand().get_commands())
cli.add_command(PreprocessingCommand().get_commands())
cli.add_command(SystemsCommand().get_commands())
cli.add_command(ToolsCommand().get_commands())
cli.add_command(ProcessingCommand(evtx_bo, registry_bo, report_timeline_bo).get_commands())

if __name__ == '__main__':
    cli()
