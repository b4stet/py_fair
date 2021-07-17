import click

from facs.command.cheat_sheets.library import LibraryCommand
from facs.command.cheat_sheets.systems import SystemsCommand
from facs.command.cheat_sheets.tools import ToolsCommand
from facs.command.cheat_sheets.logs import LogsCommand
from facs.command.cheat_sheets.acquisition import AcquisitionCommand
from facs.command.cheat_sheets.carving import CarvingCommand
from facs.command.cheat_sheets.preprocessing import PreprocessingCommand
from facs.command.cheat_sheets.processing import ProcessingCommand

from facs.command.scripts.windows import WindowsCommand
from facs.command.scripts.nsrl import NsrlCommand

from facs.bo.evtx import EvtxBo
from facs.bo.registry import RegistryBo
from facs.bo.report_timeline import ReportTimelineBO

evtx_bo = EvtxBo()
registry_bo = RegistryBo()
report_timeline_bo = ReportTimelineBO()

cli = click.Group('cli', context_settings=dict(terminal_width=160))

cheat_sheets = click.Group('cheat_sheets')
cheat_sheets.add_command(LibraryCommand().get_commands())
cheat_sheets.add_command(ToolsCommand().get_commands())
cheat_sheets.add_command(SystemsCommand().get_commands())
cheat_sheets.add_command(LogsCommand().get_commands())
cheat_sheets.add_command(AcquisitionCommand().get_commands())
cheat_sheets.add_command(CarvingCommand().get_commands())
cheat_sheets.add_command(PreprocessingCommand().get_commands())
cheat_sheets.add_command(ProcessingCommand().get_commands())

scripts = click.Group('scripts')
scripts.add_command(NsrlCommand().get_commands())
scripts.add_command(WindowsCommand(evtx_bo, registry_bo, report_timeline_bo).get_commands())

cli.add_command(cheat_sheets)
cli.add_command(scripts)
if __name__ == '__main__':
    cli()
