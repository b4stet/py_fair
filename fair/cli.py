import click

from fair.command.cheat_sheets.library import LibraryCommand
from fair.command.cheat_sheets.systems import SystemsCommand
from fair.command.cheat_sheets.tools import ToolsCommand
from fair.command.cheat_sheets.logs import LogsCommand
from fair.command.cheat_sheets.acquisition import AcquisitionCommand
from fair.command.cheat_sheets.carving import CarvingCommand
from fair.command.cheat_sheets.preprocessing import PreprocessingCommand
from fair.command.cheat_sheets.processing import ProcessingCommand

from fair.command.scripts.windows import WindowsCommand
from fair.command.scripts.nsrl import NsrlCommand
from fair.command.scripts.report import ReportCommand

from fair.loader.ods import OdsLoader


from fair.analyzer.registry_user import UserRegistryAnalyzer
from fair.analyzer.registry_host import HostRegistryAnalyzer
from fair.analyzer.evtx import EvtxAnalyzer
from fair.analyzer.timeline import TimelineAnalyzer

ods_loader = OdsLoader()

user_registry_analyzer = UserRegistryAnalyzer()
host_registry_analyser = HostRegistryAnalyzer()
evtx_analyzer = EvtxAnalyzer()
timeline_analyzer = TimelineAnalyzer()

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
scripts.add_command(WindowsCommand(evtx_analyzer, host_registry_analyser, user_registry_analyzer, timeline_analyzer).get_commands())
scripts.add_command(ReportCommand(ods_loader).get_commands())

cli = click.Group('cli', context_settings=dict(terminal_width=160))
cli.add_command(cheat_sheets)
cli.add_command(scripts)

if __name__ == '__main__':
    cli()
