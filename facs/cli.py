import click
import cProfile

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
from facs.command.scripts.report import ReportCommand

from facs.loader.ods import OdsBo


from facs.analyzer.registry_user import UserRegistryAnalyzer
from facs.analyzer.registry_host import HostRegistryAnalyzer
from facs.analyzer.evtx import EvtxAnalyzer
from facs.analyzer.artifact import ArtifactAnalyzer

ods_loader = OdsBo()

user_registry_analyzer = UserRegistryAnalyzer()
host_registry_analyser = HostRegistryAnalyzer()
evtx_analyzer = EvtxAnalyzer()
artifact_analyzer = ArtifactAnalyzer()

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
scripts.add_command(WindowsCommand(evtx_analyzer, host_registry_analyser, user_registry_analyzer, artifact_analyzer).get_commands())
scripts.add_command(ReportCommand(ods_loader).get_commands())

cli = click.Group('cli', context_settings=dict(terminal_width=160))
cli.add_command(cheat_sheets)
cli.add_command(scripts)

if __name__ == '__main__':
    # cli()
    windows = WindowsCommand(evtx_analyzer, host_registry_analyser, user_registry_analyzer, artifact_analyzer)
    windows.do_extract_evtx("../../challenges/training/challenge_stack/mnt/Windows/System32/winevt/Logs/", "../../challenges/training/challenge_stack/forensic/")
