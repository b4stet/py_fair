import click
from facs.command.acquisition import AcquisitionCommand
from facs.command.logfile import LogfileCommand


cli = click.Group('cli', context_settings=dict(terminal_width=120))
cli.add_command(AcquisitionCommand().get_commands())
cli.add_command(LogfileCommand().get_commands())

if __name__ == '__main__':
    cli()
