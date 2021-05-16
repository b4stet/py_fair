#!/usr/bin/python3

import click
from src.include import commands

cli = click.Group('cli')
for command in commands:
    cli.add_command(command().get_commands())

if __name__ == '__main__':
    cli()
