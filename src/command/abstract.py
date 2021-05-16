from abc import ABCMeta, abstractmethod
import click
import json


class AbstractCommand():
    OUTPUT_JSON = 'json'
    OUTPUT_CSV = 'csv'
    OUTPUTS = [OUTPUT_JSON, OUTPUT_CSV]

    def __init__(self):
        pass

    @abstractmethod
    def get_commands(self):
        raise NotImplementedError('Method get_commands must be implemented on class {}'.format(type(self)))

    def print(self, output: str, data: list):
        if len(data) == 0:
            return

        if output == self.OUTPUT_JSON:
            print(json.dumps(data))

        if output == self.OUTPUT_CSV:
            header = list(data[0].keys())
            columns = ['name', 'status', 'time_last']
            print(','.join(header))

            for elt in data:
                values = [elt[col] for col in header]
                print(','.join(str(value) for value in values))

    def get_option_output(self):
        return click.Option(
            ['--output', '-o', 'output'],
            help='Format to output result. Default is json',
            default='json',
            type=click.Choice(self.OUTPUTS)
        )

    def get_option_meow(self):
        return click.Option(
            ['--meow', '-m', 'meows'],
            help='An option that can be repeated',
            multiple=True,
            type=str
        )
