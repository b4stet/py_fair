import click
import json
import sys
import os
from facs.command.abstract import AbstractCommand
from facs.entity.timeline import TimelineEntity


class ProcessingCommand(AbstractCommand):

    def __init__(self, evtx_bo, registry_bo, report_timeline_bo):
        super().__init__('processing.yaml')
        self.__evtx_bo = evtx_bo
        self.__registry_bo = registry_bo
        self.__report_timeline_bo = report_timeline_bo

    def get_commands(self):
        group = click.Group(
            'processing',
            help='cheat sheets and scripts to forensicate',
            context_settings=dict(terminal_width=120)
        )

        group.add_command(click.Command(
            name='misc', help='cheat sheets for other possible steps in the analysis (manual mining, ...)',
            callback=self.get_cheat_sheet_misc
        ))

        group.add_command(click.Command(
            name='tool_patterns', help='cheat sheets of known artifacts left by attacker toolbox (psexec, mimikatz, ...)',
            callback=self.get_tool_patterns
        ))

        group.add_command(click.Command(
            name='list_defaults', help='list of default values in tool configuration (RAT, reverse shells, ...)',
            callback=self.list_defaults
        ))

        group.add_command(click.Command(
            name='win_profiling_host', help='profile a host based on evtx and registry',
            callback=self.do_win_profiling,
            params=[
                self._get_option_evtx(),
                self._get_option_hive_sam(),
                self._get_option_hive_system(),
                self._get_option_hive_software(),
                self._get_option_outdir(),
                self._get_option_output(),
            ]
        ))

        return group

    def get_cheat_sheet_misc(self):
        manual = []
        for elt in self._data['manual_mining']:
            line = '{:80}: {}'.format(elt['description'], elt['note'])
            manual.append(line)
        self._print_text('Manual mining', manual)

    def get_tool_patterns(self):
        patterns = []
        for elt in self._data['patterns']:
            for pattern in elt['detection']:
                line = 'tool: {:40} pattern: {}'.format(elt['tool'], pattern)
                patterns.append(line)
        self._print_text('Known/Possible patterns of adversaries tools', patterns)

    def list_defaults(self):
        defaults = []
        for elt in self._data['defaults']:
            line = '{:60}: {}'.format(elt['description'], elt['value'])
            defaults.append(line)
        self._print_text('Some default values of software', defaults)

    def do_win_profiling(self, evtx, hive_sam, hive_system, hive_software, outdir, output):
        if not os.path.exists(outdir):
            raise ValueError('Out directory {} does not exist.'.format(outdir))

        out_timeline = os.path.join(outdir, 'profiling_timeline.' + output)
        out_profiling_host = os.path.join(outdir, 'profiling_host.' + output)
        out_profiling_users = os.path.join(outdir, 'profiling_users.' + output)
        out_profiling_networks = os.path.join(outdir, 'profiling_networks.' + output)
        out_profiling_applications = os.path.join(outdir, 'profiling_applications_system_wide.' + output)

        # extract info from windows events
        print('[+] Analyzing evtx ... ', end='', flush=True)
        fd_evtx = open(evtx, mode='r', encoding='utf8')
        results_evtx = self.__evtx_bo.get_profiling_from_evtx(fd_evtx)
        # nb_events, computer, backdating, cleaning, start_stop, start_end = self.__evtx_bo.get_profiling_from_evtx(fd_evtx)
        fd_evtx.close()
        print('done. Processed {} events'.format(results_evtx['nb_events']))

        # extract info from system, software and sam hive
        print('[+] Analyzing registry hives ... ', end='', flush=True)
        results_registry = self.__registry_bo.get_profiling_from_registry(hive_system, hive_software, hive_sam)
        print('done.')

        # assemble timeline and reports
        result = self.__report_timeline_bo.get_profiling(results_evtx, results_registry, self.__evtx_bo.CHANNELS_MIN)
        result['report'].append({
            'title': 'Output files',
            'data': [
                'timeline in {}'.format(out_timeline),
                'host profiling in {}'.format(out_profiling_host),
                'networks profiling in {}'.format(out_profiling_networks),
                'local users profiling in {}'.format(out_profiling_users),
                'applications system wide info in {}'.format(out_profiling_applications),
            ],
        })
        for chunk in result['report']:
            self._print_text(chunk['title'], chunk['data'])

        timeline = sorted(result['timeline'], key=lambda k: k['start'])
        self._write_formatted(out_timeline, output, timeline)
        self._write_formatted(out_profiling_host, output, result['profiling']['host'])
        self._write_formatted(out_profiling_users, output, result['profiling']['users'])
        self._write_formatted(out_profiling_networks, output, result['profiling']['interfaces'])
        self._write_formatted(out_profiling_applications, output, result['profiling']['applications'])
