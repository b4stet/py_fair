import click
import os
import sys
import json
from facs.command.abstract import AbstractCommand
from facs.entity.timeline import TimelineEntity


class WindowsCommand(AbstractCommand):

    def __init__(self, evtx_bo, registry_bo, report_bo):
        self.__evtx_bo = evtx_bo
        self.__registry_bo = registry_bo
        self.__report_bo = report_bo

    def get_commands(self):
        group = click.Group(
            'windows',
            help='forensicating a Windows host',
        )

        group.add_command(click.Command(
            name='profile_host', help='profile the subject system from evtx and registry',
            callback=self.do_profile_host,
            params=[
                self._get_option_evtx(),
                self._get_option_hive_sam(),
                self._get_option_hive_system(),
                self._get_option_hive_software(),
                self._get_option_outdir(),
                self._get_option_output(),
            ]
        ))

        group.add_command(click.Command(
            name='profile_users', help='profile the users on the subject system from their ntuser.dat hive',
            callback=self.do_profile_users,
            params=[
                self._get_option_hive_ntusers(),
                self._get_option_outdir(),
                self._get_option_output(),
            ]
        ))

        return group

    def do_profile_host(self, evtx, hive_sam, hive_system, hive_software, outdir, output):
        if not os.path.exists(outdir):
            raise ValueError('Out directory {} does not exist.'.format(outdir))

        out_timeline = os.path.join(outdir, 'profiling_timeline.' + output)
        out_profiling_host = os.path.join(outdir, 'profiling_host.' + output)
        out_profiling_users = os.path.join(outdir, 'profiling_users.' + output)
        out_profiling_networks = os.path.join(outdir, 'profiling_networks.' + output)
        out_profiling_applications = os.path.join(outdir, 'profiling_applications_system_wide.' + output)
        out_profiling_storage = os.path.join(outdir, 'profiling_storage.' + output)
        out_profiling_autorun = os.path.join(outdir, 'profiling_autorun.' + output)

        # extract info from system, software and sam hive
        print('[+] Analyzing registry hives ', end='', flush=True)
        results_registry = self.__registry_bo.get_profiling_from_host_registries(hive_system, hive_software, hive_sam)
        print(' done.')

        # extract info from windows events
        print('[+] Analyzing evtx ', end='', flush=True)
        fd_evtx = open(evtx, mode='r', encoding='utf8')
        results_evtx = self.__evtx_bo.get_profiling_from_evtx(fd_evtx)
        fd_evtx.close()
        print(' done. Processed {} events'.format(results_evtx['nb_events']))

        # assemble timeline and reports
        report = self.__report_bo.assemble_host_report(results_evtx, results_registry, self.__evtx_bo.CHANNELS_MIN)
        report['report'].append({
            'title': 'Output files',
            'data': [
                'timeline in {}'.format(out_timeline),
                'host profiling in {}'.format(out_profiling_host),
                'networks profiling in {}'.format(out_profiling_networks),
                'local users profiling in {}'.format(out_profiling_users),
                'applications system wide info in {}'.format(out_profiling_applications),
                'writable storage info in {}'.format(out_profiling_storage),
                'autorun info in {}'.format(out_profiling_autorun),
            ],
        })
        for chunk in report['report']:
            self._print_text(chunk['title'], chunk['data'])

        timeline = sorted(report['timeline'], key=lambda k: k['start'])
        self._write_formatted(out_timeline, output, timeline)
        self._write_formatted(out_profiling_host, output, report['profiling']['host'])
        self._write_formatted(out_profiling_users, output, report['profiling']['users'])
        self._write_formatted(out_profiling_networks, output, report['profiling']['interfaces'])
        self._write_formatted(out_profiling_applications, output, report['profiling']['applications'])
        self._write_formatted(out_profiling_storage, output, report['profiling']['writable_storage'])
        self._write_formatted(out_profiling_autorun, output, report['profiling']['autorun'])

    def do_profile_users(self, hive_users, outdir, output):
        if not os.path.exists(outdir):
            raise ValueError('Out directory {} does not exist.'.format(outdir))

        results = {}
        for hive_user, username in hive_users:
            out = 'profiling_{}.{}'.format(username, output)
            out = os.path.join(outdir, out)

            print('[+] Analyzing registry hive for user {} '.format(username), end='', flush=True)
            profiling = self.__registry_bo.get_profiling_from_user_registry(hive_user)
            results[username] = {'outfile': out, **profiling}
            print(' done.')

        print(results)
