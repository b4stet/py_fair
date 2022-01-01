import click
import os
import json
import yaml
import heapq
from regipy.registry import RegistryHive

from fair.command.abstract import AbstractCommand
from fair.entity.report import ReportEntity


class WindowsCommand(AbstractCommand):

    def __init__(self, evtx_analyzer, host_registry_analyzer, user_registry_analyzer, artifact_analyzer):
        self.__evtx_analyzer = evtx_analyzer
        self.__host_reg_analyzer = host_registry_analyzer
        self.__user_reg_analyzer = user_registry_analyzer
        self.__artifact_analyzer = artifact_analyzer

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
                self._get_option_hive_system(),
                self._get_option_hive_ntusers(),
                self._get_option_outdir(),
                self._get_option_output(),
            ]
        ))

        group.add_command(click.Command(
            name='analyze_prefetchs', help='analyze prefecths on the subject system (first/last/nb execution, mapped_files)',
            callback=self.do_analyze_prefetchs,
            params=[
                self._get_option_prefetch(),
                self._get_option_outdir(),
                self._get_option_output(),
            ]
        ))

        group.add_command(click.Command(
            name='extract_evtx', help='extract all evtx in json',
            callback=self.do_extract_evtx,
            params=[
                self._get_option_evtx_path(),
                self._get_option_outdir(),
            ]
        ))

        return group

    def do_profile_host(self, evtx, hive_sam, hive_system, hive_software, outdir, output):
        if not os.path.exists(outdir):
            raise ValueError('Out directory {} does not exist.'.format(outdir))

        # extract info from windows events
        print('[+] Analyzing evtx ', end='', flush=True)
        fd_evtx = open(evtx, mode='r', encoding='utf8')
        nb_events, report, timeline, collection = self.__evtx_analyzer.collect_profiling_events(fd_evtx)
        fd_evtx.close()
        print(' done. Processed {} events'.format(nb_events))

        # extract info from hives, and correlate with evtx in some cases
        print('[+] Analyzing registry hives ', end='', flush=True)

        analysis = {}
        reg_system = RegistryHive(hive_system)
        reg_software = RegistryHive(hive_software)
        reg_sam = RegistryHive(hive_sam)
        self.__host_reg_analyzer.set_current_control_set(reg_system)
        self.__host_reg_analyzer.set_computer_name(reg_system)
        self.__host_reg_analyzer.set_registry_codepage(reg_system)

        report['host_info'], analysis['host_info'] = self.__host_reg_analyzer.collect_host_info(reg_system, reg_software)
        analysis['host_info'] = [a.to_dict() for a in analysis['host_info']]
        print('.', end='', flush=True)

        report['local_users'], analysis['local_users'] = self.__host_reg_analyzer.collect_local_users(reg_sam)
        analysis['local_users'] = [a.to_dict() for a in analysis['local_users']]
        print('.', end='', flush=True)

        report['applications'], analysis['applications'] = self.__host_reg_analyzer.collect_applications(collection['app_uninstalled'], reg_software)
        analysis['applications'] = [a.to_dict() for a in analysis['applications']]
        print('.', end='', flush=True)

        report['autoruns'], analysis['autoruns'] = self.__host_reg_analyzer.analyze_autoruns(reg_system, reg_software)
        analysis['autoruns'] = [a.to_dict() for a in analysis['autoruns']]
        print('.', end='', flush=True)

        report['networks'], timeline_networks, analysis['networks'] = self.__host_reg_analyzer.analyze_networks(reg_system, reg_software)
        analysis['networks'] = [a.to_dict() for a in analysis['networks']]
        timeline.extend(timeline_networks)
        print('.', end='', flush=True)

        report['usb'], timeline_usb, analysis['usb'] = self.__host_reg_analyzer.analyze_usb(collection['storage_info'], collection['pnp_connections'], reg_system, reg_software)
        analysis['usb'] = [a.to_dict() for a in analysis['usb']]
        timeline.extend(timeline_usb)
        print('.', end='', flush=True)

        print(' done.')

        # list what was analyzed
        for paragraph in report.values():
            self._print_text(paragraph.title, paragraph.details)

        # write analysis
        output_files = ReportEntity(
            title='Output files',
            details=[]
        )
        for topic, results in analysis.items():
            outfile = 'profile_host_{}.{}'.format(topic, output)
            outfile = os.path.join(outdir, outfile)
            output_files.details.append('{}'.format(outfile))
            self._write_formatted(outfile, output, results)

        # write timeline
        timeline = sorted(timeline, key=lambda k: k['start'])
        outfile = 'timeline.{}'.format(output)
        outfile = os.path.join(outdir, outfile)
        output_files.details.append('{}'.format(outfile))
        self._write_formatted(outfile, output, timeline)

        self._print_text(output_files.title, output_files.details)

    def do_profile_users(self, hive_system, hive_users, outdir, output):
        if not os.path.exists(outdir):
            raise ValueError('Out directory {} does not exist.'.format(outdir))

        reg_system = RegistryHive(hive_system)
        self.__host_reg_analyzer.set_current_control_set(reg_system)
        codepage = self.__host_reg_analyzer.get_registry_codepage(reg_system)

        for hive_user, username in hive_users:
            # process
            print('[+] Analyzing registry hive for user {} '.format(username), end='', flush=True)

            reg_user = RegistryHive(hive_user)
            self.__user_reg_analyzer.set_registry_codepage(codepage)
            report = {}
            analysis = {}
            report['rdp_connections'], analysis['rdp_connections'] = self.__user_reg_analyzer.analyze_rdp_connections(reg_user)
            analysis['rdp_connections'] = [a.to_dict() for a in analysis['rdp_connections']]
            print('.', end='', flush=True)

            report['usb_shares_usage'], analysis['usb_shares_usage'] = self.__user_reg_analyzer.analyze_usb_shares_usage(reg_user)
            analysis['usb_shares_usage'] = [a.to_dict() for a in analysis['usb_shares_usage']]
            print('.', end='', flush=True)

            report['autoruns'], analysis['autoruns'] = self.__user_reg_analyzer.analyze_autoruns(reg_user)
            analysis['autoruns'] = [a.to_dict() for a in analysis['autoruns']]
            print('.', end='', flush=True)

            report['applications'], analysis['applications'] = self.__user_reg_analyzer.analyze_applications(reg_user)
            analysis['applications'] = [a.to_dict() for a in analysis['applications']]
            print('.', end='', flush=True)

            report['cloud_accounts'], analysis['cloud_accounts'] = self.__user_reg_analyzer.analyze_cloud_accounts(reg_user)
            analysis['cloud_accounts'] = [a.to_dict() for a in analysis['cloud_accounts']]
            print('.', end='', flush=True)

            print(' done.\n')

            # write analysis
            output_files = ReportEntity(
                title='Output files for user {}'.format(username),
                details=[]
            )
            for topic, results in analysis.items():
                outfile = 'profile_user_{}_{}.{}'.format(username, topic, output)
                outfile = os.path.join(outdir, outfile)
                output_files.details.append('{}'.format(outfile))
                self._write_formatted(outfile, output, results)
            self._print_text(output_files.title, output_files.details)

        # list what was analyzed
        for paragraph in report.values():
            self._print_text(paragraph.title, paragraph.details)

    def do_analyze_prefetchs(self, prefetch, outdir, output):
        if not os.path.exists(outdir):
            raise ValueError('Out directory {} does not exist.'.format(outdir))

        fd_prefetchs = open(prefetch, mode='r', encoding='utf8')
        prefetchs = self.__artifact_analyzer.analyze_prefetchs(fd_prefetchs)
        fd_prefetchs.close()

        outfile = 'prefetchs.{}'.format(output)
        outfile = os.path.join(outdir, outfile)
        self._write_formatted(outfile, output, prefetchs)
        self._print_text(title='Wrote results in {}'.format(outfile))

    def do_extract_evtx(self, evtx_path, outdir):
        if not os.path.exists(outdir):
            raise ValueError('Out directory {} does not exist.'.format(outdir))

        if not os.path.exists(evtx_path):
            raise ValueError('Evtx directory {} does not exist.'.format(evtx_path))

        events_all = []
        nb_events_all = 0
        starts_ends = []
        outfile_evtx = os.path.join(outdir, 'evtx.ndjson')
        outfile_starts_ends = os.path.join(outdir, 'evtx_starts_ends.csv')

        for evtx in os.listdir(evtx_path):
            if evtx.endswith('.evtx'):
                file = os.path.join(evtx_path, evtx)
                print('[+] Extracting events from {} ... '.format(file), end='', flush=True)
                nb_events, events, start_end = self.__evtx_analyzer.extract_generic(file)
                start_end['evtx_file'] = evtx
                if events is not None:
                    events_all = heapq.merge(events_all, events)
                    nb_events_all += nb_events
                    starts_ends.append(start_end)
                print(' done ({} events)'.format(nb_events), flush=True)

        with open(outfile_evtx, mode='w', encoding='utf8') as fout:
            for i in range(nb_events_all):
                json.dump(next(events_all)[3], fout)
                fout.write('\n')

        self._write_formatted(outfile_starts_ends, self.OUTPUT_CSV, starts_ends)

        self._print_text(title='Wrote {} events in {}'.format(nb_events_all, outfile_evtx))
        self._print_text(title='Wrote start/end of logs in {}'.format(outfile_starts_ends))
