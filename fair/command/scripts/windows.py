import click
import os
import yaml
from regipy.registry import RegistryHive

from fair.command.abstract import AbstractCommand
from fair.entity.report import ReportEntity


class WindowsCommand(AbstractCommand):

    def __init__(self, evtx_analyzer, prefetch_analyzer, host_registry_analyzer, user_registry_analyzer, timeline_analyzer):
        self.__evtx_analyzer = evtx_analyzer
        self.__prefetch_analyzer = prefetch_analyzer
        self.__host_reg_analyzer = host_registry_analyzer
        self.__user_reg_analyzer = user_registry_analyzer
        self.__timeline_analyzer = timeline_analyzer
        super().__init__('fair_tags.yaml')

    def get_commands(self):
        group = click.Group(
            'windows',
            help='forensicating a Windows host',
        )

        group.add_command(click.Command(
            name='profile_host', help='profile the subject system from evtx and registry',
            callback=self.profile_host,
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
            callback=self.profile_users,
            params=[
                self._get_option_hive_system(),
                self._get_option_hive_ntusers(),
                self._get_option_outdir(),
                self._get_option_output(),
            ]
        ))

        group.add_command(click.Command(
            name='extract_evtx', help='extract all evtx in json',
            callback=self.extract_evtx,
            params=[
                self._get_option_evtx_path(),
                self._get_option_outdir(),
            ]
        ))

        group.add_command(click.Command(
            name='extract_prefetch', help='extract all prefetch',
            callback=self.extract_prefetch,
            params=[
                self._get_option_prefetch_path(),
                self._get_option_outdir(),
                self._get_option_output(),
            ]
        ))

        group.add_command(click.Command(
            name='extract_amcache', help='extract info fom AmCache hive',
            callback=self.extract_amcache,
            params=[
                self._get_option_amcache_path(),
                self._get_option_outdir(),
                self._get_option_output(),
            ]
        ))

        group.add_command(click.Command(
            name='merge_timelines', help='assemble evtx+fls+plaso timelines into a unique ndjson',
            callback=self.merge_timelines,
            params=[
                self._get_option_evtx(),
                self._get_option_timeline_plaso(),
                self._get_option_timeline_fls(),
                self._get_option_tags(),
                self._get_option_outdir(),
            ]
        ))

        return group

    def profile_host(self, evtx, hive_sam, hive_system, hive_software, outdir, output):
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

    def profile_users(self, hive_system, hive_users, outdir, output):
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

    def extract_evtx(self, evtx_path, outdir):
        if not os.path.exists(outdir):
            raise ValueError('Out directory {} does not exist.'.format(outdir))

        if not os.path.exists(evtx_path):
            raise ValueError('Evtx directory {} does not exist.'.format(evtx_path))

        outfile_starts_ends = os.path.join(outdir, 'evtx_starts_ends.csv')
        outfile_evtx_unsorted = os.path.join(outdir, 'evtx_unsorted.ndjson')
        outfile_evtx_sorted = os.path.join(outdir, 'evtx.ndjson')

        fd_out = open(outfile_evtx_unsorted, mode='w', encoding='utf8')
        nb_events_all = 0
        starts_ends = []
        for evtx in os.listdir(evtx_path):
            if evtx.endswith('.evtx'):
                infile_evtx = os.path.join(evtx_path, evtx)
                print('[+] Extracting events from {} ... '.format(infile_evtx), end='', flush=True)
                nb_events, start_end = self.__evtx_analyzer.extract_generic(infile_evtx, fd_out)
                start_end['evtx_file'] = evtx
                if nb_events > 0:
                    nb_events_all += nb_events
                    starts_ends.append(start_end)
                print(' done ({} events)'.format(nb_events), flush=True)
        fd_out.close()
        print('')

        self._sort_big_file(outfile_evtx_unsorted, outfile_evtx_sorted, 1)
        starts_ends.sort(key=lambda elt: elt['start'])

        self._write_formatted(outfile_starts_ends, self.OUTPUT_CSV, starts_ends)
        self._print_text(title='Wrote {} events in {}'.format(nb_events_all, outfile_evtx_sorted), newline=False)
        self._print_text(title='Wrote start/end of logs in {}'.format(outfile_starts_ends))

    def extract_prefetch(self, prefetch_path, outdir, output):
        if not os.path.exists(outdir):
            raise ValueError('Out directory {} does not exist.'.format(outdir))

        if not os.path.exists(prefetch_path):
            raise ValueError('Prefetch directory {} does not exist.'.format(prefetch_path))

        prefetchs = []
        for prefetch in os.listdir(prefetch_path):
            if prefetch.endswith('.pf'):
                infile_prefetch = os.path.join(prefetch_path, prefetch)
                print('[+] Extracting info from prefetch {} ... '.format(infile_prefetch), end='', flush=True)
                extracted = self.__prefetch_analyzer.extract(infile_prefetch)
                if output == self.OUTPUT_CSV:
                    prefetchs.extend(self.__prefetch_analyzer.flatten(extracted))
                else:
                    prefetchs.append(extracted)
                print('done', flush=True)

        outfile = 'prefetchs.{}'.format(output)
        outfile = os.path.join(outdir, outfile)
        self._write_formatted(outfile, output, prefetchs)
        self._print_text(title='Wrote prefetchs in {}'.format(outfile))

    def extract_amcache(self, amcache_path, outdir, output):
        if not os.path.exists(outdir):
            raise ValueError('Out directory {} does not exist.'.format(outdir))

        if not os.path.exists(amcache_path):
            raise ValueError('AmCache hive {} does not exist.'.format(amcache_path))

        # reg_amcache = RegistryHive(amcache_path)
        # amcache = self.__amcache_analyzer.extract(reg_amcache)

        # if output == self.OUTPUT_CSV:
        #     amcache = self.__amcache_analyzer.flatten(amcache)

        # outfile = 'amcache.{}'.format(output)
        # outfile = os.path.join(outdir, outfile)
        # self._write_formatted(outfile, output, amcache)
        # self._print_text(title='Wrote AmCache info in {}'.format(outfile))

    def merge_timelines(self, evtx, timeline_plaso, timeline_fls, outdir, tags_file):
        if not os.path.exists(outdir):
            raise ValueError('Out directory {} does not exist.'.format(outdir))

        outfile_unsorted = os.path.join(outdir, 'timelines_unsorted.ndjson')
        outfile_sorted = os.path.join(outdir, 'timelines.ndjson')

        tags = None
        if tags_file is not None:
            with open(tags_file, mode='r', encoding='utf-8') as f:
                tags = yaml.safe_load(f)
        else:
            # default tags list
            tags = self._data

        tags_mft = True if tags is not None else False
        tags_evtx = tags.get('evtx', None) if tags is not None else None
        tags_plaso = tags.get('plaso_artifacts', None) if tags is not None else None

        fd_out = open(outfile_unsorted, mode='w', encoding='utf8')

        self._print_text(title='Adding fls timeline', newline=False)
        self.__timeline_analyzer.prepare_fls(timeline_fls, fd_out, tags_mft)

        self._print_text(title='Adding evtx timeline', newline=False)
        self.__timeline_analyzer.prepare_evtx(evtx, fd_out, tags_evtx)

        self._print_text(title='Adding plaso timeline', newline=False)
        self.__timeline_analyzer.prepare_plaso(timeline_plaso, fd_out, tags_plaso)

        fd_out.close()

        self._print_text(title='Sorting by dates')
        self._sort_big_file(outfile_unsorted, outfile_sorted, 1)
        self._print_text(title='Merged all timelines in {}'.format(outfile_sorted))
