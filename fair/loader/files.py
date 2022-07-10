import os
import pefile

class FilesLoader():
    WIN_ENV_VARS = {
        'HOMEDRIVE': 'C:',
        'SYSTEMDRIVE': 'C:',
        'ALLUSERSPROFILE': 'C:/ProgramData',
        'PROGRAMDATA': 'C:/ProgramData',
        'SYSTEMROOT': 'C:/Windows',
        'WINDIR': 'C:/Windows',
        'SYSTEM': 'C:/Windows/System32',
        'SYSTEM32': 'C:/Windows/System32',
        'PROGRAMFILES': 'C:/Program Files',
        'PROGRAMW6432': 'C:/Program Files',
        'PROGRAMFILES(x86)': 'C:/Program Files (x86)',
        'COMMONPROGRAMFILES': 'C:/Program Files/Common Files',
        'COMMONPROGRAMW6432': 'C:/Program Files/Common Files',
        'COMMONPROGRAMFILES(x86)': 'C:/Program Files (x86)/Common Files',
        'DRIVERDATA': 'C:/Windows/System32/Drivers/DriverData',
    }

    def convert_path_to_unix(self, file_path, mount_point):
        # transform the path to be unix friendly
        file_path_chunks = file_path.strip('\\').replace('\\', '/').split('/')

        # expand Windows environment variable
        # it can have multiple forms: %xxx%, \xxx, $(runtime.xxx)
        pattern = file_path_chunks[0].upper()
        pattern = pattern.strip('%')
        pattern = pattern.lstrip('$(RUNTIME.')
        pattern = pattern.rstrip(')')
        if pattern in self.WIN_ENV_VARS:
            file_path_chunks[0] = self.WIN_ENV_VARS[pattern]

        return '/'.join(file_path_chunks).lower().replace('c:', mount_point)

    def get_alternative_message_table_files(self, file_path):
        alternatives = []
        alternatives.append(file_path)
        chunks = file_path.split('/')

        # it might be in 32 bit version
        orig = chunks[2]
        if orig == 'system32':
            chunks[2] = 'syswow64'
            alternatives.append('/'.join(chunks))
            chunks[2] = orig
        
        # it might be in the mui version
        dir = '/'.join(chunks[:-1])
        alternatives.append(dir + '/en-us/' + chunks[-1] + '.mui')

        return alternatives

    def find_file(self, file_path, mount_point):
        # find the case sensitive path from the mount point
        chunks = file_path.split('/')
        path_dir = '/'.join(chunks[:-1])
        path_dir = path_dir.replace('c:', mount_point)
        path_file = chunks[-1]

        real_path = None
        for root, _, files in os.walk(mount_point):
            if root.lower() != path_dir:
                continue

            for file in files:
                if file.lower() == path_file:
                    real_path = os.path.join(root, file)
                    break
                    
                if real_path is not None:
                    break

        return real_path

