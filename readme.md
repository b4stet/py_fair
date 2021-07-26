# py_facs (Forensic Automation and Cheat Sheets)

Some scripts and cheat sheets around digital forensic analysis.

Every command and subcommand have a helper.
If installed with pip3:
```
$ py_facs
$ py_facs <command> --help
$ py_facs <command> <subcommand> --help
```

Otherwise:
```
$ python3 -m facs.cli
$ python3 -m facs.cli <command> --help
$ python3 -m facs.cli <command> <subcommand> --help
```


## Requirements
```
$ python3 -m venv facs_env
$ source ./facs_env/bin/activate
$ pip3 install -r requirements.txt
```

## Install
```
$ source ./facs_env/bin/activate
$ pip3 install .
```

## Uninstall
```
$ pip3 uninstall py_facs
```

## Cheat Sheets Commands
- `library`: blogs, tools, various knowledge bases, notable cves, ...
- `tools`: cheat sheets for some tools like tsk, plaso, tshark, volatility, ...
- `systems`: some notes about operating systems
- `logs`: cheat sheets of some log paths, Windows event IDs ...
- `acquisition`: cheat sheets for operations related to data acquisition (info, dump disk/memory, mount)
- `carving`: cheat sheets to carve allocated and unallocated blocks, ...
- `preprocessing`: cheat sheets to prepare data to be analyzed, time intensive tasks
- `processing`: cheat sheets for manual mining, default values, attacker toolbox patterns

## Scripts Commands
- `nsrl`: set of scripts to extract OS and office related files (known goods), to then filter on a disk timeline
- `windows`: set of scripts to automate some parts of the forensics (eg. profiling host and users)
- `report`: set of scripts to export csv results in an ODS file, or visualize the timeline

As data volume can be huge for some artifacts, specific formats are enforced to "stream" files instead of loading them fully in memory.  
When this is required, the helper of the command indicates the expected format.

## About export to ODS
The ODF format was preferred to Open XML one due to issues with xlsx file created in LibreOffice.
However, the only suitable library found to handle creation, data updates and styles in ODF was `odfpy`.
As the notion of address/coordinates is not attached to a cell in ODF, several limitations are enforced to avoid writing a too complex processor:
- styles supported are font, size, alignement, color and color background
- cell borders are not supported by the code
    - when used, this style property is applied per cell ... not friendly to handle properly without cell addresses
    - using table range (in LibreOffice: Data > Select Range > select the table name), it's a 2 clics process to get borders as you wish the first time
    - the code maintains table range, so that borders will be auto updated when adding rows
- all cells have type `string`, which does not break date sorting since scripts generate all dates in ISO8601 format
- table should start at cell A1
- first row of a table should be the header, with non empty, nor duplicate values
    - otherwise ODF will "compress" using the property `number-column-repeated`
    - this property is not handled by the code
    - hence it will break the columns computation

## Examples
### Windows host profiling
```
$ py_facs scripts windows profile_host -e l2t_evtx.json  -d reports/ -o csv --hsystem SYSTEM_CLEAN --hsoftware SOFTWARE_CLEAN --hsam SAM_CLEAN

[+] Analyzing registry hives ........ done.
[+] Analyzing evtx ........................................................................................................................................................................................................................................................................ done. Processed 264382 events
[+] Checked start/end of windows event log for main channels
 | Security                                                                        : ok
 | System                                                                          : ok
 | Application                                                                     : ok
 | Microsoft-Windows-TaskScheduler/Operational                                     : not found
 | Microsoft-Windows-TerminalServices-RDPClient/Operational                        : not found
 | Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational          : ok
 | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational              : ok

[+] Checked evidences of system backdating
 | Looked for clock drift bigger than 10 minutes
 | From Security channel, provider Microsoft-Windows-Security-Auditing, EID 4616 where user is not "LOCAL SERVICE" or "SYSTEM"
 | From System channel, provider Microsoft-Windows-Kernel-General, EID 1 where reason is not 2
 | Found: 0 event(s)

[+] Checked evidences of log tampering
 | From Security channel, provider Microsoft-Windows-Eventlog, EID 1100/1102/1104
 | From System channel, provider Eventlog, EID 6005/6006
 | Found 13 event(s)

[+] Checked evidences of host start/stop
 | From Security channel, provider Microsoft-Windows-Eventlog, EID 4608/4609
 | From System channel, provider Microsoft-Windows-Kernel-General, EID 12/13
 | From System channel, provider User32, EID 1074
 | Found 19 event(s)

[+] Collected system information
 | computer name from key SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName
 | OS info from key SYSTEM\Microsoft\Windows NT\CurrentVersion
 | time zone info from key SYSTEM\CurrentControlSet\Control\TimeZoneInformation
 | control sets from key SYSTEM\Select

[+] Collected local accounts information
 | accounts from key SAM\SAM\Domains\Account\Users
 | groups membership from key SAM\SAM\Domains\Builtin\Aliases
 | account creation from key SAM\SAM\Domains\Account\Users\Names

[+] Collected application installed system wide or uninstalled
 | system wide installation from key SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
 | uninstalled applications from Application channel, provider MsiInstaller, EID 11724

[+] Collected network connections (ethernet, wifi, VPN)
 | NIC from subkeys of SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards
 | interface parameters from subkeys of SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces (if IP address found)
 | connections history from subkeys of SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures

[+] Collected information about writable storage (PCI, UAS drives, USB mass storage, MTP devices)
 | hardware info from Microsoft-Windows-Partition/Diagnostic channel, provider Microsoft-Windows-Partition, EID 1006
 | connections from Microsoft-Windows-Kernel-PnP/Configuration channel, provider Microsoft-Windows-Kernel-PnP, EID 410/430
 | user labels and instance info from key SOFTWARE\Microsoft\Windows Portable Devices\Devices
 | device types from key SYSTEM\CurrentControlSet\Enum\USB, property {a8b865dd-2e3d-4094-ad97-e593a70c75d6}
 | models from key SYSTEM\CurrentControlSet\Enum\USB, property {540b947e-8b40-45bc-a8a2-6a0b894cbda2}
 | first/last connections from key SYSTEM\CurrentControlSet\Enum\USB, property {83da6326-97a6-4088-9453-a1923f573b29}
 | drive letters, and volume GUID from key SYSTEM\MountedDevices (do check manually slack space)

[+] Collected information autostart services and applications
 | Windows services from subkeys of SYSTEM\CurrentControlSet\Services
 | Shell value at logon from key SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
 | Commands executed at each run of cmd.exe from key SOFTWARE\Microsoft\Command Processor
 | Autostart app and service from key SOFTWARE\Microsoft\Windows\CurrentVersion\Run
 | Autostart app and service from key SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

[+] Output files
 | timeline in ./reports/profiling_timeline.csv
 | host profiling in ./reports/profiling_host.csv
 | networks profiling in ./reports/profiling_networks.csv
 | local users profiling in ./reports/profiling_users.csv
 | applications system wide info in ./reports/profiling_applications_system_wide.csv
 | writable storage info in ./reports/profiling_storage.csv
 | autorun info in ./reports/profiling_autorun.csv

real	2m16,768s
user	2m4,409s
sys	0m12,374s
```