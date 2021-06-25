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

## Commands
- `resources`: blogs, tools, various knowledge bases, notable cves, ...
- `systems`: some notes about operating systems
- `tools`: cheat sheets for some tools like tsk, plaso, tshark, volatility, ...
- `logs`: cheat sheets of some log paths, default values, Windows event IDs ...
- `acquisition`: cheat sheets for operations related to data acquisition (info, dump disk/memory, mount)
- `carving`: cheat sheets to carve allocated and unallocated blocks, ...
- `preprocessing`: cheat sheets and scripts to prepare data to be analyzed
- `processing`: cheat sheets and scripts to forensicate

## Examples
Windows host profiling on a 120G disk dump:
```
$ py_facs processing win_profiling_host -e plaso_evtx.json -hsystem SYSTEM_CLEAN -hsoftware SOFTWARE_CLEAN -hsam SAM_CLEAN -d reports/ -o csv
[+] Analyzing evtx ... done. Processed 264382 events
[+] Analyzing registry hives ... done.
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
 | Found 18 event(s)

[+] Checked evidences of host start/stop
 | From Security channel, provider Microsoft-Windows-Eventlog, EID 4608/4609
 | From System channel, provider Microsoft-Windows-Kernel-General, EID 12/13
 | From System channel, provider User32, EID 1074
 | Found 25 event(s)

[+] Collected system information
 | computer name from key SYSTEM\Control\ComputerName\ComputerName
 | OS info from key SYSTEM\Microsoft\Windows NT\CurrentVersion
 | time zone info from key SYSTEM\Control\TimeZoneInformation
 | control sets from key SYSTEM\Select

[+] Collected local accounts information
 | accounts from key \SAM\Domains\Account\Users
 | groups membership from key \SAM\Domains\Builtin\Aliases
 | account creation from key \SAM\Domains\Account\Users\Names

[+] Collected application installed system wide and uninstalled
 | system wide installation from key \Microsoft\Windows\CurrentVersion\Uninstall
 | uninstalled from Application channel, provider MsiInstaller, EID 11724

[+] Collected network connections
 | NIC from subkeys of SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards
 | interface parameters from subkeys of SOFTWARE\Services\Tcpip\Parameters\Interfaces\
 | connections history from subkeys of SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\

[+] Output files
 | timeline in reports/profiling_timeline.csv
 | host profiling in reports/profiling_host.csv
 | networks profiling in reports/profiling_networks.csv
 | local users profiling in reports/profiling_users.csv
 | applications system wide info in reports/profiling_applications_system_wide.csv

real	2m16,088s
user	2m10,261s
sys	    0m5,787s
```