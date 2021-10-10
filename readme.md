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
$ python -m pip install pip wheel setuptools --upgrade
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
- cell types suppported are limited to `string` and `float`, which does not break date sorting since scripts generate all dates in ISO8601 format
- table should start at cell A1
- first row of a table should be the header, with non empty, nor duplicate values
    - otherwise ODF will "compress" using the property `number-column-repeated`
    - this property is not handled by the code
    - hence it will break the columns computation

## Examples
### Windows host profiling
```
$ time py_facs scripts windows profile_host -d reports/ -o csv -e l2t_evtx.json  --hsystem SYSTEM_CLEAN --hsoftware SOFTWARE_CLEAN --hsam SAM_CLEAN

[+] Analyzing evtx ......................................................................................................................... done. Processed 121389 events
[+] Analyzing registry hives ...... done.

[+] Checked start/end of windows event log for main channels
 | Security                                                                        : found
 | System                                                                          : found
 | Application                                                                     : found
 | Microsoft-Windows-TaskScheduler/Operational                                     : not found
 | Microsoft-Windows-TerminalServices-RDPClient/Operational                        : not found
 | Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational          : found
 | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational              : found

[+] Checked evidences of system backdating
 | looked for clock drifts bigger than 10 minutes
 | from Security channel, provider Microsoft-Windows-Security-Auditing, EID 4616 where user is not "LOCAL SERVICE" or "SYSTEM"
 | from System channel, provider Microsoft-Windows-Kernel-General, EID 1 where reason is not 2

[+] Checked evidences of log tampering
 | from Security channel, provider Microsoft-Windows-Eventlog, EID 1100/1102/1104
 | from System channel, provider Eventlog, EID 6005/6006

[+] Checked evidences of host start/stop/sleep/wake up
 | from Security channel, provider Microsoft-Windows-Eventlog, EID 4608/4609
 | from System channel, provider Microsoft-Windows-Kernel-General, EID 12/13
 | from System channel, provider Microsoft-Windows-Power-Troubleshooter, EID 1
 | from System channel, provider User32, EID 1074

[+] Collected system information
 | computer name from key SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName
 | OS info from key SYSTEM\Microsoft\Windows NT\CurrentVersion
 | time zone info from key SYSTEM\CurrentControlSet\Control\TimeZoneInformation
 | control sets from key SYSTEM\Select
 | NICs from subkeys of SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards
 | prefetch status from key SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters

[+] Collected local accounts information
 | accounts from key SAM\SAM\Domains\Account\Users
 | groups membership from key SAM\SAM\Domains\Builtin\Aliases
 | account creation from key SAM\SAM\Domains\Account\Users\Names

[+] Collected application installed system wide or uninstalled
 | system wide installation from key SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
 | uninstalled applications from Application channel, provider MsiInstaller, EID 11724

[+] Collected autostart services and applications
 | Windows services from subkeys of SYSTEM\CurrentControlSet\Services
 | shell value at logon from key SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
 | commands executed at each run of cmd.exe from key SOFTWARE\Microsoft\Command Processor
 | autostart app and service from key SOFTWARE\Microsoft\Windows\CurrentVersion\Run
 | autostart app and service from key SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

[+] Collected network connections (ethernet, wifi, VPN)
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
 
[+] Output files
 | reports/profile_host_host_info.csv
 | reports/profile_host_local_users.csv
 | reports/profile_host_applications.csv
 | reports/profile_host_autoruns.csv
 | reports/profile_host_networks.csv
 | reports/profile_host_usb.csv
 | reports/timeline.csv


real	0m15.904s
user	0m10.194s
sys	  0m5.697s

```

### Windows User hive profiling
```
$ time py_facs scripts windows profile_users -d reports/ -o csv --huser NTUSER_CLEAN stack 
[+] Analyzing registry hive for user stack ..... done.

[+] Collected RDP connections
 | destination servers from key HKU\software\Microsoft\Terminal Server Client\Default
 | username from subkeys of HKU\software\Microsoft\Terminal Server Client\Servers

[+] Collected connections to network shares and USB devices
 | from HKU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2

[+] Collected autostart services and applications
 | shell value at logon from key NTUSER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
 | commands executed at each run of cmd.exe from key NTUSER\Software\Microsoft\Command Processor
 | autostart app and service from key NTUSER\Software\Microsoft\Windows\CurrentVersion\Run
 | autostart app and service from key NTUSER\Software\Microsoft\Windows\CurrentVersion\RunOnce

[+] Collected applications executed by the user
 | from key HKU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store

[+] Collected Cloud accounts and synchronisation information
 | Microsoft accounts from subkeys of HKU\Software\Microsoft\IdentityCRL\UserExtendedProperties
 | Google DriveFS from key HKU\Software\Google\DriveFS\Share
 | Google Backup and Sync from key HKU\Software\Google\Drive
 | OneDrive personal from key HKU\Software\Microsoft\OneDrive\Accounts\Personal
 | OneDrive for Business from key HKU\\Software\Microsoft\OneDrive\Accounts\Business1

[+] Output files for user stack
 | reports/profile_user_stack_rdp_connections.csv
 | reports/profile_user_stack_usb_shares_usage.csv
 | reports/profile_user_stack_autoruns.csv
 | reports/profile_user_stack_applications.csv
 | reports/profile_user_stack_cloud_accounts.csv


real	0m0.462s
user	0m0.260s
sys	  0m0.035s
```

### Windows evtx extraction
Note about 'dropped events': some events are retrieved by `libevtx` but the xml string cannot be parsed as a DOM document because of missing namespace.
```
$ py_facs scripts windows extract_evtx -e mnt/Windows/System32/winevt/Logs/ -d forensic/facs/ | tee forensic/facs/extract_evtx.log
[+] Extracting events from mnt/Windows/System32/winevt/Logs/Microsoft-Windows-Diagnosis-Scripted%4Admin.evtx ...  done (6 events extracted, 0 dropped)
[+] Extracting events from mnt/Windows/System32/winevt/Logs/AMSI%4Operational.evtx ...  done (0 events extracted, 0 dropped)
[+] Extracting events from mnt/Windows/System32/winevt/Logs/Application.evtx ...  done (3150 events extracted, 0 dropped)
[+] Extracting events from mnt/Windows/System32/winevt/Logs/HardwareEvents.evtx ...  done (0 events extracted, 0 dropped)
...
[+] Extracting events from mnt/Windows/System32/winevt/Logs/Security.evtx ...  done (7732 events extracted, 0 dropped)
[+] Extracting events from mnt/Windows/System32/winevt/Logs/System.evtx ...  done (3934 events extracted, 0 dropped)
[+] Extracting events from mnt/Windows/System32/winevt/Logs/Windows PowerShell.evtx ...  done (24 events extracted, 0 dropped)

[+] Wrote results (129325 events, 7936 dropped) in forensic/facs/evtx.json


real	0m58.454s
user	0m57.876s
sys	  0m0.272s
```

The resulting ndjson contains all keys from EventData/ProcessingErrorData/UserData. For instance, on an EID 4624, it looks like:
```
{
  "raw": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\n  <System>\n    <Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"{54849625-5478-4994-A5BA-3E3B0328C30D}\"/>\n    <EventID>4624</EventID>\n    <Version>2</Version>\n    <Level>0</Level>\n    <Task>12544</Task>\n    <Opcode>0</Opcode>\n    <Keywords>0x8020000000000000</Keywords>\n    <TimeCreated SystemTime=\"2018-01-08T13:55:13.409186900Z\"/>\n    <EventRecordID>48623</EventRecordID>\n    <Correlation/>\n    <Execution ProcessID=\"772\" ThreadID=\"5012\"/>\n    <Channel>Security</Channel>\n    <Computer>DESKTOP-SOI9AFH</Computer>\n    <Security/>\n  </System>\n  <EventData>\n    <Data Name=\"SubjectUserSid\">S-1-5-18</Data>\n    <Data Name=\"SubjectUserName\">DESKTOP-SOI9AFH$</Data>\n    <Data Name=\"SubjectDomainName\">WORKGROUP</Data>\n    <Data Name=\"SubjectLogonId\">0x00000000000003e7</Data>\n    <Data Name=\"TargetUserSid\">S-1-5-21-3001495921-1769015868-3887507880-1001</Data>\n    <Data Name=\"TargetUserName\">stackinit@outlook.com</Data>\n    <Data Name=\"TargetDomainName\">MicrosoftAccount</Data>\n    <Data Name=\"TargetLogonId\">0x0000000000bd46d1</Data>\n    <Data Name=\"LogonType\">7</Data>\n    <Data Name=\"LogonProcessName\">Negotiat</Data>\n    <Data Name=\"AuthenticationPackageName\">Negotiate</Data>\n    <Data Name=\"WorkstationName\">DESKTOP-SOI9AFH</Data>\n    <Data Name=\"LogonGuid\">{00000000-0000-0000-0000-000000000000}</Data>\n    <Data Name=\"TransmittedServices\">-</Data>\n    <Data Name=\"LmPackageName\">-</Data>\n    <Data Name=\"KeyLength\">0</Data>\n    <Data Name=\"ProcessId\">0x0000000000000304</Data>\n    <Data Name=\"ProcessName\">C:\\Windows\\System32\\lsass.exe</Data>\n    <Data Name=\"IpAddress\">-</Data>\n    <Data Name=\"IpPort\">-</Data>\n    <Data Name=\"ImpersonationLevel\">%%1833</Data>\n    <Data Name=\"RestrictedAdminMode\">-</Data>\n    <Data Name=\"TargetOutboundUserName\">-</Data>\n    <Data Name=\"TargetOutboundDomainName\">-</Data>\n    <Data Name=\"VirtualAccount\">%%1843</Data>\n    <Data Name=\"TargetLinkedLogonId\">0x0000000000bd4674</Data>\n    <Data Name=\"ElevatedToken\">%%1843</Data>\n  </EventData>\n</Event>\n",
  "datetime": "2018-01-08 13:55:13.409186+00:00",
  "channel": "Security",
  "provider": "Microsoft-Windows-Security-Auditing",
  "eid": "4624",
  "computer": "DESKTOP-SOI9AFH",
  "writer_sid": "",
  "SubjectUserSid": "S-1-5-18",
  "SubjectUserName": "DESKTOP-SOI9AFH$",
  "SubjectDomainName": "WORKGROUP",
  "SubjectLogonId": "0x00000000000003e7",
  "TargetUserSid": "S-1-5-21-3001495921-1769015868-3887507880-1001",
  "TargetUserName": "account@outlook.com",
  "TargetDomainName": "MicrosoftAccount",
  "TargetLogonId": "0x0000000000bd46d1",
  "LogonType": "7",
  "LogonProcessName": "Negotiat",
  "AuthenticationPackageName": "Negotiate",
  "WorkstationName": "DESKTOP-SOI9AFH",
  "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
  "TransmittedServices": "-",
  "LmPackageName": "-",
  "KeyLength": "0",
  "ProcessId": "0x0000000000000304",
  "ProcessName": "C:\\Windows\\System32\\lsass.exe",
  "IpAddress": "-",
  "IpPort": "-",
  "ImpersonationLevel": "%%1833",
  "RestrictedAdminMode": "-",
  "TargetOutboundUserName": "-",
  "TargetOutboundDomainName": "-",
  "VirtualAccount": "%%1843",
  "TargetLinkedLogonId": "0x0000000000bd4674",
  "ElevatedToken": "%%1843",
  "timestamp": 1515419713.409186,
  "source": "log_evtx",
  "tags": [
    "authn"
  ]
}

```