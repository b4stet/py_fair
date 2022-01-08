# py_fair (Forensic Automation for Incident Response)

Some scripts and cheat sheets around digital forensic analysis.


## Requirements
```
$ python3 -m venv fair_env
$ source ./fair_env/bin/activate
$ python -m pip install pip wheel setuptools --upgrade
$ pip3 install -r requirements.txt
```

It also requires some system utilities:
- `sort`
- `cut`

## Install
```
$ source ./fair_env/bin/activate
$ pip3 install .
```

## Uninstall
```
$ pip3 uninstall py_fair
```

## Usage
Every command and subcommand have a helper.
If installed with pip3:
```
$ py_fair
$ py_fair <command> --help
$ py_fair <command> <subcommand> --help
```

Otherwise, from the project root:
```
$ python3 -m fair.cli
$ python3 -m fair.cli <command> --help
$ python3 -m fair.cli <command> <subcommand> --help
```

### Cheat Sheets Commands
- `library`: blogs, tools, various knowledge bases, notable cves, ...
- `tools`: cheat sheets for some tools like tsk, plaso, tshark, volatility, ...
- `systems`: some notes about operating systems
- `logs`: cheat sheets of some log paths, Windows artifacts ...
- `acquisition`: cheat sheets for operations related to data acquisition (info, dump disk/memory, mount)
- `carving`: cheat sheets to carve allocated and unallocated blocks, ...
- `preprocessing`: cheat sheets to prepare data to be analyzed, time intensive tasks
- `processing`: cheat sheets for mining, default values, attacker toolbox patterns, some possible traces per mitre tactic

### Scripts Commands
- `nsrl`: set of scripts to extract OS and office related files (known goods), to then filter on a disk timeline
- `windows`: set of scripts to automate some parts of the forensics (eg. profiling host and users, extract evtx, assemble for timesketch)
- `report`: set of scripts to export csv results in an ODS file

As data volume can be huge for some artifacts, specific formats are enforced to "stream" files instead of loading them fully in memory.  
When this is required, the helper of the command indicates the expected format.

### About export to ODS
The ODF format was preferred to Open XML one due to issues with xlsx files opened in LibreOffice.
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
    - this property is not handled by the code, hence it will break the columns computation
