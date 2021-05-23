# py_facs (Forensic Automation and Cheat Sheets)

Some wrappers and cheat sheets around common operations in a digital forensic analysis on a debian based GNU/Linux distribution.  

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
- `acquisition`: cheat sheets for operations related to data acquisition (info about disks, dump disk/memory, mount)
- `logs`: cheat sheet of interesting fields depending on the source
- `resources`: blogs, tools, various knowledge bases, notable cves, ...

