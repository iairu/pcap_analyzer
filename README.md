# PCAP Analyzer FIN

**Ondrej Spanik** (iairu.com)

Use at least Python 3.7

## Setup virtual env.

Local environment for Python in root directory of this project:

```
python -m venv .
```

This way all PIP packages will be installed directly into the folder of choice and not globally, similar to Node.js projects.

**Make sure to activate your virtual environment** and check that it has properly activated on any new terminal in your project!

### Activation

After opening any terminal where you would like to work with the project (run, install packages, etc.), make sure to use an activation script:

​	**Windows CMD:** `Scripts\activate.bat`

​	**Windows PowerShell:** `Scripts\activate.ps1`

​	**Bash:** `source Scripts/activate`

### Activation check

If you aren't sure whether the virtual environment has activated using the methods above in your current terminal instance use:

```
where pip
```

Which should point you to *./Scripts/pip*. If it doesn't, try running another activation script in the folder. Same thing goes for `where python`, ...

### VSCode auto-activate

Then VSCode setup of Python local environment that will guarantee auto-activation of venv on all subsequent new terminal instances:

> Ctrl+Shift+P - Select interpreter - Select Interpreter path - *Open the ./Scripts/python (generated by venv) directory*

## Package dependencies

Package installation recommended AFTER virtual env. setup and activated (*check using `where pip`*), as not to saturate your global packages.

```
pip install scapy[complete]
```

Not all of the aforementioned packages are used in their entirety, but they're available just in case.

### Package version check

In case of incompatibilities, detailed information about package versions in `requirements.txt` generated using `pip freeze > requirements.txt`. 

Most of these packages are installed as dependencies automatically.

## Run

Make sure to activate VENV. See "Activation".

To analyze all frames within a .pcap file and print all hexdumps followed by analysis results, simply use:
```
python __main__.py [path to pcap]
```

### Flags and help

To get a list of up-to-date flags use `-h`

```
python __main__.py -h
```
Here are some useful flags:

- To set starting frame use `-f` (or `--first`).
- To limit frames read and analyzed use `-c` (or `--count`).
- To hide hexdumps use `--no-hexdump`.
- To not calculate and hide sender leaderboard use `--no-leaderboard`.

### Performance concerns

Performance is mainly impacted by `argparse`, which seems to add at least a second long delay on launch.

This can be observed by simply running without any pcap file.

## File/folder hierarchy

| File/Folder   | Explanation                                                  |
| ------------- | ------------------------------------------------------------ |
| `__main__.py` | Where all the parts come together<br />- Loads entered and checked arguments<br />- Passes PCAP path to `scapy` to retrieve an array of packets<br />- Loops over the array analyzing all packets, output based on flags |
| `_analyze.py` | The main point of this project.<br />Class `Analyze`<br />- Init: Gets a packet as a byte sequence, analyzes it<br />- All analyzed parts are accessible as attributes |
| `_args.py`    | The first thing that really runs<br />- Defines possible arugments and flags that `__main__.py` can be ran with<br /><br />- Processes arguments using `argparse`<br />- Checks arguments / flags for errors |
| `_byte.py`    | Utilites for working with bytes<br />- Delimiting function (for example for MAC addresses)<br />- Bytes to Int function (builtin to Python only on newest versions, so I made my own)<br />- Hexdump function with configurable offset and byte count per row |
| `_close.py`   | An output for user-caused and user-readable errors, incl. exit codes<br />- Used for unfixable errors caused by user<br />- Not used for errors caused by developer / bugs |

## Build

Build using pyinstaller, first `pip install pyinstaller`, then run `pyinstaller -F __main__.py` in root directory with VENV activated, which will output `__main__.exe` binary into `dist` folder. Make sure to copy `protocols` folder into the dist folder to include with built binary.