## File/folder hierarchy

| File/Folder   | Explanation                                                  |
| ------------- | ------------------------------------------------------------ |
| `__main__.py` | Where all the parts come together<br />- Loads entered and checked arguments<br />- Passes PCAP path to `scapy` to retrieve an array of packets<br />- Loops over the array analyzing all packets, output based on flags |
| `_analyze.py` | The main point of this project.<br />Class `Analyze`<br />- Init: Gets a packet as a byte sequence, analyzes it<br />- All analyzed parts are accessible as attributes |
| `_args.py`    | The first thing that really runs<br />- Defines possible arugments and flags that `__main__.py` can be ran with<br /><br />- Processes arguments using `argparse`<br />- Checks arguments / flags for errors |
| `_byte.py`    | Utilites for working with bytes<br />- Delimiting function (for example for MAC addresses)<br />- Bytes to Int function (builtin to Python only on newest versions, so I made my own)<br />- Hexdump function with configurable offset and byte count per row |
| `_close.py`   | An output for user-caused and user-readable errors, incl. exit codes<br />- Used for unfixable errors caused by user<br />- Not used for errors caused by developer / bugs |

