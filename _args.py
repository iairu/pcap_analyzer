"""
Argument parsing (incl. help) for CLI usage.
Also holds the parsed arguments within self (class).
First thing that the CLI should work with really...

"""
from _close import *
import os
import argparse

class Args:
    """Contains all parsed arguments as attributes."""
    def __init__(self):
        # Argument definition
        argparser = argparse.ArgumentParser(description="PCAP Network Analyzer (PKS) - Ondrej Spanik 2021 - github.com/iairu")
        argparser.add_argument("path",type=str, help="Path to a *.pcap file, from which to read network packets")
        argparser.add_argument("-count", "-c", type=int, help="Number of packets to read (default:-1 = all)")

        # Parsing
        arguments = argparser.parse_args()

        # Checking user input (note: python has a weird way of doing ternary)
        _path = str(arguments.path if os.path.isfile(arguments.path) else close(Code.INCORRECT_ARG_PATH))
        if not _path.endswith(".pcap"): close(Code.INCORRECT_ARG_PATH)

        _count = int(-1 if (arguments.count == None) else arguments.count) # -1 means all for compatibility with scapy
        if (_count < -1): close(Code.INCORRECT_ARG_COUNT)

        # Returning all parsed arguments
        self.path = _path
        self.count = _count