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
        argparser.add_argument("-f", "--first", type=int, help="Which frame to start from (default:1 = first)")
        argparser.add_argument("-c", "--count", type=int, help="Number of packets to read (default:-1 = all)")
        argparser.add_argument("--no-hexdump", action="store_true", help="Won't print hexdumps of any frame, otherwise all printed")
        argparser.add_argument("--no-leaderboard", action="store_true", help="Won't show or calculate top sender + leaderboard")

        # Parsing
        arguments = argparser.parse_args()

        # Checking user input (note: python has a weird way of doing ternary)
        _path = str(arguments.path if os.path.isfile(arguments.path) else close(Code.INCORRECT_ARG_PATH))
        if not _path.endswith(".pcap"): close(Code.INCORRECT_ARG_PATH)

        _first = int(1 if (arguments.first == None) else arguments.first)
        if (_first < 1): close(Code.INCORRECT_ARG_FIRST)

        _count = int(-1 if (arguments.count == None) else arguments.count) # -1 means all for compatibility with scapy
        if (_count < -1): close(Code.INCORRECT_ARG_COUNT)

        # Returning all parsed arguments
        self.path = _path
        self.first = _first
        self.count = _count
        self.no_hexdump = bool(arguments.no_hexdump)
        self.no_leaderboard = bool(arguments.no_leaderboard)