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
        argparser.add_argument("-s", "--sort-app-protocol", type=str, help="Retrieve sorted TCP/UDP communication for given protocol name (see tcp_ports.txt, udp_ports.txt)")
        argparser.add_argument("-ss", "--sort-short", action="store_true", help="Only output the first frame of TCP/UDP communication, use in conjunction with -s")
        argparser.add_argument("-cp", "--count-protocol", type=str, help="Packets on given app protocol will be counted instead (only RIP supported right now)")
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

        _sort_app_protocol = "" if (arguments.sort_app_protocol == None) else str(arguments.sort_app_protocol)

        _sort_short = bool(arguments.sort_short)
        if (_sort_short == True and _sort_app_protocol == ""): 
            close(Code.SS_MISSING_ARG_PAIR)

        _count_protocol = "" if (arguments.count_protocol == None) else str(arguments.count_protocol)

        # Returning all parsed arguments
        self.path = _path
        self.first = _first
        self.count = _count
        self.count_protocol = _count_protocol
        self.sort_app_protocol = _sort_app_protocol
        self.sort_short = _sort_short
        self.no_hexdump = bool(arguments.no_hexdump)
        self.no_leaderboard = bool(arguments.no_leaderboard)