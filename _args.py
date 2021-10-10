"""
Argument parsing (incl. help) for CLI usage.
Also holds the parsed arguments within self (class).
First thing that the CLI should work with really...

"""
from _close import *
import argparse

class Args:
    """Contains all parsed arguments as attributes."""
    def __init__(self):
        # Argument definition
        argparser = argparse.ArgumentParser(description="PCAP Network Analyzer (PKS) - Ondrej Spanik 2021 - github.com/iairu")
        argparser.add_argument("path", type=open, help="Path to a *.pcap file, from which to read network packets")
        argparser.add_argument("-c", type=int, help="Number of packets to read (default:0 = all)")

        # Parsing + Exception conversion to human readable
        try:
            arguments = argparser.parse_args()
        except FileNotFoundError:
            close(Code.INCORRECT_ARG_PATH)

        # Checking user input
        count = 0 if (arguments.c == None) else arguments.c # note: python has a weird way of doing ternary
        if (count < 0): close(Code.INCORRECT_ARG_COUNT)

        # Returning all parsed arguments
        self.path = arguments.path # todo not really path but opened file curently, depending on scapy support this may have to be changed
        self.count = count