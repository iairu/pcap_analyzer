"""
The actual analysis of an individual packet using bytecode until output.
"""
from _byte import delim

class Analyze:
    def __init__(self, _bytes: bytes):
        self.eth_dst = _bytes[0:6]
        self.eth_src = _bytes[6:12]
        return

    def output(self):
        self.print()
        return

    def print(self):
        print(f"Packet length WIRE:   TODO")
        print(f"Packet length API:    TODO")
        print(f"?ETH Standard?:       TODO")
        print(f"\_ Destin MAC:        {delim(self.eth_dst)}")
        print(f"\_ Source MAC:        {delim(self.eth_src)}")
        print(f"\_ Type, Trailer:     TODO, TODO")
        print(f"LLC:                  TODO")
        print(f"\_ DSAP, SSAP:        TODO, TODO")
        print(f"\_ CField, Protocol:  TODO, TODO")
        print(f"TODO...")
        return