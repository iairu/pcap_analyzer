"""
Saved analyzed frame
"""

from _args import Args
from _analyze import Analyze
from _analyze_ip import AnalyzeIP
from _analyze_t import AnalyzeTransport
from _reader import Protocols
import _byte as byte

class Frame:
    def __init__(self, frame_no: int, pkt: bytes, protocols: Protocols):
        self.frame_no = frame_no
        self.pkt = pkt
        self.protocols = protocols
        self.anal = None
        self.anal_ip = None
        self.anal_t = None
        return

    def analyzeAll(self):
        # ETH Analysis
        self.anal = Analyze(self.pkt, self.protocols)

        # IPv4 Analysis
        if (self.anal.has_eth_type and byte.btoi(self.anal.eth_type) == 0x800):
            self.anal_ip = AnalyzeIP(self.anal.data, self.protocols)

        # TCP/UDP/ICMP analysis (Transport layer)
        if (self.anal_ip != None):
            self.anal_t = AnalyzeTransport(self.anal_ip.data, self.anal_ip.protocol_str, self.protocols)
        return

    def output(self):
        self.print()
        return

    def printHexDump(self):
        # Hexdump by default
        byte.printHexDump(self.pkt)
        return

    def print(self):
        print("_______")
        print("Frame #" + str(self.frame_no) + ":")

        # Analysis printing
        if (self.anal != None): self.anal.print()
        if (self.anal_ip != None): self.anal_ip.print()
        if (self.anal_t != None): self.anal_t.print()
        return