"""
IPv4 Analysis.
"""
from _byte import delim, btoi, btoIPv4

class AnalyzeIP:
    """ It is expected that IPv4 has already been detected and passed _data starts with an IPv4 header"""

    class __Dict__:
        protocols = { # todo: nacitat zo suboru
            0x01: "ICMP",
            0x02: "IGMP",
            0x06: "TCP",
            0x09: "IGRP",
            0x11: "UDP",
            0x2F: "GRE",
            0x32: "ESP",
            0x33: "AH",
            0x39: "SKIP",
            0x58: "EIGRP",
            0x59: "OSPF",
            0x73: "L2TP"
        }
        
    # ------------------------------------------

    def str_protocol(self, code: int) -> str:
        return self.__Dict__.protocols.get(code, "Unknown Protocol")

    def __init__(self, _data: bytes):
        self.protocol = _data[9:10] # 6.bajt od zaciatku IPv4 (1B)
        self.ip_src = _data[12:16] # 12-15 bajt (4B)
        self.ip_dst = _data[16:20] # 16-19 bajt (4B)
        return

    def output(self):
        self.print()
        return

    def print(self):
        print(f"IPv4")
        print(f"\_ Protocol:          0x{self.protocol.hex()} [{self.str_protocol(btoi(self.protocol))}]")
        print(f"\_ Source IP:         {delim(self.ip_src)} [{btoIPv4(self.ip_src)}]")
        print(f"\_ Dest   IP:         {delim(self.ip_dst)} [{btoIPv4(self.ip_dst)}]")
        return