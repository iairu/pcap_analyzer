"""
ARP Analysis.
"""
from _byte import btoi, btoIPv4
from _reader import Protocols

class AnalyzeARP:
    def __init__(self, _data: bytes, _protocols: Protocols):
        self.str_arp_opcode = _protocols.str_arp_opcode

        self.opcode = _data[20-14:22-14]
        self.ip_src = _data[28-14:32-14]
        self.ip_dst = _data[38-14:42-14]
        return

    def output(self, out):
        arp_opcode = self.str_arp_opcode(btoi(self.opcode))
        if (arp_opcode != "Unknown"):
            out["arp_opcode"] = arp_opcode
        out["src_ip"] = btoIPv4(self.ip_src)
        out["dst_ip"] = btoIPv4(self.ip_dst)
        return out