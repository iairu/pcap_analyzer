"""
IPv4 Analysis.
"""
from _byte import delim, btoIPv4

class AnalyzeIP:
    """ It is expected that IPv4 has already been detected and passed _data starts with an IPv4 header"""

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
        print(f"\_ Protocol:          0x{self.protocol.hex()} [TODO]") # todo dict, later file
        print(f"\_ Source IP:         {delim(self.ip_src)} [{btoIPv4(self.ip_src)}]")
        print(f"\_ Destin IP:         {delim(self.ip_dst)} [{btoIPv4(self.ip_dst)}]")
        return