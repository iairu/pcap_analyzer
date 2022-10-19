"""
IPv4 Analysis including parts of IPv4 header specific to ICMP analysis
"""
from _byte import zeroPrefix, delim, btoi, itobin, btoIPv4
from _reader import Protocols

class AnalyzeIP:
    """ It is expected that IPv4 has already been detected and passed _data starts with an IPv4 header"""
        
    # ------------------------------------------

    def str_ip(self, code: int) -> str:
        return self._protocols.str_ip(code)

    def __init__(self, _data: bytes, protocols: Protocols):
        self._protocols = protocols

        self.protocol = _data[9:10] # 6.bajt od zaciatku IPv4 (1B)
        self.protocol_str = self.str_ip(btoi(self.protocol))

        self.id = btoi(_data[18-14:20-14])

        flags_and_offset = _data[20-14:22-14]
        # flags_and_offset_binary = zeroPrefix(str(bin(btoi(flags_and_offset)))[2:],16) 
        self.flags_and_offset_binary = zeroPrefix(itobin(btoi(flags_and_offset)),16) 
        # /\ first removes 0b from binary string, then fixes python behavior with prefixed 0s to match length of input bytes, which was 16
        self.flags_mf = self.flags_and_offset_binary[2] == "1" # extract the third bit only as bool
        self.frag_offset = int("0b" + self.flags_and_offset_binary[3:] + "000",2) # remove first three bits, adjust offset, save as binary string and convert to int

        self.ip_src = _data[12:16] # 12-15 bajt (4B)
        self.ip_dst = _data[16:20] # 16-19 bajt (4B)
        self.data = _data[20:] # 20+ bajt
        return

    def output(self, out):
        out["src_ip"] = btoIPv4(self.ip_src)
        out["dst_ip"] = btoIPv4(self.ip_dst)
        if (btoi(self.protocol) == 0x01): # parts specific to ICMP analysis
            # only handle fragmentation for ICMP
            out["id"] = self.id
            out["flags_mf"] = self.flags_mf
            out["frag_offset"] = self.frag_offset
            out["protocol"] = self.protocol_str
        else:
            out["protocol"] = self.protocol_str
        return out

    def print(self):
        print(f"IPv4")
        print(f"\_ Protocol:          0x{self.protocol.hex()} [{self.protocol_str}]")
        print(f"\_ Source IP:         {delim(self.ip_src)} [{btoIPv4(self.ip_src)}]")
        print(f"\_ Dest   IP:         {delim(self.ip_dst)} [{btoIPv4(self.ip_dst)}]")
        return