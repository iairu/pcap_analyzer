"""
IPv4 Analysis.
"""
from _byte import delim, btoi, btoIPv4
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

        self.ip_src = _data[12:16] # 12-15 bajt (4B)
        self.ip_dst = _data[16:20] # 16-19 bajt (4B)
        self.data = _data[20:] # 20+ bajt
        return

    def output(self):
        self.print()
        return

    def print(self):
        print(f"IPv4")
        print(f"\_ Protocol:          0x{self.protocol.hex()} [{self.protocol_str}]")
        print(f"\_ Source IP:         {delim(self.ip_src)} [{btoIPv4(self.ip_src)}]")
        print(f"\_ Dest   IP:         {delim(self.ip_dst)} [{btoIPv4(self.ip_dst)}]")
        return

class AnalyzeAfterIP:
    """ TCP, UDP and ICMP analysis """


    def str_tcp(self, code: int) -> str:
        return self._ports.str_tcp(code)

    def str_udp(self, code: int) -> str:
        return self._ports.str_udp(code)

    def str_icmp(self, code: int) -> str:
        return self._ports.str_icmp(code)

    def __init__(self, _data: bytes, _protocol_str: str, _ports: Protocols):
        self._ports = _ports

        self.unsupported = False
        self.protocol_str = _protocol_str

        if (_protocol_str in ["TCP","UDP"]): # TCP, UDP
            self.port_src = btoi(_data[0:2])
            self.port_dst = btoi(_data[2:4])

            if (_protocol_str == "TCP"): # TCP
                # first half of the 12th byte, byte has 8 bits, to keep first half, shift right by 4
                # the actual length of the header is "the first half" multiplied by 4, minimum being "5" * 4 = 20bytes
                self.header_len = (_data[12] >> 4) * 4 # single byte is int by default, no need to call btoi()
                self.data = _data[self.header_len:]
                # todo: flags?
            elif (_protocol_str == "UDP"): # UDP
                self.header_len = 8 # should always be 8
                self.data = _data[8:]

        elif (_protocol_str == "ICMP"): # ICMP
            self.type = _data[0]
            self.code = _data[1]
        else:
            self.unsupported = True
        return

    def output(self):
        self.print()
        return

    def print(self):
        if (self.unsupported):
            print(f"Unsupported protocol\n\_ Only TCP/UDP/ICMP analysis supported.")
            return

        print(f"{self.protocol_str}")
        if (self.protocol_str == "TCP"):
            print(f"\_ Source Port:       {self.port_src} [{self.str_tcp(self.port_src)}]")
            print(f"\_ Dest   Port:       {self.port_dst} [{self.str_tcp(self.port_dst)}]")
            print(f"\_ Header len:        {self.header_len} B")
            print(f"\_ (Data length):     {len(self.data)}")
        elif (self.protocol_str == "UDP"):
            print(f"\_ Source Port:       {self.port_src} [{self.str_udp(self.port_src)}]")
            print(f"\_ Dest   Port:       {self.port_dst} [{self.str_udp(self.port_dst)}]")
            print(f"\_ Header len:        {self.header_len} B always")
            print(f"\_ (Data length):     {len(self.data)}")
        elif (self.protocol_str == "ICMP"):
            print(f"\_ Type:              {self.type} [{self.str_icmp(self.type)}]")
            print(f"\_ Code:              {self.code}")

        return