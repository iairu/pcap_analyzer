"""
Transport layer TCP, UDP analysis incl. Network layer ICMP analysis
"""
from _byte import btoi, itobin, zeroPrefix
from _reader import Protocols


class AnalyzeTransport:
    """ TCP, UDP and ICMP analysis """

    def str_tcp(self, code: int) -> str:
        return self._ports.str_tcp(code)

    def str_udp(self, code: int) -> str:
        return self._ports.str_udp(code)

    def str_icmp(self, code: int) -> str:
        return self._ports.str_icmp(code)

    def __init__(self, _data: bytes, _protocol_str: str, _ports: Protocols):
        self._ports = _ports

        self.unsupported = False # if unsupported protocol
        self.protocol_str = _protocol_str

        self.port_src = None
        self.port_dst = None
        self.header_len = None
        self.flags = None
        self.flags_str = None
        self.type = None
        self.data = None
        self.code = None

        if (_protocol_str in ["TCP","UDP"]): # TCP, UDP
            self.port_src = btoi(_data[0:2])
            self.port_dst = btoi(_data[2:4])

            if (_protocol_str == "TCP"): # TCP
                # first half of the 12th byte, byte has 8 bits, to keep first half, shift right by 4
                # the actual length of the header is "the first half" multiplied by 4, minimum being "5" * 4 = 20bytes
                self.header_len = (_data[12] >> 4) * 4 # single byte is int by default, no need to call btoi()
                self.data = _data[self.header_len:]

                nonce_mask = 15 # 00001111
                self.flags = bytes([
                    (nonce_mask & _data[12]), # last 4 bits of the first byte only (the first 4 were header_len) for reserved/nonce
                    _data[13] # 13th byte for CWR,ECN,Urgent,ACK,PUSH,RST,SYN,FIN
                    ])

                self.flags_str = zeroPrefix(itobin(btoi(self.flags)),12) # get a 12bit binary string of active flags
            elif (_protocol_str == "UDP"): # UDP
                self.header_len = 8 # should always be 8
                self.data = _data[8:]

        elif (_protocol_str == "ICMP"): # ICMP
            self.type = _data[0]
            self.code = _data[1]
        else:
            self.unsupported = True
        return

    def tcp_flags_to_name(self):
        if (self.flags_str == None):
            return "Undefined flags_str"

        names = {
            0: "Reserved1",
            1: "Reserved2",
            2: "Reserved3",
            3: "Nonce",
            4: "CWR",
            5: "ECN-Echo",
            6: "Urgent",
            7: "ACK",
            8: "PUSH",
            9: "RST",
            10: "SYN",
            11: "FIN"
        }

        active = [] # all active possibilities from names

        # get all active
        for i,b in enumerate(self.flags_str):
            if (b == "1"):
                active.append(names[i])

        return ", ".join(active) # all active names, comma separated

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
            print(f"\_ Flags:             0x{self.flags.hex()} [{self.flags_str} - {self.tcp_flags_to_name()}]")
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