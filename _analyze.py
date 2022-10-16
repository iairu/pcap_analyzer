"""
The actual analysis of an individual packet using bytes until output.
"""
from _byte import delim, btoi
from _reader import Protocols


class Analyze:
    """ The actual analysis of an individual packet using bytes until output. """
    class Eth_stds:
        """ Supported Ethernet Standards """
        UNKNOWN = "Unknown"
        IEEE_802_3_RAW = "IEEE 802.3 RAW"
        IEEE_802_3_LLCSNAP = "IEEE 802.3 LLC & SNAP"
        IEEE_802_3_LLC = "IEEE 802.3 LLC"
        ETHERNET2 = "Ethernet II"

    # ------------------------------------------

    def str_sap(self, code: int) -> str:
        return self._protocols.str_sap(code)

    def str_eth_type(self, code: int): 
        return self._protocols.str_eth_type(code)

    def str_pid(self, code: int): 
        return self._protocols.str_pid(code)

    def __init__(self, _bytes: bytes, protocols: Protocols):
        self._protocols = protocols
        
        self.eth_std = self.Eth_stds.UNKNOWN
        self.has_eth_type: bool = False
        self.len: int = len(_bytes)
        self.wirelen: int = 64 if (self.len <= 60) else self.len + 4
        # self.is_ipx: bool = False

        # DATA LINK HEADER
        # \_ MAC
        self.eth_dst = _bytes[0:6] # 0-5 bajt (6B) # todo: isl kontrolovat uz tu
        self.eth_src = _bytes[6:12] # 6-11 bajt (6B)

        # \_ LENGTH + STANDARD || ETHERTYPE
        len_or_type = btoi(_bytes[12:14]) # 12-13 bajt (2B)
        if (len_or_type <= 1500):
            self.eth_len = _bytes[12:14]

            # STANDARD
            dsap_or_raw = _bytes[14:16].hex() # 14-15 bajt (2B)
            # 802.3 RAW                     0xFFFF
            # 802.2 SNAP (== LLC + SNAP)    0xAAAA
            # 802.2 LLC                     0x____
            if (dsap_or_raw == "ffff"):
                self.eth_std = self.Eth_stds.IEEE_802_3_RAW
            elif (dsap_or_raw == "aaaa"):
                self.eth_std = self.Eth_stds.IEEE_802_3_LLCSNAP
            else:
                self.eth_std = self.Eth_stds.IEEE_802_3_LLC

        elif (len_or_type >= 1536):
            self.eth_std = self.Eth_stds.ETHERNET2
            self.eth_type = _bytes[12:14]
            self.has_eth_type = True
            self.data = _bytes[14:] # 14 bajt po koniec
            return
        else:
            self.eth_std = self.Eth_stds.UNKNOWN
            self.data = _bytes[14:] # assumed
            return

        # LOGICAL LINK HEADER +
        # if (self.eth_std == self.Eth_stds.IEEE_802_3_RAW):
        #     self.is_ipx = True if (_bytes[14:16].hex() == "ffff") else False # ffff checksum 14-15 bajt (2B)    # <--- obvious if RAW
        if (self.eth_std == self.Eth_stds.IEEE_802_3_LLC or self.eth_std == self.Eth_stds.IEEE_802_3_LLCSNAP):
            self.dsap = _bytes[14:15] # (1B)
            self.ssap = _bytes[15:16] # (1B)
            self.control = _bytes[16:17] # (1B)
            # SNAP HEADER
            if (self.eth_std == self.Eth_stds.IEEE_802_3_LLCSNAP):
                # ISL check/fix
                isl_offset = 0
                if (delim(self.eth_dst) in ["01:00:0c:00:00:00","03:00:0c:00:00:00"]):
                    isl_offset = 26 # posun kvoli ISL
                    self.eth_dst = _bytes[0+isl_offset:6+isl_offset] # 0-5 bajt (6B)
                    self.eth_src = _bytes[6+isl_offset:12+isl_offset] # 6-11 bajt (6B)
                # all LLC+SNAP cases
                self.vendor_code = _bytes[17+isl_offset:20] # 17-19 bajt (3B)
                self.eth_type = _bytes[20+isl_offset:22+isl_offset] # 20-21 bajt (2B)
                self.has_eth_type = True
                self.data = _bytes[22+isl_offset:] # 22 bajt po koniec
            else: # self.eth_std == self.Eth_stds.IEEE_802_3_LLC
                self.data = _bytes[17:] # 17 bajt po koniec
        return

    def output(self, out):
        # Packet output dictionary, this year's edition
        out["len_frame_pcap"] = self.len
        out["len_frame_medium"] = self.wirelen
        out["frame_type"] = self.eth_std
        out["src_mac"] = delim(self.eth_src)
        out["dst_mac"] = delim(self.eth_dst)

        if (self.eth_std == self.Eth_stds.ETHERNET2):
            ether_type = self.str_eth_type(btoi(self.eth_type))
            if (ether_type != "Unknown"):
                out["ether_type"] = ether_type
        else:
            if (self.eth_std == self.Eth_stds.IEEE_802_3_RAW):
                out["sap"] = "IPX"
            elif (self.eth_std == self.Eth_stds.IEEE_802_3_LLC):
                sap = self.str_sap(btoi(self.dsap))
                if (sap != "Unknown"):
                    out["sap"] = sap
            elif (self.eth_std == self.Eth_stds.IEEE_802_3_LLCSNAP):
                pid = self.str_pid(btoi(self.eth_type))
                if (pid != "Unknown"):
                    out["pid"] = pid

        return out

    def print(self):
        # Last year's edition
        print(f"Length WIRE / API:    {self.wirelen} B / {self.len} B")
        print(f"STANDARD:             {self.eth_std}")

        print(f"DATA LINK Header:")
        print(f"\_ Dest   MAC:        {delim(self.eth_dst)}")
        print(f"\_ Source MAC:        {delim(self.eth_src)}")

        if (self.eth_std == self.Eth_stds.ETHERNET2):
            print(f"\_ EthType:           0x{self.eth_type.hex()} [{self.str_eth_type(btoi(self.eth_type))}]")
        else:
            print(f"\_ Length:            0x{self.eth_len.hex()} [{btoi(self.eth_len)}]")
            if (self.eth_std == self.Eth_stds.IEEE_802_3_RAW):
                print(f"IPX")
            else:
                print(f"LOGICAL LINK Header:")
                print(f"\_ DSAP:              0x{self.dsap.hex()} [{self.str_sap(btoi(self.dsap))}]")
                print(f"\_ SSAP:              0x{self.ssap.hex()} [{self.str_sap(btoi(self.ssap))}]")
                print(f"\_ Control:           0x{self.control.hex()} [{btoi(self.control)}]")

            if (self.eth_std == self.Eth_stds.IEEE_802_3_LLCSNAP):
                print(f"SNAP Header:")
                print(f"\_ Vendor, EthType:   {delim(self.vendor_code)}, 0x{self.eth_type.hex()} [{self.str_eth_type(btoi(self.eth_type))}]")
        
        return