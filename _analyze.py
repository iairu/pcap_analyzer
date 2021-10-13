"""
The actual analysis of an individual packet using bytes until output.
"""
from _byte import delim, btoi


class Analyze:
    """ The actual analysis of an individual packet using bytes until output. """
    class Eth_stds:
        """ Supported Ethernet Standards """
        UNKNOWN = "Unknown"
        IEEE_802_3_RAW = "IEEE 802.3 RAW"           # todo: check 802.2 802.3 if correct minor ver.
        IEEE_802_2_LLCSNAP = "IEEE 802.2 LLC+SNAP"  # todo: check 802.2 802.3 if correct minor ver.
        IEEE_802_2_LLC = "IEEE 802.2 LLC"
        ETHERNET2 = "Ethernet II"

    class __Dict__:
        saps = { # todo: nacitat zo suboru
            0x00: "Null SAP",
            0x02: "LLC SM / Individual",
            0x03: "LLC SM / Group",
            0x06: "IP (DoDIP)",
            0x0E: "PROWAY Net",
            0x42: "BPDU / 802.1 STree",
            0x4E: "MMS",
            0x5E: "ISI IP",
            0x7E: "X.25 PLP (ISO 8208)",
            0x8E: "PROWAY ASL",
            0xAA: "SNAP",
            0xE0: "IPX",
            0xF4: "LAN Management",
            0xFE: "ISO Net Layer Protocols",
            0xFF: "Global DSAP"
        }
        eth_types = { # todo: nacitat zo suboru
            0x0200: "XEROX PUP",
            0x0201: "PUP Addr Trans",
            0x0800: "IPv4",
            0x0801: "X.75 Internet",
            0x0805: "X.25 Level 3",
            0x0806: "ARP",
            0x8035: "Reverse ARP",
            0x809B: "Appletalk",
            0x80F3: "AppleTalk AARP (Kinetics)",
            0x8100: "IEEE 802.1Q VLAN-tagged frames",
            0x8137: "IPX",
            0x86DD: "IPv6",
            0x880B: "PPP",
            0x8847: "MPLS",
            0x8848: "MPLS upstream label",
            0x8863: "PPPoE Discovery Stage",
            0x8864: "PPPoE Session Stage"
        }

    # ------------------------------------------

    def str_sap(self, code: int) -> str:
        return self.__Dict__.saps.get(code, "Unknown SAP")

    def str_eth_type(self, code: int) -> str:
        return self.__Dict__.eth_types.get(code,"Unknown ETH TYPE")

    def __init__(self, _bytes: bytes):
        self.eth_std = self.Eth_stds.UNKNOWN
        self.eth_lenint = -1
        self.eth_len_wireint = -1
        # self.is_ipx: bool = False

        # DATA LINK HEADER
        # \_ MAC
        self.eth_dst = _bytes[0:6] # 0-5 bajt (6B)
        self.eth_src = _bytes[6:12] # 6-11 bajt (6B)

        # \_ LENGTH + STANDARD || ETHERTYPE
        len_or_type = btoi(_bytes[12:14]) # 12-13 bajt (2B)
        if (len_or_type <= 1500):
            self.eth_len = _bytes[12:14]
            self.eth_lenint = btoi(self.eth_len)
            self.eth_len_wireint = 64 if (self.eth_lenint <= 60) else self.eth_lenint + 4 # todo: nesedi s wiresharkom

            # STANDARD
            dsap_or_raw = _bytes[14:16].hex() # 14-15 bajt (2B)
            # todo \/ kontrola wireshark spravnost flagov
            # 802.3 RAW                     0xFFFF
            # 802.2 SNAP (== LLC + SNAP)    0xAAAA
            # 802.2 LLC                     0x____
            if (dsap_or_raw == "ffff"):
                self.eth_std = self.Eth_stds.IEEE_802_3_RAW
            elif (dsap_or_raw == "aaaa"):
                self.eth_std = self.Eth_stds.IEEE_802_2_LLCSNAP
            else:
                self.eth_std = self.Eth_stds.IEEE_802_2_LLC

        elif (len_or_type >= 1536):
            self.eth_std = self.Eth_stds.ETHERNET2
            self.eth_type = _bytes[12:14]
            self.data = _bytes[14:] # 14 bajt po koniec
            
            self.eth_lenint = -1 # todo: manual calc i guess?
            self.eth_len_wireint = -1
            return
        else:
            self.eth_std = self.Eth_stds.UNKNOWN
            self.data = _bytes[14:] # assumed
            
            self.eth_lenint = -1 # todo: manual calc i guess?
            self.eth_len_wireint = -1
            return

        # LOGICAL LINK HEADER +
        # if (self.eth_std == self.Eth_stds.IEEE_802_3_RAW):
        #     self.is_ipx = True if (_bytes[14:16].hex() == "ffff") else False # ffff checksum 14-15 bajt (2B)    # <--- obvious if RAW
        if (self.eth_std == self.Eth_stds.IEEE_802_2_LLC or self.eth_std == self.Eth_stds.IEEE_802_2_LLCSNAP):
            self.dsap = _bytes[14:15] # (1B)
            self.ssap = _bytes[15:16] # (1B)
            self.control = _bytes[16:17] # (1B)
            # SNAP HEADER
            if (self.eth_std == self.Eth_stds.IEEE_802_2_LLCSNAP):
                self.vendor_code = _bytes[17:20] # 17-19 bajt (3B)
                self.eth_type = _bytes[20:22] # 20-21 bajt (2B)
                self.data = _bytes[22:] # 22 bajt po koniec
            else: # self.eth_std == self.Eth_stds.IEEE_802_2_LLC
                self.data = _bytes[17:] # 17 bajt po koniec
        return

    def output(self):
        self.print()
        return

    def print(self):
        print(f"Length WIRE / API:    {self.eth_len_wireint} / {self.eth_lenint}")
        print(f"STANDARD:             {self.eth_std}")

        print(f"DATA LINK Header:")
        print(f"\_ Dest   MAC:        {delim(self.eth_dst)}")
        print(f"\_ Source MAC:        {delim(self.eth_src)}")

        if (self.eth_std == self.Eth_stds.ETHERNET2):
            print(f"\_ EthType:           0x{self.eth_type.hex()} [{self.str_eth_type(btoi(self.eth_type))}]")
        else:
            print(f"\_ Length:            0x{self.eth_len.hex()} [{btoi(self.eth_len)}]")

            if (self.eth_std == self.Eth_stds.IEEE_802_3_RAW):
                """soon"""
                #print(f"IPX")
            else:
                print(f"LOGICAL LINK Header:")
                print(f"\_ DSAP:              0x{self.dsap.hex()} [{self.str_sap(btoi(self.dsap))}]")
                print(f"\_ SSAP:              0x{self.ssap.hex()} [{self.str_sap(btoi(self.ssap))}]")
                print(f"\_ Control:           0x{self.control.hex()} [{btoi(self.control)}]")

            if (self.eth_std == self.Eth_stds.IEEE_802_2_LLCSNAP):
                print(f"SNAP Header:")
                print(f"\_ Vendor, EthType:   {delim(self.vendor_code)}, 0x{self.eth_type.hex()} [{self.str_eth_type(btoi(self.eth_type))}]")
        
        #todo anything else incl. missing
        
        return