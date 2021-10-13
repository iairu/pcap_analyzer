"""
Reads relevant .txt files in /protocols directory and saves them as dict(int,str) in its instance.
"""
from _close import *

def __protocolFileToDict__(filepath: str) -> dict:
    with open(filepath, "r") as fptr:
        out_dict: dict = {}
        # Parsing all rows
        for row in fptr:
            # Parsing a single row
            was_space: bool = False
            code: str = ""
            _code: int = -1
            name: str = ""
            rlen = len(row)
            # If row non-empty and not a comment
            if (rlen > 0 and row[0] != "#"):
                for c in row:
                    # Parsing a single character
                    if (c == "\r" or c == "\n"): continue
                    if (c == " "):
                        was_space = True
                    elif (was_space):
                        name += c
                    else:
                        code += c
                # Finished parsing, check validity
                if (code[0] != "0" and code[1] != "x"):
                    close(Code.PROTOCOL_DEFINITION_WRONG)
                else:
                    try:
                        _code = int(code, 16)
                    except ValueError:
                        close(Code.PROTOCOL_DEFINITION_WRONG)
                # Add to dict
                out_dict[_code] = name
    return out_dict

class Protocols:
    """ Reads relevant .txt files in /protocols directory and saves them as dict(int,str) in its instance """

    class ProtocolFileMap:
        ETHTYPE = "eth_types.txt"
        SAP = "saps.txt"
        IP = "ip_protocols.txt"
        TCP = "tcp_ports.txt"
        UDP = "udp_ports.txt"

    # ------------------------------------------

    def __init__(self):
        try:
            self.eth_type = __protocolFileToDict__("./protocols/" + self.ProtocolFileMap.ETHTYPE)
            self.sap = __protocolFileToDict__("./protocols/" + self.ProtocolFileMap.SAP)
            self.ip = __protocolFileToDict__("./protocols/" + self.ProtocolFileMap.IP)
            self.tcp = __protocolFileToDict__("./protocols/" + self.ProtocolFileMap.TCP)
            self.udp = __protocolFileToDict__("./protocols/" + self.ProtocolFileMap.UDP)
        except FileNotFoundError:
            close(Code.PROTOCOL_FILE_NOT_FOUND)
        return

    def str_eth_type(self, code: int) -> str:
        return self.eth_type.get(code,"Unknown ETH TYPE")
    
    def str_sap(self, code: int) -> str:
        return self.sap.get(code, "Unknown SAP")

    def str_ip(self, code: int) -> str:
        return self.ip.get(code, "Unknown IP Protocol")

    def str_tcp(self, code: int) -> str:
        return self.tcp.get(code, "Unknown TCP Port")

    def str_udp(self, code: int) -> str:
        return self.udp.get(code, "Unknown UDP Port")