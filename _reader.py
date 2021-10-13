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
                    _code = int(code, 16)
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
            self.ethtype = __protocolFileToDict__("./protocols/" + self.ProtocolFileMap.ETHTYPE)
            self.sap = __protocolFileToDict__("./protocols/" + self.ProtocolFileMap.SAP)
            self.ip = __protocolFileToDict__("./protocols/" + self.ProtocolFileMap.IP)
            self.tcp = __protocolFileToDict__("./protocols/" + self.ProtocolFileMap.TCP)
            self.udp = __protocolFileToDict__("./protocols/" + self.ProtocolFileMap.UDP)
        except FileNotFoundError:
            close(Code.PROTOCOL_FILE_NOT_FOUND)
        return