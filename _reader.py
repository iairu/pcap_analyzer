"""
Reads relevant .txt files in /protocols directory.
"""
from _close import *

class ProtocolFileMap:
    ETHTYPE = "eth_types.txt"
    SAP = "saps.txt"
    IP = "ip_protocols.txt"
    TCP = "tcp_ports.txt"
    UDP = "udp_ports.txt"

def __protocolFileToDict__(file: str) -> dict(int, str):
    with open("./protocols/" + file, "r") as fptr:
        out_dict: dict(int, str) = {}
        # Parsing all rows
        for row in fptr:
            # Parsing a single row
            was_space: bool = False
            code: str = ""
            _code: int = -1
            name: str = ""
            rlen = len(row)
            # If row non-empty and not a comment
            if (rlen > 0 and code[0] != "#"):
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
                    _code = int(code)
                # Add to dict
                out_dict[_code] = name
    return out_dict