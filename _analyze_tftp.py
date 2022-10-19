"""
TFTP Analysis.
"""
from _byte import printHexDump, btoi, btoIPv4
from _analyze_t import AnalyzeTransport

class AnalyzeTFTP:
    def __init__(self, pkt_bytes: bytes, last_data_len: int):
        self.opcode = btoi(pkt_bytes[42+0:42+2])
        self.data_len = len(pkt_bytes[42+6:])+2
        self.started = True if (self.opcode == 1 or self.opcode == 2) else False
        self.complete = True if (last_data_len < 512 and self.opcode == 4) else False
        return

    def output(self, out):
        # out["tftp_opcode"] = self.opcode
        # out["tftp_data_length"] = self.data_len
        return out