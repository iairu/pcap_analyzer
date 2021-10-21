
from _close import *
from _frame import Frame
from _reader import Protocols

class ProtocolCounter:
    def __init__(self, frames: list, protocolToCount: str, protocols: Protocols):
        if (protocolToCount not in ["RIP"]):
            close(Code.COUNT_NYI)
            
        self.protocol_str = protocolToCount
        self.counter = 0
        self.filtered_frames = []

        for f in frames:
            if not isinstance(f, Frame):
                continue

            # UDP (RIP)
            if (f.anal_ip != None and f.anal_ip.protocol_str == "UDP"):
                if (f.anal_t != None and protocols.int_udp(protocolToCount) in [f.anal_t.port_src, f.anal_t.port_dst]):
                    self.filtered_frames.append(f)
                    self.counter += 1

        return

    def print(self):
        for f in self.filtered_frames:
            if not isinstance(f, Frame):
                continue

            f.print()
            f.printHexDump()
        print(f"Counted {self.counter} frames of {self.protocol_str} protocol.")
        pass