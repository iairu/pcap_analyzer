"""
IPv4 Analysis.
"""
from _byte import printHexDump, btoi, btoIPv4
from _reader import Protocols
from _analyze_ip import AnalyzeIP

class ICMPfragment:
    def __init__(self, _id: int, data: bytes):
        self.id = _id
        self.data = data
        self.matched = False

class AnalyzeICMP:
    def __init__(self, _anal_ip: AnalyzeIP, _unmatchedFragments: list[ICMPfragment], _protocols: Protocols):
        self.str_icmp_type = _protocols.str_icmp_type

        _id = _anal_ip.id
        _flags_mf = _anal_ip.flags_mf
        _frag_offset = _anal_ip.frag_offset
        _data = _anal_ip.data

        self.final = False
        self.data = None
        self.type = None
        self.code = None

        # this will be an unmatched fragment, more to come
        if (_flags_mf == True):
            _unmatchedFragments.append(ICMPfragment(_id, _data))
            return
            
        self.final = True

        # this is the final fragment, reconstruct the data from unmatched previous fragments
        reconstruct = bytearray()
        for frag in _unmatchedFragments:
            if frag.matched == False and frag.id == _id:
                reconstruct += frag.data
                frag.matched = True
        reconstruct += _data
        self.data = bytes(reconstruct)

        # only for final fragments: get ICMP details from reconstructed data
        self.type = self.data[0:1]
        self.code = self.data[2:3]

        return

    def output(self, out):
        if (self.final and self.type != None):
            out["icmp_type"] = self.str_icmp_type(btoi(self.type))
        return out