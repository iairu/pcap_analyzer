"""
Filter implementations for individual supported protocols over abstract interface defined in _filter.
"""

from _filter import Filter

def matchARP(pkt_out: dict, pkt_bytes: bytes, meta: dict):
    return False if (pkt_out.get("ether_type") != "ARP") else True

def completionARP(all: list[dict], meta: dict):
    complete = []
    incomplete = []
    for pkt_out in all:
        # todo
        complete.append(pkt_out)
    return [complete, incomplete]

filterARP = Filter("ARP", matchARP, completionARP) # todo
# filterTFTP = Filter("TFTP", matchTFTP, completionTFTP) # todo + add to supported below
# filterICMP = Filter("ICMP", matchICMP, completionICMP) # todo + add to supported below

class Filters:
    supported: list[Filter] = [filterARP]

    # Get info if queried filter is supported and if so, return it
    def grab(self, name: str):
        for f in self.supported:
            if (f.name == name):
                return f
        return None