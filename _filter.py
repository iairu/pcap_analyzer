"""
An abstract interface to unify implementations of filters for different protocols
using matching, extraction and completion.

Sample implementation, put all implementations into _filters.py:
------
def matchSAMPLE(data: bytes, meta: dict):
    return False

def extractSAMPLE(data: bytes, meta: dict):
    return {}

def completionSAMPLE(all: list[dict], meta: dict):
    complete = []
    incomplete = []
    return [complete, incomplete]

filterSAMPLE = Filter("SAMPLE", matchSAMPLE, extractSAMPLE, completionSAMPLE)

class Filters:
    supported: list[Filter] = [filterSAMPLE]
------

"""

from typing import Callable
from _reader import Protocols

class Filter(object):
    def __init__(self, name: str, matcherFunc: Callable | None, completionFunc: Callable | None):
        self.name = name

        self._match = matcherFunc # bool = matcherFunc(pkt_out: dict, pkt_bytes: bytes)
        self._completion = completionFunc # [complete, incomplete] = completionFunc(all: list[dict])
        
        # Communication buckets
        self.all: list[dict] = []
        self.complete: list[dict] = []
        self.incomplete: list[dict] = []

    # match if the given packet belongs to the protocol named in this filter, then
    # extract only relevant packet information for further filtering (e.g. communication buckets), then
    # add to self.all (e.g. to be ready for completion())
    def matchAdd(self, pkt_out: dict, protocols: Protocols):
        matched: bool = self._match(pkt_out, {}, protocols)
        if (matched == True):
            self.all.append(pkt_out)
        return matched

    # actual filter into complete/incomplete buckets
    def completion(self, protocols, external: dict = {}):
        _complete, _incomplete = self._completion(self.all, protocols, external)
        self.complete: list[dict] = _complete
        self.incomplete: list[dict] = _incomplete
