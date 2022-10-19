"""
Filter implementations for individual supported protocols over abstract interface defined in _filter.
"""

from _filter import Filter
from _reader import Protocols

def matchARP(pkt_out: dict, meta: dict, protocols: Protocols):
    return False if (pkt_out.get("ether_type") != protocols.str_eth_type(0x0806)) else True

def matchICMP(pkt_out: dict, meta: dict, protocols: Protocols):
    return False if (pkt_out.get("protocol") != protocols.str_ip(0x01)) else True

def completionARP(all: list[dict], protocols: Protocols, meta: dict):
    complete_comm_num = 1
    complete = []

    incomplete_comm_num = 1
    incomplete = []

    comm_num = 1
    matcher = []

    # assign incomplete and complete-for-matching communications
    for pkt_out in all:
        opcode = pkt_out["arp_opcode"]
        src_ip = pkt_out["src_ip"]
        dst_ip = pkt_out["dst_ip"]
        comm_identifier = str(src_ip) + ":" + str(dst_ip)
        if (opcode == protocols.str_arp_opcode(1)): # request
            matcher.append([0, comm_identifier, 1, pkt_out])
            # /\ [0 meaning unmatched, -comm_num meaning rematchable, comm_num for non-rematchable, 
            # common communication identifier, opcode, pkt_out]
        elif (opcode == protocols.str_arp_opcode(2)): # reply
            first_done = False
            for inc in matcher:
                if (inc[0] <= 0 and comm_identifier == inc[1] and inc[2] == 1):
                    # for all unmatched/rematchable requests before
                    # if there is a common communication identifier
                    if (not first_done): # this one will be non-rematchable because first req with first reply
                        inc[0] = comm_num
                        first_done = True
                    else:
                        inc[0] = -comm_num
            if (first_done):
                matcher.append([comm_num, comm_identifier, 2, pkt_out]) # complete communication because reqs found
                comm_num += 1 # next communication takes place after each found reply
            else:
                incomplete.append({"number_comm": incomplete_comm_num, "packets": [pkt_out]})
                incomplete_comm_num += 1
        else:
            incomplete.append({"number_comm": incomplete_comm_num, "packets": [pkt_out]})
            incomplete_comm_num += 1

    # match complete communications
    for m in matcher:
        comm_num = abs(m[0]) # abs, because communication assignments are by now finalized
        comm_identifier = m[1]
        opcode = m[2]
        pkt_out = m[3]

        if (comm_num == 0):
            # we didn't find a pair = incomplete
            incomplete.append({"number_comm": incomplete_comm_num, "packets": [pkt_out]})
            incomplete_comm_num += 1
        else:
            i = comm_num - 1
            out_of_bounds = True if i >= len(complete) else False
            if (out_of_bounds):
                # add as a new complete communication
                comm_ips = comm_identifier.split(":")
                complete.append({"number_comm": complete_comm_num, "src_comm": comm_ips[0], "dst_comm": comm_ips[1], "packets": [pkt_out]})
                complete_comm_num += 1
            else:
                # add to existing complete communication
                complete[i]["packets"].append(pkt_out)

    return [complete, incomplete]

def completionICMP(all: list[dict], protocols: Protocols, meta: dict):
    complete_comm_num = 1
    complete = []

    incomplete_comm_num = 1
    incomplete = []

    comm_num = 1
    matcher = []

    # assign incomplete and complete-for-matching communications
    for pkt_out in all:
        icmp_type = pkt_out.get("icmp_type")
        src_ip = pkt_out.get("src_ip")
        dst_ip = pkt_out.get("dst_ip")
        _id = pkt_out.get("id")
        comm_identifier = str(src_ip) + ":" + str(dst_ip) + ":" + str(_id)
        if (icmp_type == None):
            matcher.append([0, comm_identifier, pkt_out])

        elif (icmp_type == protocols.str_icmp_type(8)): # echo request, start communication as incomplete
            for m in matcher: # set any related fragments to this communication
                if (m[0] == 0 and m[1] == comm_identifier): # related fragment
                    m[0] = -comm_num
            matcher.append([-comm_num, comm_identifier, pkt_out])

        elif (icmp_type == protocols.str_icmp_type(0)): # echo reply, end communication (complete if it had requests prior)
            had_requests = False
            k = [] # to get back to initial reply fragments when completness wasn't yet sure
            for i, m in enumerate(matcher): # set any related fragments to this communication
                if (m[0] == 0 and m[1] == comm_identifier): # related fragment
                    k.append(i)
                    m[0] = -comm_num # set incompletness
                elif (m[0] == -comm_num):
                    had_requests = True
                    m[0] = comm_num # set completness of this packet
            if (had_requests):
                for i in k: # set completness of any related fragments
                    matcher[i][0] = comm_num
            matcher.append([-comm_num if (not had_requests) else comm_num, comm_identifier, pkt_out])
            comm_num += 1 # end this communication

        else:
            incomplete.append({"number_comm": incomplete_comm_num, "packets": [pkt_out]})
            incomplete_comm_num += 1

    # match complete communications
    for m in matcher:
        comm_num = m[0] # abs, because communication assignments are by now finalized
        comm_identifier = m[1]
        pkt_out = m[2]

        if (comm_num <= 0):
            # we didn't find a pair = incomplete
            incomplete.append({"number_comm": incomplete_comm_num, "packets": [pkt_out]})
            incomplete_comm_num += 1
        else:
            i = comm_num - 1
            out_of_bounds = True if i >= len(complete) else False
            if (out_of_bounds):
                # add as a new complete communication
                comm_ips = comm_identifier.split(":")
                complete.append({"number_comm": complete_comm_num, "src_comm": comm_ips[0], "dst_comm": comm_ips[1], "packets": [pkt_out]})
                complete_comm_num += 1
            else:
                # add to existing complete communication
                complete[i]["packets"].append(pkt_out)

        

    return [complete, incomplete]

def completionTFTP(all: list[dict], protocols: Protocols, meta: dict):
    complete_comm_num = 1
    complete = []

    incomplete_comm_num = 1
    incomplete = []

    comm_num = 1
    matcher = meta

    # assign incomplete and complete communications
    for m in matcher:
        if (m[6] == True and m[7] == True):
            complete.append({"number_comm": complete_comm_num, "src_comm": m[0], "dst_comm": m[1], "packets": m[4]})
            complete_comm_num += 1
        else:
            incomplete.append({"number_comm": incomplete_comm_num, "src_comm": m[0], "dst_comm": m[1], "packets": m[4]})
            incomplete_comm_num += 1

    return [complete, incomplete]

filterARP = Filter("ARP", matchARP, completionARP)
filterICMP = Filter("ICMP", matchICMP, completionICMP)
filterTFTP = Filter("TFTP", None, completionTFTP) # todo currently work in progress

class Filters:
    # supported: list[Filter] = [filterARP, filterICMP, filterTFTP]
    supported: list[Filter] = [filterARP, filterICMP]

    # Get info if queried filter is supported and if so, return it
    def grab(self, name: str):
        for f in self.supported:
            if (f.name == name):
                return f
        return None
