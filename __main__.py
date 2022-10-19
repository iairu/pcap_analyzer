from warnings import filterwarnings
filterwarnings("ignore") # don't show scapy deprecation warnings (https://github.com/secdev/scapy/pull/3645)

from _close import *
from _args import Args
from _analyze import Analyze
from _analyze_ip import AnalyzeIP
from _analyze_t import AnalyzeTransport
from _analyze_arp import AnalyzeARP
from _analyze_icmp import AnalyzeICMP
from _reader import Protocols
from _filters import Filters
import _byte as byte
import scapy.all as scapy

import ruamel.yaml
from ruamel.yaml.scalarstring import LiteralScalarString

def main():
    protocols = Protocols()
    args = Args()
    offset = args.first - 1
    packets = scapy.rdpcap(args.path, args.count + offset)

    count = len(packets) - offset # packets[0] is first if count > 0, packets[count-1] is last
    if (count == 0): close(Code.INCORRECT_ARG_COUNT_ZERO)
    if (count < 0): close(Code.INCORRECT_ARG_FIRST_TOO_HIGH)

    filt = None # Filter was not requested by user
    if (args.protocol != None):
        filters = Filters()
        filt = filters.grab(args.protocol)
        if (filt == None):
            # Filter was requested by user but not supported
            close(Code.PROTOCOL_NOT_SUPPORTED)

    # YAML output to file
    yaml = ruamel.yaml.YAML()

    # List of all packet outputs
    pkts_out: list[dict] = []

    # List of remaining unmatched fragments for ICMP analysis
    unmatched_icmp_fragments: list[bytes] = []

    # Save IPv4 senders and number of packets they sent
    senders = {}

    # Process individual packet bytes into packet outputs
    for i in range(count):
        # Get the raw bytes for this packet
        pkt_bytes = bytes(packets[i + offset])

        # Initialize packet output dict for this packet
        pkt_out = {}
        pkt_out["frame_number"] = i + offset + 1

        # Do the analysis over raw bytes
        anal = Analyze(pkt_bytes, protocols)
        anal.output(pkt_out) # append to existing output

        # Continue with IPv4 analysis
        anal_ip = None
        if (anal.has_eth_type and byte.btoi(anal.eth_type) == 0x800): # only if eth_type is IPv4
            anal_ip = AnalyzeIP(anal.data, protocols) # do the analysis
            anal_ip.output(pkt_out) # append to existing output

        # Then Transport layer analysis
        if (anal_ip != None):
            anal_t = AnalyzeTransport(anal_ip.data, anal_ip.protocol_str, protocols)
            anal_t.output(pkt_out) # append to existing output

        # ARP analysis
        if (anal_ip == None and anal.has_eth_type and byte.btoi(anal.eth_type) == 0x806): # only if eth_type is ARP
            anal_arp = AnalyzeARP(anal.data, protocols)
            anal_arp.output(pkt_out)

        # ICMP analysis
        if (anal_ip != None and byte.btoi(anal_ip.protocol) == 0x01): # only if IPv4 protocol is ICMP
            anal_icmp = AnalyzeICMP(anal_ip, unmatched_icmp_fragments, protocols)
            anal_icmp.output(pkt_out)

        # Save IPv4 senders and number of packets they sent
        if (anal_ip != None):
            src_ip = byte.btoIPv4(anal_ip.ip_src)
            senders[src_ip] = 1 if not senders.get(src_ip) else senders[src_ip] + 1

        # Add hexdump to the end of packet output (processed for correct YAML output)
        pkt_out["hexa_frame"] = LiteralScalarString(byte.outputHexDump(pkt_bytes))

        # Add finished packet output to the list
        if (filt == None):
            pkts_out.append(pkt_out)
        else:
            filt.matchAdd(pkt_out, protocols)

    # Header values for output and list of packet outputs
    output: dict = {}
    output["name"] = "PKS2022/23"
    output["pcap_name"] = args.path
    if (filt == None):
        # No filter requested by user
        output["packets"] = pkts_out

        # Calculate IPv4 stats
        out_senders = []
        top_sender_packet_count = 0
        top_senders = []
        for sip, scount in senders.items():
            out_senders.append({
                "node": sip,
                "number_of_sent_packets": scount
            })
            if (scount > top_sender_packet_count):
                top_senders = [sip]
                top_sender_packet_count = scount
            elif (scount == top_sender_packet_count):
                top_senders.append(sip)

        output["ipv4_senders"] = out_senders
        output["max_send_packets_by"] = top_senders

    else:
        # Supported filter requested by user
        output["filter_name"] = filt.name
        filt.completion(protocols)
        output["complete_comms"] = filt.complete # todo: in Filter redefine complete as dict {number_comm, src_com, dst_comm, packets = part of Filter.complete}
        output["partial_comms"] = filt.incomplete # todo: /\, also if empty then don't assign
        

    # Save the dict as YAML
    if (args.print):
        yaml.dump(output, sys.stdout)
    else:
        with open(args.output, "w") as fw:
            yaml.dump(output, fw)
        print("Saved output to '" + args.output + "'")

    close(Code.SUCCESS)

def yaml():
    pass

if __name__ == "__main__":
    main()