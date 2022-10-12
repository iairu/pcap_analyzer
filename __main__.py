from warnings import filterwarnings
filterwarnings("ignore") # don't show scapy deprecation warnings (https://github.com/secdev/scapy/pull/3645)

from _close import *
from _args import Args
from _analyze import Analyze
from _analyze_ip import AnalyzeIP
from _analyze_t import AnalyzeTransport
from _reader import Protocols
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

    # YAML output to file
    yaml = ruamel.yaml.YAML()

    # List of all packet outputs
    pkts_out: list[dict] = []

    # Process individual packet bytes into packet outputs
    for i in range(count):
        # Get the raw bytes for this packet
        pkt_bytes = bytes(packets[i + offset])

        # Initialize packet output dict for this packet
        pkt_out = {}
        pkt_out["frame_number"] = i + offset + 1

        # Do the analysis over raw bytes
        anal = Analyze(pkt_bytes, protocols)
        pkt_out = anal.output(pkt_out) # append to existing output

        # Continue with IPv4 analysis
        anal_ip = None
        if (anal.has_eth_type and byte.btoi(anal.eth_type) == 0x800):
            anal_ip = AnalyzeIP(anal.data, protocols) # do the analysis
            pkt_out = anal_ip.output(pkt_out) # append to existing output

        # Then Transport layer analysis
        if (anal_ip != None):
            anal_t = AnalyzeTransport(anal_ip.data, anal_ip.protocol_str, protocols)
            pkt_out = anal_t.output(pkt_out) # append to existing output

        # Add hexdump to the end of packet output (processed for correct YAML output)
        pkt_out["hexa_frame"] = LiteralScalarString(byte.outputHexDump(pkt_bytes))

        # Add finished packet output to the list
        pkts_out.append(pkt_out)

    # Header values for output and list of packet outputs
    output: dict = {}
    output["name"] = "PKS2022/23"
    output["pcap_name"] = args.path
    output["packets"] = pkts_out

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