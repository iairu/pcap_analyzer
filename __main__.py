from warnings import filterwarnings
filterwarnings("ignore") # don't show scapy deprecation warnings (https://github.com/secdev/scapy/pull/3645)

from _close import *
from _args import Args
from _analyze import Analyze
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

        # Do the analysis over raw bytes
        anal = Analyze(pkt_bytes, protocols)

        # Analysis saved into packet output dictionary
        pkt_out = anal.output(i + offset + 1)

        # Add hexdump into packet output
        pkt_out["hexa_frame"] = LiteralScalarString(byte.outputHexDump(pkt_bytes))

        # Add the packet output to the list (later for YAML)
        pkts_out.append(pkt_out)

    output: dict = {}
    output["name"] = "PKS2022/23"
    output["pcap_name"] = "all.pcap" # todo: replace me
    output["packets"] = pkts_out

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