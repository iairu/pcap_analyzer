from _close import *
from _args import Args
from _analyze import Analyze
from _analyze_ip import AnalyzeIP
from _reader import Protocols
import _byte as byte
import scapy.all as scapy

def main():
    protocols = Protocols()
    args = Args()
    offset = args.first - 1
    packets = scapy.rdpcap(args.path, args.count + offset)

    count = len(packets) - offset # packets[0] is first if count > 0, packets[count-1] is last
    if (count == 0): close(Code.INCORRECT_ARG_COUNT_ZERO)
    if (count < 0): close(Code.INCORRECT_ARG_FIRST_TOO_HIGH)
    for i in range(count):
        pkt = bytes(packets[i + offset])
        print("_______")
        print("Frame #" + str(i + offset + 1) + ":")

        # Hexdump by default
        if not (args.no_hexdump): byte.printHexDump(pkt)
        
        # Analysis
        anal = Analyze(pkt)
        anal.output()

        # IPv4 Analysis
        if (anal.has_eth_type and byte.btoi(anal.eth_type) == 0x800):
            anal_ip = AnalyzeIP(anal.data)
            anal_ip.output()

    close(Code.SUCCESS)

if __name__ == "__main__":
    main()