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
    senders: dict[str, int] = {}

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
        anal = Analyze(pkt, protocols)
        anal.output()

        # IPv4 Analysis
        if (anal.has_eth_type and byte.btoi(anal.eth_type) == 0x800):
            anal_ip = AnalyzeIP(anal.data, protocols)
            anal_ip.output()
            # Save senders and number of packets they sent
            if not (args.no_leaderboard):
                sip = byte.btoIPv4(anal_ip.ip_src)
                senders[sip] = 1 if not senders.get(sip) else senders[sip] + 1

    # Sender Leaderboard output
    if not (args.no_leaderboard):
        print("_______")
        print("Senders IPs:")
        top_sip: str = "Unknown"
        top_scount: int = 0
        for sip, scount in senders.items():
            print(sip)
            if (scount > top_scount):
                top_sip = sip
                top_scount = scount

        print(f"Top sender is {top_sip} with {top_scount} packets sent.")

    close(Code.SUCCESS)

if __name__ == "__main__":
    main()