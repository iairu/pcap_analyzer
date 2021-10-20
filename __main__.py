from _close import *
from _args import Args
from _reader import Protocols
from _frame import Frame
from _sort import SortComm
import _byte as byte
import scapy.all as scapy

def main():
    protocols = Protocols() # reader for protocols/*.txt
    args = Args() # user arguments
    offset = args.first - 1 # for frame number calc incl. "-f/--first" arg offset
    packets = scapy.rdpcap(args.path, args.count + offset) # for raw bytes to analyze
    senders: dict[str, int] = {} # for leaderboard
    frames = [] # for communication sorting

    count = len(packets) - offset # packets[0] is first if count > 0, packets[count-1] is last
    if (count == 0): close(Code.INCORRECT_ARG_COUNT_ZERO)
    if (count < 0): close(Code.INCORRECT_ARG_FIRST_TOO_HIGH)
    for i in range(count):
        # Raw bytes of packet
        pkt = bytes(packets[i + offset])

        # Frame analysis, output
        frame = Frame(i + offset + 1, pkt, protocols)
        frame.analyzeAll()

        # Frame unsorted printing or saving for later sorting
        if (args.sort_app_protocol):
            frames.append(frame)
        else:
            frame.print()
            if (not args.no_hexdump): frame.printHexDump()

        # Save senders and number of packets they sent
        if (frame.anal_ip != None and not args.no_leaderboard):
            sip = byte.btoIPv4(frame.anal_ip.ip_src)
            senders[sip] = 1 if not senders.get(sip) else senders[sip] + 1

    # Communication sorting:
    if (args.sort_app_protocol):
        sort = SortComm(args.sort_app_protocol, frames, protocols, args.sort_short)
        sort.print()
    else:
        # Sender Leaderboard output, not filtered for sorted communication
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