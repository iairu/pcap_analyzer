from _close import *
from _args import *
from _analyze import *
import _byte as byte
import scapy.all as scapy

def main():
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

    close(Code.SUCCESS)

if __name__ == "__main__":
    main()