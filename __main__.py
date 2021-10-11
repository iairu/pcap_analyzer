from _close import *
from _args import *
import _byte as byte
import scapy.all as scapy

def main():
    args = Args()
    packets = scapy.rdpcap(args.path, args.count)

    count = len(packets) # packets[0] is first if count > 0, packets[count-1] is last
    if (count == 0): close(Code.INCORRECT_ARG_COUNT_ZERO)
    for i in range(count):
        print("_______")
        print("Frame #" + str(i + 1) + ":")
        pkt = bytes(packets[i])
        byte.printHexDump(pkt)
        # print(pkt) # todo this will go into Analyzer(raw_frame) after i figure out what some symbols in the bytes print sequence mean

    close(Code.SUCCESS)

if __name__ == "__main__":
    main()