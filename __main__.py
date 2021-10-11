from _close import *
from _args import *
import scapy.all as scapy

def main():
    args = Args()
    packets = scapy.rdpcap(args.path, args.count)

    count = len(packets) # packets[0] is first if count > 0, packets[count-1] is last
    for i in range(count):
        print("Frame #" + str(i + 1) + ":")
        print(bytes(packets[i])) # todo this will go into Analyzer(raw_frame) after i figure out what some symbols in the bytes print sequence mean

    close(Code.SUCCESS)

if __name__ == "__main__":
    main()