from _close import *
from _args import *

def main():
    args = Args()
    
    print("Testing some printing " + args.count.__str__() + " and the path is ...")
    print(args.path)

    close(Code.SUCCESS)

if __name__ == "__main__":
    main()