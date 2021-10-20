"""
Graceful closure with end-user readable reasoning clean from any traces.
Ends the program using sys.exit

- code - Pseudo-enum class that contains all supported codes as args for close(code).
- close(code) - Closes with given code, printing out related message.

"""

import sys

class Code:
    """Pseudo-enum class that contains all supported codes as args for close(code)."""
    # todo: use python exceptions?
    SUCCESS = 0
    # FAILURE = 1
    INCORRECT_ARG_PATH = 10
    INCORRECT_ARG_COUNT = 20
    INCORRECT_ARG_COUNT_ZERO = 21
    INCORRECT_ARG_FIRST = 30
    INCORRECT_ARG_FIRST_TOO_HIGH = 31
    PROTOCOL_DEFINITION_WRONG = 50
    PROTOCOL_FILE_NOT_FOUND = 51
    SS_MISSING_ARG_PAIR = 60

def close(_code=Code.SUCCESS):
    """Closes with given code, printing out related message."""
    if (_code == Code.SUCCESS): # no message code
        sys.exit(_code)

    # error message codes
    switch={
        # Code.FAILURE: "Failure.",
        Code.INCORRECT_ARG_PATH: "Incorrect 'path' argument - Wrong filetype or file doesn't exist.",
        Code.INCORRECT_ARG_COUNT: "Incorrect 'count' argument - Has to be -1 or more.",
        Code.INCORRECT_ARG_COUNT_ZERO: "At least one right behind me, but none here... 'count' is 0 or 'first' needs to be lower.",
        Code.INCORRECT_ARG_FIRST: "Incorrect 'first' argument - Has to be 1 or more.",
        Code.INCORRECT_ARG_FIRST_TOO_HIGH: "Argument 'first' too high - Verify number of packets first.",
        Code.PROTOCOL_DEFINITION_WRONG: "Incorrect protocol definition in one of ./protocols text files.\nMake sure to use 0xNN hex format delimited from protocol name by a single space (e.g. 0xAA SNAP).\nFor TCP/UDP ports make sure to use decimal format instead.",
        Code.PROTOCOL_FILE_NOT_FOUND: "Missing a file with protocols. Verify all _reader.py/ProtocolFileMap files are present in the ./protocols subfolder.",
        Code.SS_MISSING_ARG_PAIR: "Missing argument pair for -ss, make sure to use -s as well.",
    }
    print("Wasted: " + switch.get(_code, "Closed unexpectedly."))
    print("Use -h for help.")
    sys.exit(_code)