"""
Graceful closure with end-user readable reasoning clean from any traces.
Ends the program using sys.exit

- code - Pseudo-enum class that contains all supported codes as args for close(code).
- close(code) - Closes with given code, printing out related message.

"""

import sys

class Code:
    """Pseudo-enum class that contains all supported codes as args for close(code)."""
    SUCCESS = 0
    # FAILURE = 1
    INCORRECT_ARG_PATH = 10
    INCORRECT_ARG_COUNT = 20
    INCORRECT_ARG_COUNT_ZERO = 21

def close(_code=Code.SUCCESS):
    """Closes with given code, printing out related message."""
    if (_code == Code.SUCCESS): # no message code
        sys.exit(_code)

    # error message codes
    switch={
        # Code.FAILURE: "Failure.",
        Code.INCORRECT_ARG_PATH: "Incorrect 'path' argument - Wrong filetype or file doesn't exist.",
        Code.INCORRECT_ARG_COUNT: "Incorrect 'count' argument - Has to be -1 or more.",
        Code.INCORRECT_ARG_COUNT_ZERO: "'count' is 0.",
    }
    print("Wasted: " + switch.get(_code, "Closed unexpectedly."))
    print("Use -h for help.")
    sys.exit(_code)