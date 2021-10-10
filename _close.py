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
    UNDEFINED = 1
    INCORRECT_ARG_PATH = 10
    INCORRECT_ARG_COUNT = 20

def close(_code=Code.UNDEFINED):
    """Closes with given code, printing out related message."""
    if (_code == Code.SUCCESS): # no message code
        sys.exit(_code)

    # error message codes
    switch={
        Code.UNDEFINED: "Closed.",
        Code.INCORRECT_ARG_PATH: "Incorrect path - Wrong filetype or file doesn't exist.", # todo filetype check not in place yet
        Code.INCORRECT_ARG_COUNT: "Incorrect count argument - Has to be 0 or more."
    }
    print("Wasted: " + switch.get(_code, "Unknown close code - Closed."))
    sys.exit(_code)