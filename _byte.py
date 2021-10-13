"""
Utilities for conversion of bytes into int, hex and dumping bytes as a hexdump.
"""

def btoi(_bytes: bytes) -> int:
    """Bytes to Int conversion"""
    out = 0
    for b in _bytes:
        out *= 256
        out += int(b)
    return out

def delim(_bytes: bytes, delimiter: str = ":") -> str:
    """ Delimit a hex byte sequence, also turning it into string"""
    delimited = str()
    undelimited = _bytes.hex()
    last = len(undelimited) - 1

    for i, c in enumerate(undelimited):
        # add delimiter every two characters (one byte) excluding the end of string
        if (i % 2 and i < last):
            delimited += c + delimiter
        else:
            delimited += c

    return delimited

# Direct access prefered instead of the following methods:
# def getString(_bytes: bytes, _fromByte: int, _toByte: int) -> str:
#     return _bytes[_fromByte:_toByte].hex()

# def getString(_bytes: bytes, _fromByte: int=0) -> str:
#     return _bytes[_fromByte:].hex()


def printHexDump(_bytes: bytes, _each: int = 16, offset: int = 4):
    # print(getDelimitedString(_bytes, " ")) # todo newline each 8 bytes, how to iterate over bytes?
    # _each = 16 # bytes per row
    # offset = 4 # Max necessary length for the first column (row counter in hex)

    def zeroPrefix(number: str, length: int) -> str:
        # Prefiex the given "number" by zeros until its length matches "length"
        out = number
        length -= len(out)
        while(length):
            out = "0" + out
            length -= 1
        return out

    
    _from = 0
    _to = _each
    while(len( _bytes[ _from : _to ] ) > 0):
        print(
            # Offset column (hex row counter) ([2:] removes the "0x" hex prefix)
            zeroPrefix(str(hex(_from))[2:], offset) + ": " + 
            # Substring of spaced bytes
            delim( _bytes[ _from : _to ], " ")
            )
        _from += _each
        _to += _each
    return