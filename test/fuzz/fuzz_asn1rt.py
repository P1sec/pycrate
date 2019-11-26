#!/usr/bin/env python3

from pycrate_asn1dir    import TCAP_MAPv2v3
#
from pycrate_core       import utils
from pycrate_core       import charpy
from pycrate_asn1rt     import err
#
from pythonfuzz.main import PythonFuzz


@PythonFuzz
def fuzz(buf):
    buf = bytes(buf)
    try:
        M = TCAP_MAPv2v3.TCAP_MAP_Messages.TCAP_MAP_Message
        M.from_ber(buf)
        #r = M.to_asn1()
    except utils.PycrateErr:
        pass

if __name__ == '__main__':
    fuzz()

