#!/usr/bin/env python3

from pycrate_asn1dir    import TCAP_MAPv2v3
from pycrate_asn1dir    import S1AP
from pycrate_asn1dir    import X2AP
#
from pycrate_core       import utils
from pycrate_core       import charpy
from pycrate_asn1rt     import err
from pycrate_asn1rt     import asnobj
asnobj.ASN1Obj._SILENT = True
#
from pythonfuzz.main import PythonFuzz


TM = TCAP_MAPv2v3.TCAP_MAP_Messages.TCAP_MAP_Message

@PythonFuzz
def fuzz_tcap_map(buf):
    buf = bytes(buf)
    try:
        TM.from_ber(buf)
        r = TM.to_ber()
    except utils.PycrateErr:
        pass


SP = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
X2 = X2AP.X2AP_PDU_Descriptions.X2AP_PDU

@PythonFuzz
def fuzz_s1ap(buf):
    buf = bytes(buf)
    try:
        SP.from_aper(buf)
        r = SP.to_aper()
    except utils.PycrateErr:
        pass

@PythonFuzz
def fuzz_x2ap(buf):
    buf = bytes(buf)
    try:
        X2.from_aper(buf)
        r = X2.to_aper()
    except utils.PycrateErr:
        pass


if __name__ == '__main__':
    fuzz_tcap_map()
    #fuzz_s1ap()
    fuzz_x2ap()

