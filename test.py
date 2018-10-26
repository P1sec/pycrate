#!/usr/bin/env python3
import sys
import time
from test import test_pycrate

# core / asn1rt objects config
test_pycrate.Element._SAFE_STAT = True
test_pycrate.Element._SAFE_DYN  = True
test_pycrate.ASN1Obj._SAFE_INIT = True
#
# testing the compilation of all ASN.1 modules
test_pycrate.TEST_ASN1C_ALL = False

def main():
    TO = time.time()
    
    print('[+] running unit tests')
    ut = test_pycrate.TestPycrate()
    ut.test_core()
    ut.test_media()
    ut.test_ether()
    ut.test_asn1c()
    ut.test_asn1rt()
    ut.test_csn1()
    ut.test_mobile()
    
    print('[+] running perf test')
    test_pycrate.test_perf_all()
    
    print('[+] time: %f sec' % (time.time() - TO, ))
    return 0


if __name__ == '__main__':
    sys.exit(main())

