#!/usr/bin/env python

# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.3
# *
# * Copyright 2017. Benoit Michau. ANSSI.
# *
# * This program is free software: you can redistribute it and/or modify
# * it under the terms of the GNU General Public License version 2 as published
# * by the Free Software Foundation. 
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# * GNU General Public License for more details. 
# *
# * You will find a copy of the terms and conditions of the GNU General Public
# * License version 2 in the "license.txt" file or
# * see http://www.gnu.org/licenses/ or write to the Free Software Foundation,
# * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
# *
# *--------------------------------------------------------
# * File Name : pycrate_berdecode.py
# * Created : 2017-07-04
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

import os
import sys
import argparse
import pprint

from binascii import unhexlify, hexlify
from pycrate_core.utils    import python_version, str_types, bytes_types
from pycrate_core.charpy   import Charpy
from pycrate_asn1rt.codecs import ASN1CodecBER
        

pprint.stdprinter = pprint.PrettyPrinter
#
class MyPrettyPrinter(pprint.stdprinter):
    RA = range(128)
    def _format(self, obj, *args, **kwargs):
        if isinstance(obj, str_types + bytes_types) and \
        not all([c in self.RA for c in obj]):
            obj = hexlify(obj)
        return pprint.stdprinter._format(self, obj, *args, **kwargs)
#
# enabling this will print hex stream for what looks like non-ascii str / bytes
#pprint.PrettyPrinter=MyPrettyPrinter


def main():
    
    parser = argparse.ArgumentParser(description='print any ASN.1 BER/CER/DER encoded objects '\
             'into a generic and nested tag-length-value structure')
    
    parser.add_argument('-i', dest='input', type=str,
                        help='file containing the binary encoded objects')
    parser.add_argument('-s', dest='stream', type=str,
                        help='hexadecimal string encoding the objects')
    #
    args = parser.parse_args()
    if args.input:
        try:
            fd = open(args.input, 'rb')
        except:
            print('%s, args error: file %s not found' % (sys.argv[0], args.input))
            return 0
        buf = fd.read()
        fd.close()
    elif args.stream:
        try:
            buf = unhexlify(args.stream)
        except:
            print('%s, args error: invalid hex stream' % (sys.argv[0], args.stream))
            return 0
    else:
        print('%s, args error: missing input encoded object' % sys.argv[0])
        return 0
    #
    char = Charpy(buf)
    cnt  = 0 
    while char.len_bit() >= 16:
        Obj, V = ASN1CodecBER.decode_tlv_ws(char)
        print('\n' + 14*'--' + ' object %i ' % cnt + 14*'--' + '\n')
        pprint.pprint(V)
        cnt += 1
    return 0
    
if __name__ == '__main__':
    sys.exit(main())

