#!/usr/bin/env python3

# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
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

class MyPrettyPrinter(pprint.stdprinter):
    
    def _format(self, obj, *args, **kwargs):
        if isinstance(obj, bytes_types):
            obj = hexlify(obj)
        elif isinstance(obj, list):
            # this is required for the Python3 pretty-printer which works line-by-line
            # and not object-by-object
            for i, objsub in enumerate(obj[:]):
                if isinstance(objsub, bytes_types):
                    del obj[i]
                    obj.insert(i, hexlify(objsub))
        return pprint.stdprinter._format(self, obj, *args, **kwargs)


def main():
    
    parser = argparse.ArgumentParser(description='print any ASN.1 BER/CER/DER encoded objects '\
             'into a generic and nested tag-length-value structure')
    
    parser.add_argument('-i', dest='input', type=str,
                        help='file containing the binary encoded objects')
    parser.add_argument('-s', dest='stream', type=str,
                        help='hexadecimal string encoding the objects')
    parser.add_argument('-x', dest='hex', action='store_true',
                        help='print non-ascii strings in hexadecimal form')
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
            print('%s, args error: invalid hex stream %s' % (sys.argv[0], args.stream))
            return 0
    else:
        print('%s, args error: missing input encoded object' % sys.argv[0])
        return 0
    if args.hex:
        pprint.PrettyPrinter=MyPrettyPrinter
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

