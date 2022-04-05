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
# * File Name : pycrate_showstruct.py
# * Created : 2017-04-23
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

import os
import sys
import argparse

from pycrate_core.base import Buf
from pycrate_core.elt  import Element

# list of supported media
mediasup = 'BMP, GIF, JPEG, MP3, MPEG4, PNG, TIFF'

def main():
    
    parser = argparse.ArgumentParser(description='print the internal structure of the input media file,'\
              'supported formats are: %s' % mediasup)
    parser.add_argument('input', type=str, help='input media file')
    parser.add_argument('-bl', type=int, default=1024,
                        help='maximum length for buffer representation')
    parser.add_argument('-wt', action='store_true', default=False,
                        help='show also absent / transparent fields')
    args = parser.parse_args()
    
    if not os.path.isfile(args.input):
        print('%s, args error: invalid input %s' % (sys.argv[0], args.input))
        return 0
    suf = args.input.split('.')[-1].upper()
    try:
        fd = open(args.input, 'rb')
    except:
        print('%s, args error: unable to open input %s' % (sys.argv[0], args.input))
        return 0
    else:
        buf = fd.read()
        fd.close()
    
    if suf == 'BMP':
        from pycrate_media.BMP import BMP
        struct = BMP()
    elif suf == 'GIF':
        from pycrate_media.GIF import GIF
        struct = GIF()
    elif suf in ('JPG', 'JPEG'):
        from pycrate_media.JPEG import JPEG
        struct = JPEG()
    elif suf == 'MP3':
        from pycrate_media.MP3 import MP3
        struct = MP3()
    elif suf in ('MPEG4', 'MP4'):
        from pycrate_media.MPEG4 import MPEG4
        struct = MPEG4()
    elif suf == 'PNG':
        from pycrate_media.PNG import PNG
        struct = PNG()
    elif suf in ('TIFF', 'TIF'):
        from pycrate_media.TIFF import TIFF
        struct = TIFF()
    else:
        print('%s, unknown format: %s' % (sys.argv[0], suf))
        return 0
    
    Buf.REPR_MAXLEN = args.bl
    
    try:
        struct.from_bytes(buf)
    except:
        print('%s, parsing error: unable to parse file %s' % (sys.argv[0], args.input))
        return 0
    
    # do not print absent / transparent fields
    if not args.wt:
        Element.ENV_SEL_TRANS = False
    
    print(struct.show())
    return 0

if __name__ == '__main__':
    sys.exit(main())

