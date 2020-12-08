#!/usr/bin/env python3

# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2020. Benoit Michau. P1Sec.
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
# * File Name : pycrate_shownas.py
# * Created : 2020-12-08
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

import os
import sys
import argparse

from binascii       import unhexlify, hexlify
from pycrate_mobile import NAS


def main():
    #
    parser = argparse.ArgumentParser(description='decode and pretty print mobile 2G-3G-4G-5G NAS message')
    parser.add_argument('NASPDU', type=str, help='hexadecimal encoded NAS message')
    parser.add_argument('-mt', action='store_true', help='force decoding to Mobile Terminated NAS message')
    parser.add_argument('-mo', action='store_true', help='force decoding to Mobile Originated NAS message')
    parser.add_argument('-l2', action='store_true', help='message includes a GSM L2 pseudo-length header')
    args = parser.parse_args()
    #
    try:
        buf = unhexlify(args.NASPDU)
    except Exception as err:
        print('[+] invalid hexadecimal NAS message, error: %s' % err)
        return 0
    #
    if args.mt:
        msg, err = NAS.parse_NAS_MT(buf, args.l2)
    elif args.mo:
        msg, err = NAS.parse_NAS_MO(buf, args.l2)
    else:
        msg, err = NAS.parse_NAS_MT(buf, args.l2)
        if err:
            msg, err = NAS.parse_NAS_MO(buf, args.l2)
    #
    if err:
        print('[+] unable to decode the provided NAS message')
    else:
        print('[+] decoded NAS message:\n%s' % msg.show())
    return 0


if __name__ == '__main__':
    sys.exit(main())

