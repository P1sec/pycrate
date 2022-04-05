#!/usr/bin/python

# -*- coding: UTF-8 -*-
#/**
# * S1AP test utility
# * Script to test pycrate decoding/re-encoding for APER
# * Script is using tshark json pipe input which was generated from real pcap
# *
# * Usage:
# * Use any s1ap pcap (trace.pcap)
# * ./tshark -T ek -x -j s1ap -r trace.pcap > trace.json
# * python test_s1ap.py
# *
# * Copyright 2017 Martin Kacer, H21 lab
# *
# *
# *
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2017 Benoit Michau. ANSSI.
# *
# * This library is free software; you can redistribute it and/or
# * modify it under the terms of the GNU Lesser General Public
# * License as published by the Free Software Foundation; either
# * version 2.1 of the License, or (at your option) any later version.
# *
# * This library is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# * Lesser General Public License for more details.
# *
# * You should have received a copy of the GNU Lesser General Public
# * License along with this library; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, 
# * MA 02110-1301  USA
# *
# *--------------------------------------------------------
# * File Name : test_s1ap.py
# * Created : 2017-12-28
# * Authors : Martin Kacer 
# *--------------------------------------------------------
#*/

import sys
import time
import random
import traceback
import binascii
from pycrate_asn1dir import S1AP

# Global options to control the script behavior
option_print_verbose = True       # print verbose decoding output
option_fuzzing_messages = False    # fuzz messages before pycrate decoding
option_reencode = True             # re-encode into hex and compare with the hex input
#


with open('res/s1ap_pcapr.json') as f:
    lines = f.readlines()
    for s in lines:

        i = s.find('"s1ap_raw": "')
        ln = len('"s1ap_raw": "')
        if (i > 0):
            #print(s[i:])
            subs = s[i+ln:]
            l = subs.find('"')
            s1ap_hex = subs[0:l]
            
            if (option_print_verbose):
                print("HEX  IN: " +  s1ap_hex)
            
            # fuzzing of messages
            if (option_fuzzing_messages):
                for i in range (0, 1):
                    if s1ap_hex != '':
                        s1ap_hex_f = s1ap_hex
                        position = int(random.randint(0, len(s1ap_hex_f))/2)
                        position = position * 2
                        s1ap_hex_f = s1ap_hex_f[:position] + format(random.randint(0, 255), '02x') + s1ap_hex_f[position + 2:]
                        s1ap_hex = s1ap_hex_f
                    
                    if (option_print_verbose):
                        print("FUZZ IN: " + s1ap_hex)
            
            try:
                # decode using pycrate
                s1ap = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
                s1ap.from_aper(binascii.unhexlify(s1ap_hex))
                
                s1ap_decoded = s1ap.get_val()
                # verbose output
                if (option_print_verbose):
                    print(s1ap_decoded)
                    print(s1ap.to_asn1())
                # 
                
                # re-encode using pycrate
                if (option_reencode == True):
                    s1ap.set_val(s1ap_decoded)
                    s1ap_hex_out = str(binascii.hexlify(s1ap.to_aper()))
                    if (option_print_verbose):
                        print("HEX OUT:" + s1ap_hex_out)
                    
                    # decode again and try to check diff
                    s1ap_reencoded = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
                    s1ap_reencoded.from_aper(binascii.unhexlify(s1ap_hex))
                    s1ap_decoded = str(s1ap.get_val())
                    s1ap_reencoded_decoded = str(s1ap.get_val())
                    if (s1ap_decoded != s1ap_reencoded_decoded):
                        print("!!!!!!! Re-encoding error begin !!!!!!!")
                        print("ENCODED  IN: " + s1ap_hex)
                        print("RE-RENCODED: " + s1ap_hex_out)
                        print(s1ap_decoded)
                        print(s1ap_reencoded_decoded)
                        print("!!!!!!! Re-encoding error end !!!!!!!")
                    #
                                                    
                #
                
            except Exception as err:
                print("!!!!!!! Exception begin !!!!!!!")
                print(err)
                traceback.print_exc()
                print("!!!!!!! Exception end !!!!!!!")
            

