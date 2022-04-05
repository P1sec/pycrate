#!/usr/bin/python

# -*- coding: UTF-8 -*-
#/**
# * Sigtran test utility
# * Script to test pycrate decoding/re-encoding for BER / Sigtran
# * Script is using tshark json pipe input which was generated from real pcap
# *
# * Usage:
# * Use any sigtran or ss7 pcap (trace.pcap)
# * ./tshark -T ek -x -j tcap -r trace.pcap > trace.json
# * python test_tcapmap.py
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
# * File Name : test_tcapmap.py
# * Created : 2017-11-30
# * Authors : Martin Kacer 
# *--------------------------------------------------------
#*/

import sys
import time
import random
import traceback
import binascii
from pycrate_asn1dir import TCAP_MAP

# Global options to control the script behavior
option_print_verbose = True       # print verbose decoding output
option_fuzzing_messages = False    # fuzz messages before pycrate decoding
option_reencode = True             # re-encode into hex and compare with the hex input
#


with open('res/tcapmap_pcapr.json') as f:
    lines = f.readlines()
    for s in lines:

        i = s.find('"tcap_raw": "')
        ln = len('"tcap_raw": "')
        if (i > 0):
            #print(s[i:])
            subs = s[i+ln:]
            l = subs.find('"')
            tcap_hex = subs[0:l]
            
            if (option_print_verbose):
                print("HEX  IN: " +  tcap_hex)
            
            # fuzzing of messages
            if (option_fuzzing_messages):
                for i in range (0, 1):
                    if tcap_hex != '':
                        tcap_hex_f = tcap_hex
                        position = int(random.randint(0, len(tcap_hex_f))/2)
                        position = position * 2
                        tcap_hex_f = tcap_hex_f[:position] + format(random.randint(0, 255), '02x') + tcap_hex_f[position + 2:]
                        tcap_hex = tcap_hex_f
                    
                    if (option_print_verbose):
                        print("FUZZ IN: " + tcap_hex)
            
            try:
                # decode using pycrate
                tcap = TCAP_MAP.TCAP_MAP_Messages.TCAP_MAP_Message
                tcap.from_ber(binascii.unhexlify(tcap_hex))
                
                tcap_decoded = tcap.get_val()
                # verbose output
                if (option_print_verbose):
                    print(tcap_decoded)
                    print(tcap.to_asn1())
                # 
                
                # re-encode using pycrate
                if (option_reencode == True):
                    tcap.set_val(tcap_decoded)
                    tcap_hex_out = str(binascii.hexlify(tcap.to_ber()))
                    if (option_print_verbose):
                        print("HEX OUT:" + tcap_hex_out)
                    
                    # decode again and try to check diff
                    tcap_reencoded = TCAP_MAP.TCAP_MAP_Messages.TCAP_MAP_Message
                    tcap_reencoded.from_ber(binascii.unhexlify(tcap_hex))
                    tcap_decoded = str(tcap.get_val())
                    tcap_reencoded_decoded = str(tcap.get_val())
                    if (tcap_decoded != tcap_reencoded_decoded):
                        print("!!!!!!! Re-encoding error begin !!!!!!!")
                        print("ENCODED  IN: " + tcap_hex)
                        print("RE-RENCODED: " + tcap_hex_out)
                        print(tcap_decoded)
                        print(tcap_reencoded_decoded)
                        print("!!!!!!! Re-encoding error end !!!!!!!")
                    #
                                                    
                #
                
            except Exception as err:
                print("!!!!!!! Exception begin !!!!!!!")
                print(err)
                traceback.print_exc()
                print("!!!!!!! Exception end !!!!!!!")
            

