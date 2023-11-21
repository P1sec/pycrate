# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.6
# *
# * Copyright 2023. Benoit Michau. P1Sec.
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
# * File Name : test/test_sms.py
# * Created : 2023-11-20
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from binascii   import unhexlify
from timeit     import timeit

from pycrate_mobile.TS23040_SMS import *

# SMS 7 bit character together with UDH requires complex alignment and padding
# Here is a harness test to ensure everything gets encoded / decoded properly

def test_tpudh(I=28, J=8):
    for i in range(0, I):
        for j in range(0, J):
            txt = i*'A'
            enc = SMS_SUBMIT(val={
                'TP_UDHI': 1,
                'TP_DA'  : {'Num': '33123456'},
                'TP_DCS' : {'Group': 0, 'Charset': 0, 'Class': 0},
                'TP_UD'  : {
                    'UDH' : {'UDH': [{'T': 2, 'V': j*b'\0'}]},
                    'UD'  : txt
                }})
            buf = enc.to_bytes()
            dec = SMS_SUBMIT()
            dec.from_bytes(buf)
            assert( dec['TP_UD']['UD'].decode() in (txt, txt+'\r') )


# For more real-cases testing, here are some wireshark filters to collect such kind of SMS
# gsm_sms.tp-dcs == 0 and gsm_sms.dis_field_udh.user_data_header_length != 6 and gsm_sms.ie_identifier != 0x00
# gsm_sms.dis_field_udh.gsm.fill_bits == 0x0 and gsm_sms.ie_identifier != 0x00


def test_perf_sms():
    
    print('[+] SMS_SUBMIT encoding and decoding with GSM 7-bit and TP-UDH')
    Ta = timeit(test_tpudh, number=5)
    print('test_tpudh: {0:.4f}'.format(Ta))


if __name__ == '__main__':
    test_perf_sms()

