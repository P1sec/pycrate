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
# * File Name : test/test_gmr1.py
# * Created : 2023-11-21
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from binascii import *
from timeit     import timeit

from pycrate_gmr1.TS101376_04_08 import *


# All the test PDUs are taken from https://osmocom.org/projects/gmr/wiki/Example_Data

SI1 = tuple(map(unhexlify, (
    '08686bc8b000011041380000000000000000000000000000', # 3h
    '08686bc8b00001104185b908bef147b6eeeb5abffffa0000', # 2Bbis
    '08686bc8b00001104148242dcc8f04451501f41465f4a100', # 3I
    '08686bc8b00001104150000025f4f3eefb3cd78042000000', # 3Jbis
    '08686bc8b000011041c600cfc9c12d82e200000000000000', # 4D
    '08686bc8b00001104181a082b664def84bffffffc3000000', # 2Abis
    '08686bc8b000011041004f8a8029023db8ae1dba898094f0', # 3A
    '08686bc8b0000110410800000000000000000000000200f0', # 3Bbis
    '08686bc8b0000110411078341afecfc00000000000000000', # 3C
    '08686bc8b000011041180000000000000000000000000000', # 3D
    '08686bc8b000011041200000000000000000000000000000', # 3Ebis
    '08686bc8b000011041c969300480a0910440000000000000', # 4E
    '08686bc8b000011041280000000000000000000000000000', # 3F
    '08686bc8b00001104130063f3c5180018880000000000000', # 3Gbis
    )))

PagingT3 = tuple(map(unhexlify, (
    '5d062400cc00000000cd00000000ce03f00000cf00000000',
    '5d062400a4a494e580a5336f4b80a66cc88480a707000480',
    '5d062400084100008009000100800a0000ff800b44150080',
    '5d062400a85594a980a940f92d80aafd3c0080aba10d3580',
    )))

ImmAss = tuple(map(unhexlify, (
    '3d063f0042606ff61da431c1ee5d80202b2b2b2b2b2b2b2b',
    )))

RRPDU = tuple(map(unhexlify, (
    '0635117522090b0c83c26ab4d10084', # CipherModeCmd
    '06102424304101', # ChannelMod
    '060d00', # ChannelRel
    )))


def test_gmr():
    #
    # system info type 1
    sit1 = system_information_type_1.clone()
    for b in SI1:
        sit1.from_bytes(b)
        v = sit1.get_val()
        sit1 = system_information_type_1.clone()
        sit1.set_val(v)
        assert( sit1.to_bytes() == b )
    #
    # paging
    prt3 = GMR1PagingReq3()
    for b in PagingT3:
        prt3.from_bytes(b)
        v = prt3.get_val()
        prt3 = GMR1PagingReq3()
        prt3.set_val(v)
        assert( prt3.to_bytes() == b )
    #
    # immediate assignment
    ia = GMR1ImmediateAssignment()
    for b in ImmAss:
        ia.from_bytes(b)
        v = ia.get_val()
        ia = GMR1ImmediateAssignment()
        ia.set_val(v)
        assert( ia.to_bytes() == b )
    #
    # L3 GMR1CipherModeCmd
    m = GMR1CipherModeCmd()
    m.from_bytes(RRPDU[0])
    v = m.get_val()
    m.set_val(v)
    assert( m.to_bytes() == RRPDU[0] )
    #
    # L3 GMR1ChannelModeModify
    # WNG: discrepancy with GSM 44.018 section 9.1.5 (where ChannelDesc is 3 bytes, not 4)
    #m = GMR1ChannelModeModify()
    #m.from_bytes(RRPDU[1])
    #v = m.get_val()
    #m.set_val(v)
    #assert( m.to_bytes() == RRPDU[1] )
    #
    # L3 GMR1ChannelRelease
    m = GMR1ChannelRelease()
    m.from_bytes(RRPDU[2])
    v = m.get_val()
    m.set_val(v)
    assert( m.to_bytes() == RRPDU[2] )


def test_perf_gmr():
    
    print('[+] GMR-1 L3 and CSN.1 encoding and decoding')
    Ta = timeit(test_gmr, number=50)
    print('test_gmr1: {0:.4f}'.format(Ta))


if __name__ == '__main__':
    test_perf_gmr()

