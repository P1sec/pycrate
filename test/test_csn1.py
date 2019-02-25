# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2016. Benoit Michau. ANSSI.
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
# * File Name : test/test_csn1.py
# * Created : 2016-06-22
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from binascii import *
from timeit   import timeit

from pycrate_csn1dir.classmark_3_value_part           import classmark_3_value_part
from pycrate_csn1dir.ms_network_capability_value_part import ms_network_capability_value_part
from pycrate_csn1dir.ms_ra_capability_value_part      import ms_ra_capability_value_part
from pycrate_csn1dir.receive_npdu_number_list_value   import receive_npdu_number_list_value
from pycrate_csn1dir.si2quater_rest_octets            import si2quater_rest_octets
from pycrate_csn1dir.si_13_rest_octets                import si_13_rest_octets

from pycrate_csn1.csnobj import _with_json


def test_msnetcap():
    Obj = ms_network_capability_value_part.clone()
    buf = unhexlify(b'e5e034')
    val = [1, 1, 1, 0, 1, 0, 1, 1, [1, 1, 0, 0, 0, 0], 0, 0, 0, 1, 1, 0, 1, 0, 0]
    #
    Obj.from_bytes(buf)
    rep = Obj.repr()
    assert( Obj.get_val() == val )
    assert( Obj.to_bytes() == buf )
    #
    if _with_json:
        t = Obj.to_json()
        Obj.from_json(t)
        assert( Obj.get_val() == val )


def test_mscm3():
    Obj = classmark_3_value_part.clone()
    buf = unhexlify(b'601404cf65233b880092f28000')
    val = [0,
         ['110', [0, 0, 0, 0], 1, 4],
         ['0'],
         ['0'],
         0,
         0,
         ['0'],
         ['1', 6],
         ['0'],
         ['1', [1, ['1', 2], ['1', 2]]],
         ['0'],
         ['1', 4],
         ['1', 1],
         1,
         0,
         0,
         ['1', 3, 0, ['1', 3]],
         ['0'],
         ['0'],
         0,
         1,
         ['0'],
         ['0'],
         '0',
         0,
         0,
         0,
         ['0'],
         '0',
         1,
         0,
         ['0'],
         1,
         ['0'],
         ['0'],
         1,
         0,
         1,
         1,
         1,
         1,
         0,
         1,
         1,
         0,
         0,
         0,
         0,
         0,
         0,
         0,
         0,
         0,
         0,
         [0, 0, 0]]
    #
    Obj.from_bytes(buf)
    rep = Obj.repr()
    assert( Obj.get_val() == val )
    assert( Obj.to_bytes() == buf )
    #
    if _with_json:
        t = Obj.to_json()
        Obj.from_json(t)
        assert( Obj.get_val() == val )

def test_rcvnpdunumlist():
    Obj = receive_npdu_number_list_value.clone()
    # TODO: get a buffer to test against


def test_msracap():
    Obj = ms_ra_capability_value_part.clone()
    buf = unhexlify(b'1a53432b259ef9890040009dd9c633120080013a332c662401000260')
    val = [[['0001', # Access capabilities struct 1
           [82,
            [[4,
              ['1', [1, 0, 1, 0, 0, 0, 0]],
              1,
              1,
              0,
              0,
              ['1',
               [['0'],
                ['1', 12, 1],
                ['0'],
                ['0'],
                ['1', 12, 1],
                ['1', 3, 0, ['1', 3]]]],
              ['1', 2],
              0,
              1,
              1,
              0,
              0,
              0,
              1,
              ['0'],
              0,
              ['1', 0],
              '0',
              0,
              0,
              0,
              1,
              0,
              0,
              ['0'],
              0,
              0,
              ['0'],
              0,
              0,
              0,
              0,
              0,
              0,
              1,
              0,
              1,
              1],
             []]]],
          ['1', # more Access capabiities struct
           [['0111', # Access capabilities struct 2
             [51,
              [[4,
                ['0'],
                1,
                1,
                0,
                0,
                ['0'],
                ['1', 2],
                0,
                1,
                1,
                0,
                0,
                0,
                1,
                ['0'],
                0,
                ['1', 0],
                '0',
                0,
                0,
                0,
                1,
                0,
                0,
                ['0'],
                0,
                0,
                ['0'],
                0,
                0,
                0,
                0,
                0,
                0,
                1,
                0,
                1,
                1],
               []]]],
            ['1', # more Access capabiities struct
             [['0100', # Access capabilities struct 3
               [51,
                [[1,
                  ['0'],
                  1,
                  1,
                  0,
                  0,
                  ['0'],
                  ['1', 2],
                  0,
                  1,
                  1,
                  0,
                  0,
                  0,
                  1,
                  ['0'],
                  0,
                  ['1', 0],
                  '0',
                  0,
                  0,
                  0,
                  1,
                  0,
                  0,
                  ['0'],
                  0,
                  0,
                  ['0'],
                  0,
                  0,
                  0,
                  0,
                  0,
                  0,
                  1,
                  0,
                  1,
                  1],
                 []]]],
              ['0']]]]]], # no more Access capabiities struct
         [[0, 0, 0, 0]]] # spare bits
    #
    Obj.from_bytes(buf)
    rep = Obj.repr()
    assert( Obj.get_val() == val )
    assert( Obj.to_bytes() == buf )
    #
    if _with_json:
        t = Obj.to_json()
        Obj.from_json(t)
        assert( Obj.get_val() == val )
    
    #
    buf = unhexlify(b'1bb3432b259ef989004000d801bbe8c662401000360068f8b1989004000d8010')
    val = [[['0001',
           [93,
            [[4,
              ['1', [1, 0, 1, 0, 0, 0, 0]],
              1,
              1,
              0,
              0,
              ['1',
               [['0'],
                ['1', 12, 1],
                ['0'],
                ['0'],
                ['1', 12, 1],
                ['1', 3, 0, ['1', 3]]]],
              ['1', 2],
              0,
              1,
              1,
              0,
              0,
              0,
              1,
              ['0'],
              0,
              ['1', 0],
              '0',
              0,
              0,
              0,
              1,
              0,
              0,
              ['0'],
              0,
              0,
              ['0'],
              0,
              0,
              0,
              0,
              0,
              0,
              1,
              1,
              1,
              1,
              ['0'],
              0,
              0,
              0,
              0,
              0,
              0,
              0,
              0,
              1],
             []]]],
          ['1',
           [['0111',
             [62,
              [[4,
                ['0'],
                1,
                1,
                0,
                0,
                ['0'],
                ['1', 2],
                0,
                1,
                1,
                0,
                0,
                0,
                1,
                ['0'],
                0,
                ['1', 0],
                '0',
                0,
                0,
                0,
                1,
                0,
                0,
                ['0'],
                0,
                0,
                ['0'],
                0,
                0,
                0,
                0,
                0,
                0,
                1,
                1,
                1,
                1,
                ['0'],
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                1],
               []]]],
            ['1',
             [['0100',
               [62,
                [[1,
                  ['0'],
                  1,
                  1,
                  0,
                  0,
                  ['0'],
                  ['1', 2],
                  0,
                  1,
                  1,
                  0,
                  0,
                  0,
                  1,
                  ['0'],
                  0,
                  ['1', 0],
                  '0',
                  0,
                  0,
                  0,
                  1,
                  0,
                  0,
                  ['0'],
                  0,
                  0,
                  ['0'],
                  0,
                  0,
                  0,
                  0,
                  0,
                  0,
                  1,
                  1,
                  1,
                  1,
                  ['0'],
                  0,
                  0,
                  0,
                  0,
                  0,
                  0,
                  0,
                  0,
                  1],
                 []]]],
              ['0']]]]]],
         [[0, 0, 0]]]
    #
    Obj.from_bytes(buf)
    rep = Obj.repr()
    assert( Obj.get_val() == val )
    assert( Obj.to_bytes() == buf )
    #
    if _with_json:
        t = Obj.to_json()
        Obj.from_json(t)
        assert( Obj.get_val() == val )


def test_si2qr():
    Obj = si2quater_rest_octets.clone()
    buf = unhexlify(b'46a032caa88c2fcf8e0b2b2b2b2b2b2b2b2b2b2b')
    #
    Obj.from_bytes(buf)
    val = Obj.get_val()
    rep = Obj.repr()
    assert( Obj.to_bytes() == buf )
    #
    if _with_json:
        t = Obj.to_json()
        Obj.from_json(t)
        assert( Obj.get_val() == val )
    
    buf = unhexlify(b'cee0048648c0100401004010040100401000802b')
    #
    Obj.from_bytes(buf)
    val = Obj.get_val()
    rep = Obj.repr()
    assert( Obj.to_bytes() == buf )
    #
    if _with_json:
        t = Obj.to_json()
        Obj.from_json(t)
        assert( Obj.get_val() == val )
    
    buf = unhexlify(b'ef200bc10996463fc15010c1ceada382a02b2b2b')
    #
    Obj.from_bytes(buf)
    val = Obj.get_val()
    rep = Obj.repr()
    assert( Obj.to_bytes() == buf )
    #
    if _with_json:
        t = Obj.to_json()
        Obj.from_json(t)
        assert( Obj.get_val() == val )


def test_si13r():
    Obj = si_13_rest_octets.clone()
    buf = unhexlify(b'a0005847eb4a93e51a298a16ab2b2b2b2b2b2b2b')
    val = [['H',
          2,
          0,
          ['0'],
          ['0',
           1,
           0,
           6,
           0,
           [1,
            0,
            7,
            7,
            0,
            1,
            6,
            ['1', 1, 2, 4],
            ['1', 15, [[['1', 0, 5], 0, 0, 0], [1, 1], [0, 1, 0, ['0']], 0]]],
           [10, 12, 10, 0, 2]],
          ['H', 1, ['H', 1, ['L']]]],
         ['L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L',
          'L']]
    #
    Obj.from_bytes(buf)
    rep = Obj.repr()
    assert( Obj.get_val() == val )
    assert( Obj.to_bytes() == buf )
    #
    if _with_json:
        t = Obj.to_json()
        Obj.from_json(t)
        assert( Obj.get_val() == val )


def test_perf_csn1():
    
    print('[+] CSN.1 MS network capability decoding and re-encoding')
    Ta = timeit(test_msnetcap, number=600)
    print('test_msnetcap: {0:.4f}'.format(Ta))
    
    print('[+] CSN.1 MS classmark 3 decoding and re-encoding')
    Tb = timeit(test_mscm3, number=200)
    print('test_mscm3: {0:.4f}'.format(Tb))
    
    print('[+] CSN.1 MS radio access capability decoding and re-encoding')
    Tc = timeit(test_msracap, number=30)
    print('test_msracap: {0:.4f}'.format(Tc))
    
    print('[+] CSN.1 SI2 quater rest octets decoding and re-encoding')
    Td = timeit(test_si2qr, number=50)
    print('test_si2qr: {0:.4f}'.format(Td))
    
    print('[+] CSN.1 SI13 rest octets decoding and re-encoding')
    Te = timeit(test_si13r, number=200)
    print('test_si13r: {0:.4f}'.format(Te))
    
    print('[+] test_csn1 total time: {0:.4f}'.format(Ta+Tb+Tc+Td+Te))


if __name__ == '__main__':
    test_perf_csn1()

