# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.1
# *
# * Copyright © 2016. Benoit Michau. ANSSI.
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
# * File Name : test/test_csn1.py
# * Created : 2016-06-22
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from binascii import *

from pycrate_csn1dir.mscm3          import Classmark_3_Value_part
from pycrate_csn1dir.msnetcap       import MS_network_capability_value_part
from pycrate_csn1dir.msracap        import MS_RA_capability_value_part
from pycrate_csn1dir.rcvnpdunumlist import Receive_N_PDU_Number_list_value


def test_msnetcap():
    Obj = MS_network_capability_value_part
    buf = unhexlify('e5e034')
    val = [1, 1, 1, 0, 1, 0, 1, 1, [1, 1, 0, 0, 0, 0], 0, 0, 0, 1, 1, 0, 1, 0, 0]
    #
    Obj.from_bytes(buf)
    rep = Obj.__repr__()
    assert( Obj.get_val() == val )
    assert( Obj.to_bytes() == buf )
    
def test_msracap():
    Obj = MS_RA_capability_value_part
    buf = b'\x1aSC+%\x9e\xf9\x89\x00@\x00\x9d\xd9\xc63\x12\x00\x80\x01:3,f$\x01\x00\x02`'
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
           [[['0111', # Access capabilities struct 2
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
              [[['0100', # Access capabilities struct 3
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
                ['0']], # no more Access capabiities struct
               [0, 0, 0, 0]]]], # spare bits
            []]]], # spare bits
         []] # spare bits
    #
    Obj.from_bytes(buf)
    rep = Obj.__repr__()
    assert( Obj.get_val() == val )
    assert( Obj.to_bytes() == buf )

