# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.1
# *
# * Copyright © 2016. Benoit Michau. ANSSI.
# *
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# * 
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# * 
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# * 02110-1301, USA.
# *
# *--------------------------------------------------------
# * File Name : pycrate_core/utils.py
# * Created : 2016-02-23
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

import sys

if sys.version_info[0] < 3:
    from .utils_py2 import *
else:
    from .utils_py3 import *
#
# configure max recursion
#sys.setrecursionlimit(200)

#------------------------------------------------------------------------------#
# library wide logging function
#------------------------------------------------------------------------------#

def log(msg):
    print(msg)

#------------------------------------------------------------------------------#
# additional bit list functions
#------------------------------------------------------------------------------#

def bytelist_to_bitlist(bytelist):
    """Convert an iterable of bytes -uint8- to a list of bits -0 or 1-
    
    Args:
        bytelist (iterable of integer) : iterable of uint8 values (0<=X<=255)
    
    Returns:
        bitlist (list of integer) : list of 0 and 1
    
    Raises:
        KeyError : if bytelist contains invalid values
    """
    ret = []
    [ret.extend(ARRTOBIT_LUT[val]) for val in bytelist]
    return ret

def bitlist_to_bytelist(bitlist):
    """Convert an iterable of bits -0 or 1- to a list of bytes -uint8-
    
    Args:
        bitlist (iterable of integer) : iterable of 0 and 1
    
    Returns:
        bytelist (list of integer) : list of uint8 values (0<=X<=255)
    
    Raises:
        KeyError : if bitlist contains invalid values
    """
    ret = []
    # cast the iterable to a tuple for dict LU
    bitlist = tuple(bitlist)
    trail = len(bitlist) % 8
    if trail:
        [ret.append(BITTOARR_LUT[bitlist[i:i+8]]) \
            for i in range(0, len(bitlist)-trail, 8)]
        ret.append( BITTOARR_LUT[bitlist[-trail:] + (8-trail) * (0, )] )
        return ret
    else:
        [ret.append(BITTOARR_LUT[bitlist[i:i+8]]) \
            for i in range(0, len(bitlist), 8)]
        return ret

def uint_to_bitlist(uint):
    pass

def bitlist_to_uint(bitlist):
    pass

#------------------------------------------------------------------------------#
# Element definition helping routines
#------------------------------------------------------------------------------#

def get_typenames(*types):
    """Returns the name of types from a list of types"""   
    return tuple([t.__name__ for t in types])

def flatten(*args):
    """Returns a flat tuple from a serie of possibly nested arguments"""
    ret = []
    for a in args:
        try:
            ret.extend(flatten(*a))
        except:
            ret.append(a)
    return tuple(ret)

#------------------------------------------------------------------------------#
# Dictionnary routine
#------------------------------------------------------------------------------#

def reverse_dict(dic):
    """Reverses the {keys : values} of the input dict to {values : keys}"""
    return dict([(b, a) for (a, b) in dic.items()])

#------------------------------------------------------------------------------#
# decomposition routine
#------------------------------------------------------------------------------#

def decompose_uint_sl(sl=8, val=0):
    """Decompose a value in a list of factors of power of 2,
    i.e. 2 left-shifted by `sl'
    
    decompose_uint(X, Y) -> [a, b, c, d ...]
        where Y = a + (b << X) + (c << 2X) + (d << 3X) ...
    
    Args:
        sl  (integer) : unsigned integer used as left shifting argument
        val (integer) : unsigned integer to be factored
    
    Returns:
        dec (list of integers) : list of factors
    """
    mul = 1<<sl
    dec = [val%mul]
    while val >= mul:
        val >>= sl
        dec.append( val%mul )
    return dec

#------------------------------------------------------------------------------#
# integer functions
#------------------------------------------------------------------------------#

def bytes_to_int(buf, bitlen=1):
    """Convert the leftmost bits of a bytes buffer to a signed integer,
    2's complement representation with most significant bit leftmost
    
    Args:
        buf (bytes) : bytes string
        bitlen (integer) : length in bits
    
    Returns:
        int (integer) : signed integer value
    
    Raises:
        PycrateErr : if `bitlen' is not strictly positive or if `buf' is not 
        long enough
    """
    uint = bytes_to_uint(buf, bitlen)
    if uint >= 1<<(bitlen-1):
        # 2's complement
        return uint - (1<<bitlen)
    else:
        return uint

def int_to_bytes(val, bitlen=1):
    """Convert a signed integer to a bytes buffer of given length in bits,
    int with 2's complement representation and most significant bit leftmost
    
    Args:
        val (integer) : signed integer
        bitlen (integer) : length in bits
    
    Returns:
        buf (bytes) : bytes string
    
    Raises:
        PycrateErr : if `bitlen' is not strictly positive
    """
    if val < 0:
        # 2's complement
        return uint_to_bytes((1<<bitlen)+val, bitlen )
    else:
        return uint_to_bytes(val, bitlen)

