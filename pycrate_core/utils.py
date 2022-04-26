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

try:
    import platform
except ImportError:
    python_implementation = 'Unknown'
else:
    python_implementation = platform.python_implementation()
    # can be 'CPython' or 'PyPy'
 
#------------------------------------------------------------------------------#
# library wide logging function
#------------------------------------------------------------------------------#

def log(msg):
    print(msg)

#------------------------------------------------------------------------------#
# additional bit list / str functions
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

def bytes_to_bitstr(buf):
    """Convert a bytes string to a str of 0 and 1
    
    Args:
        buf (bytes) : bytes string
    
    Returns:
        bitlstr (str of integer) : str of 0 and 1
    
    Raises:
        KeyError : if `s' is not bytes
    """
    bl = 8*len(buf)
    return uint_to_bitstr(bytes_to_uint(buf, bl), bl)

def bitstr_to_bytes(bitstr):
    """Convert a str of 0 and 1 to a bytes string
    
    Args:
        bitstr (str of integer) : str of 0 and 1
    
    Returns:
        buf (bytes) : bytes string
    
    Raises:
        KeyError : if bitstr contains invalid values
    """
    return uint_to_bytes(bitstr_to_uint(bitstr), len(bitstr))

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
        except Exception:
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

def uint_to_bitstr(uint, bitlen):
    """Convert an unsigned integer uint of length bitlen to a str of 0 and 1
    
    Args:
        uint (unsigned integer)
        bitlen (unsigned integer)
    
    Returns:
        bitstr (str of 0 and 1)
    """
    bl = bin(uint)[2:]
    if len(bl) < bitlen:
        # extend v
        bl = '0'*(bitlen-len(bl)) + bl
    return bl

def bitstr_to_uint(bitstr):
    """Convert a str of 0 and 1 to an unsigned integer uint
    
    Args:
        bitstr (str of 0 and 1)
    
    Returns:
        uint (unsigned integer)
    """
    return int(bitstr, 2)

def uint_to_bitlist(uint, bitlen):
    """Convert an unsigned integer uint of length bitlen to a list of 0 and 1
    
    Args:
        uint (unsigned integer)
        bitlen (unsigned integer)
    
    Returns:
        bitlist (list of 0 and 1)
    """
    return [0 if b == '0' else 1 for b in uint_to_bitstr(uint, bitlen)]

def bitlist_to_uint(bitlist):
    """Convert a list of 0 and 1 to an unsigned integer uint
    
    Args:
        bitstr (list of 0 and 1)
    
    Returns:
        uint (unsigned integer)
    """
    return int(''.join(['1' if b else '0' for b in bitlist]), 2)

def int_to_bytes(val, bitlen=1):
    """Convert a signed integer to a bytes buffer of given length in bits,
    int with 2's complement representation and most significant bit leftmost
    
    Args:
        val (integer) : signed integer
        bitlen (integer) : length in bits
    
    Returns:
        buf (bytes) : bytes string
    """
    if val < 0:
        # 2's complement
        return uint_to_bytes((1<<bitlen)+val, bitlen)
    else:
        return uint_to_bytes(val, bitlen)

def bytes_to_int(buf, bitlen=1):
    """Convert the leftmost bits of a bytes buffer to a signed integer,
    2's complement representation with most significant bit leftmost
    
    Args:
        buf (bytes) : bytes string
        bitlen (integer) : length in bits
    
    Returns:
        val (integer) : signed integer value
    """
    uint = bytes_to_uint(buf, bitlen)
    if uint >= 1<<(bitlen-1):
        # 2's complement
        return uint - (1<<bitlen)
    else:
        return uint

def int_to_bitstr(val, bitlen):
    """Convert a signed integer val of length bitlen to a str of 0 and 1
    
    Args:
        val (signed integer)
        bitlen (unsigned integer)
    
    Returns:
        bitstr (str of 0 and 1)
    """
    if val < 0:
        # 2's complement
        return uint_to_bitstr((1<<bitlen)+val, bitlen)
    else:
        return uint_to_bitstr(val, bitlen)

def bitstr_to_int(bitstr):
    """Convert a str of 0 and 1 to a signed integer val
    
    Args:
        bitstr (str of 0 and 1)
    
    Returns:
        val (signed integer)
    """
    uint, bitlen = int(bitstr, 2), len(bitstr)
    if uint >= 1<<(bitlen-1):
        # 2's complement
        return uint - (1<<bitlen)
    else:
        return uint

def int_to_bitlist(val, bitlen):
    """Convert a signed integer val of length bitlen to a list of 0 and 1
    
    Args:
        val (signed integer)
        bitlen (unsigned integer)
    
    Returns:
        bitlist (list of 0 and 1)
    """
    if val < 0:
        # 2's complement
        return uint_to_bitlist((1<<bitlen)+val, bitlen)
    else:
        return uint_to_bitlist(val, bitlen)

def bitlist_to_int(bitlist):
    """Convert a list of 0 and 1 to a signed integer val
    
    Args:
        bitstr (str of 0 and 1)
    
    Returns:
        val (signed integer)
    """
    uint, bitlen = bitlist_to_uint(bitlist), len(bitlist)
    if uint >= 1<<(bitlen-1):
        # 2's complement
        return uint - (1<<bitlen)
    else:
        return uint

def swap_int(val, bitlen):
    """Swap the endianness of the signed integer val of length bitlen
    
    Args:
        val (signed integer)
        bitlen (unsigned integer)
    
    Returns:
        ret (signed integer)
    """
    if val < 0:
        # 2's complement
        tmp = swap_uint((1<<bitlen)+val, bitlen)
    else:
        tmp = swap_uint(val, bitlen)
    if tmp >= 1<<(bitlen-1):
        return tmp - (1<<bitlen)
    else:
        return tmp

def uint_to_hex(uint, bitlen):
    """Return the string of hexadecimal character representing the unsigned 
    integer uint (big-endian)
    
    Args:
        uint (unsigned integer)
        bitlen (unsigned integer)
    
    Returns:
        hex (str of hex chars)
    """
    if bitlen == 0:
        return ''
    niblen = bitlen>>2
    if bitlen % 4:
        niblen += 1
        # not nibble-aligned, need to left-shift the uint value
        uint <<= 4 - (bitlen%4)
    h = hex(uint)
    if h[-1] == 'L':
        h = h[2:-1]
    else:
        h = h[2:]
    if len(h) < niblen:
        return (niblen-len(h))*'0' + h
    else:
        return h

#------------------------------------------------------------------------------#
# structure duplication routine
#------------------------------------------------------------------------------#

_atomic_types = str_types + bytes_types + integer_types + (NoneType, bool)

def cpstruct(struct, wobj=False):
    """Return an identical object to struct in terms of internal values, but with 
    copied wrapping structures. Values need to be integer or string (or any object
    if wobj is set to True), wrapping structures need to be tuple, list, set or dict.
    
    Args:
        struct (tuple, list, set or dict)
    
    Returns:
        tuple, list, set or dict with identical value
    
    Raises:
        ValueError in case of invalid struct type
        except if wobj is set to True, where any object is returned as is
    """
    
    if isinstance(struct, (tuple, list, set)):
        return struct.__class__([cpstruct(i) for i in struct])
    elif isinstance(struct, dict):
        return {cpstruct(i): cpstruct(j) for i, j in struct.items()}
    elif wobj:
        return struct
    elif isinstance(struct, _atomic_types):
        return struct
    else:
        raise(ValueError('invalid argument of type %s' % type(struct)))

