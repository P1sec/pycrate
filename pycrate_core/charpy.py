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
# * File Name : pycrate_core/charpy.py
# * Created : 2016-02-09
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = ['CharpyErr', 'Charpy']

from .utils import *

#------------------------------------------------------------------------------#
# Charpy specific error
#------------------------------------------------------------------------------#

class CharpyErr(PycrateErr):
    pass

#------------------------------------------------------------------------------#
# Charpy object
#------------------------------------------------------------------------------#

class Charpy(object):
    """
    Charpy is a bit-stream handler
    
    It has ways to work over aligned and unaligned bit-stream,
    exposing methods to:
    - convert it to bytes buffer, bytelist, bitlist, unsigned integer, 
      signed integer
    - consume it byte by byte or bit by bit to produce bytes buffer, bytelist, 
      bitlist, unsigned integer, signed integer
    
    It uses the following attributes:
    - _buf: bytes buffer
    - _len_bit: buffer length in bits
    - _cur: buffer cursor value in bits
    - _REPR: to configure the instance representation
    """
    
    _REPR_POS = ('buf', 'bytelist', 'bitlist', 'uint', 'int', 'hex', 'bin')
    _REPR = 'buf'
    _REPR_MAX = 512
    
    def __init__(self, buf=None):
        """Initialize the charpy instance
        
        Args:
            buf (bytes or None): bytes buffer to initialize the charpy instance
                _buf attribute; if None, _buf stays empty   
        """
        # initialize cursor
        self._cur = 0
        # initialize the intermediate container for concatenation
        self._concat = []
        
        # initialize internal value
        if buf is None:
            self._buf = b''
            self._len_bit = 0
        else:
            self.set_bytes(buf)
    
    def _pack(self):
        if not self._concat:
            return
        # concatenate the content in _concat at the end of the current instance
        cur = self._cur
        self._cur = 0
        self._concat.insert(0, (TYPE_BYTES, self._buf, self._len_bit))
        self.set_bytes( *pack_val(*self._concat) )
        self._concat = []
        self._cur = cur
    
    def len_bit(self):
        """Return the length in bits
        
        Returns:
            len_bit (integer): length in bits of the remaining buffer
        """
        if self._concat: self._pack()
        return self._len_bit - self._cur
    
    def len_byte(self):
        """Return the length in bytes
        
        Returns:
            len_byte (integer): length in bytes of the remaining buffer 
        """
        bitlen = self.len_bit() 
        if bitlen % 8:
            return 1+(bitlen>>3)
        else:
            return bitlen>>3
    
    def bin(self):
        """Provide a binary representation of the remaining buffer
        
        Returns:
            bit_str (str): string of 0 and 1
        """
        bitlen = self.len_bit()
        if bitlen == 0:
            return ''
        else:
            return uint_to_bitstr(self.to_uint(), bitlen)
    
    def hex(self):
        """Provide an hexadecimal representation of the remaining buffer
        
        Returns:
            hex_str (str): string of hex character
        """
        bitlen = self.len_bit()
        if bitlen == 0:
            return ''
        else:
            return uint_to_hex(self.to_uint(), bitlen)
    
    # _REPR_POS = ('buf', 'bytelist', 'bitlist', 'uint', 'int', 'hex', 'bin')
    def repr(self):
        """Provide a printable representation of the remaining buffer
        
        Returns:
            repr_str (str): string, according to _REPR and _REPR_MAX attributes 
        """
        if self._REPR == 'buf' or self._REPR not in self._REPR_POS:
            # bytes buffer, default one
            r = self.to_bytes()
            if len(r) > self._REPR_MAX:
                if python_version < 3:
                    return 'charpy(b{0}...{1})'.format(
                        repr(r[0:self._REPR_MAX])[:-1], repr(r[-2:])[1:])
                else:
                    return 'charpy({0}...{1})'.format(
                        repr(r[0:self._REPR_MAX])[:-1], repr(r[-2:])[2:])
            elif python_version < 3:
                return 'charpy(b{0})'.format(repr(r))
            else:
                return 'charpy({0})'.format(repr(r))
        elif self._REPR == 'bytelist':
            # list of bytes
            r = self.to_bytelist()
            if len(r) > self._REPR_MAX:
                return 'charpy([{0}, ..., {1}])'.format(\
                        repr(r[0:self._REPR_MAX])[1:-1], r[-1])
            else:
                return 'charpy({0})'.format(repr(r))
        elif self._REPR == 'bitlist':
            # list of bits
            r = self.to_bitlist()
            if len(r) > self._REPR_MAX:
                return 'charpy([{0}, ..., {1}])'.format(\
                        repr(r[0:self._REPR_MAX])[1:-1], r[-1])
            else:
                return 'charpy({0})'.format(repr(r))
        elif self._REPR == 'uint':
            # big unsigned int
            r = repr(self.to_uint())
            if r[-1] == 'L':
                # Python2 long case
                r = r[:-1]
            if len(r) > self._REPR_MAX:
                return 'charpy({0}...{1})'.format(r[0:self._REPR_MAX], r[-1])
            else:
                return 'charpy({0})'.format(r)
        elif self._REPR == 'int':
            # big signed int
            r = repr(self.to_int())
            if r[-1] == 'L':
                r = r[:-1]
            if len(r) > self._REPR_MAX:
                return 'charpy({0}...{1})'.format(r[0:self._REPR_MAX], r[-1])
            else:
                return 'charpy({0})'.format(r)
        elif self._REPR == 'bin':
            # string of 0 and 1
            r = self.bin()
            if len(r) > self._REPR_MAX:
                return 'charpy(0b{0}...{1})'.format(r[0:self._REPR_MAX], r[-1])
            else:
                return 'charpy(0b{0})'.format(r)
        elif self._REPR == 'hex':
            # string of hex char
            r = self.hex()
            if len(r) > self._REPR_MAX:
                return 'charpy(0x{0}...{1})'.format(r[0:self._REPR_MAX], r[-1])
            else:
                return 'charpy(0x{0})'.format(r)
    
    def rewind(self, bitlen=None):
        """Rewind the charpy instance's cursor for the given bit length
        
        Args:
            bitlen : None or unsigned integer
                if None, rewinds the charpy instance completely
                else, rewinds for the given number of bits
        
        Returns:
            None
        """
        if self._concat: self._pack()
        if bitlen is None or bitlen > self._cur:
            self._cur = 0
        elif bitlen > 0:
            self._cur -= bitlen
    
    def forward(self, bitlen=None):
        """Set the charpy instance's cursor foward for the given bit length
        
        Args:
            bitlen : None or unsigned integer
                if None, set the cursor at the end of the charpy instance
                else, set the cursor forward for the given number of bits
        
        Returns:
            None
        """
        if self._concat: self._pack()
        if bitlen is None or bitlen > (self._len_bit - self._cur):
            self._cur = self._len_bit
        elif bitlen > 0:
            self._cur += bitlen
    
    def set_bytes(self, buf=b'', bitlen=None):
        """Reinitialize the charpy instance and its cursor by setting a Python 
        bytes buffer into it
        
        Args:
            buf (bytes) : bytes buffer
            bitlen (integer) : length in bits for the buffer
                if None, the whole bytes buffer is taken as is
        
        Returns:
            None
        
        Raises:
            CharpyErr : if `buf' has not the correct type
        """
        if not isinstance(buf, bytes_types):
            raise(CharpyErr('invalid argument type: {0}, expecting bytes'\
                            .format(type(buf).__name__)))
        elif bitlen is None or bitlen < 0 or bitlen > 8*len(buf):
            self._len_bit = 8*len(buf)
            self._buf = buf
        elif bitlen == 0:
            self._len_bit = 0
            self._buf = b''
        else:
            self._len_bit = bitlen
            self._buf = buf
        self._cur = 0
        self._concat = []
    
    def append_bytes(self, buf=b'', bitlen=None):
        """Append a bytes buffer at the end of the charpy instance
        
        Args:
            buf (bytes) : bytes buffer to be appended
            bitlen (integer) : length in bits for the buffer to append
                if None, the whole bytes buffer is taken as is
        
        Returns:
            None
        
        Raises:
            CharpyErr : if `buf' has not the correct type
        """
        if not isinstance(buf, bytes_types):
            raise(CharpyErr('invalid argument type: {0}'.format(type(buf))))
        elif bitlen is None or bitlen > 8*len(buf):
            bitlen = 8*len(buf)
        elif bitlen <= 0:
            return
        self._concat.append( (TYPE_BYTES, buf, bitlen) )
    
    def to_bytes(self, bitlen=None):
        """Provide the bytes buffer of the charpy instance, starting at the 
        current cursor position and ending after the given bitlen
        
        Args:
            bitlen (integer) : length in bits for the requested bytes buffer
                if None, the whole charpy bytes buffer is returned
        
        Returns:
            buf (bytes) : the current charpy bytes buffer
                if not byte-aligned, it is padded with 0 bits rightmost
        
        Raises:
            CharpyErr : if `bitlen' is negative or overflow the maximum bitlen
        """
        if self._concat: self._pack()
        if bitlen is None:
            # get the whole charpy buffer
            bitlen = self._len_bit - self._cur
        elif bitlen < 0:
            raise(CharpyErr('negative bitlen: {0}'.format(bitlen))) 
        elif self._cur + bitlen > self._len_bit:
            raise(CharpyErr('bitlen overflow: {0}, max {1}'\
                            .format(bitlen, self._len_bit-self._cur)))
        elif bitlen == 0:
            return b''
        off_byte, off_bit = self._cur >>3, self._cur % 8
        len_byte, len_bit = bitlen >>3, bitlen % 8
        if off_bit == 0:
            # aligned access
            if len_bit == 0:
                # byte-aligned buffer
                return self._buf[off_byte:off_byte+len_byte]
            else:
                # byte-unaligned buffer
                # need to zero last bits of the last byte
                return bytes_zero_last_bits(
                        self._buf[off_byte:off_byte+len_byte+1], 8-len_bit)
        else:
            # unaligned access
            if off_bit + len_bit > 8:
                buf = bytes_lshift(self._buf[off_byte:off_byte+len_byte+2], 
                                   off_bit)[:-1]
            else:
                buf = bytes_lshift(self._buf[off_byte:off_byte+len_byte+1], 
                                   off_bit)
                if len_bit == 0:
                    return buf[:-1]
            # len_bit > 0
            # need to zero last bits of the last byte
            return bytes_zero_last_bits(buf, 8-len_bit)
    
    def get_bytes(self, bitlen=None):
        """Consume the bytes buffer of the charpy instance, starting at the
        current cursor position and ending after the given bitlen
        
        the charpy instance's cursor is incremented according to bitlen
        
        Args:
            bitlen (integer) : length in bits for the requested bytes buffer
                if None, the whole charpy bytes buffer is returned
        
        Returns:
            buf (bytes) : the current charpy bytes buffer
                if not byte-aligned, it is padded with 0 bits rightmost
        
        Raises:
            CharpyErr : if `bitlen' is negative or overflow the maximum bitlen
        """
        if self._concat: self._pack()
        if bitlen is None:
            # get the whole charpy buffer
            bitlen = self._len_bit - self._cur
        elif bitlen < 0:
            raise(CharpyErr('negative bitlen: {0}'.format(bitlen))) 
        elif self._cur + bitlen > self._len_bit:
            raise(CharpyErr('bitlen overflow: {0}, max {1}'\
                            .format(bitlen, self._len_bit-self._cur)))
        elif bitlen == 0:
            return b''
        off_byte, off_bit = self._cur >>3, self._cur % 8
        len_byte, len_bit = bitlen >>3, bitlen % 8
        self._cur += bitlen
        if off_bit == 0:
            # aligned access
            if len_bit == 0:
                # byte-aligned buffer
                return self._buf[off_byte:off_byte+len_byte]
            else:
                # byte-unaligned buffer
                # need to zero last bits of the last byte
                return bytes_zero_last_bits(
                        self._buf[off_byte:off_byte+len_byte+1], 8-len_bit)
        else:
            # unaligned access
            if off_bit + len_bit > 8:
                buf = bytes_lshift(self._buf[off_byte:off_byte+len_byte+2], 
                                   off_bit)[:-1]
            else:
                buf = bytes_lshift(self._buf[off_byte:off_byte+len_byte+1], 
                                   off_bit)
                if len_bit == 0:
                    return buf[:-1]
            # len_bit > 0
            # need to zero last bits of the last byte
            return bytes_zero_last_bits(buf, 8-len_bit)
    
    def set_bytelist(self, bytelist=[], bitlen=None):
        """Reinitialize the charpy instance and its cursor by setting a list of
        uint8 integer values into it
        
        Args:
            bytelist (iterable of integer) : iterable of uint8 values
            bitlen (integer) : length in bits for the bytelist
                if None, the whole bytelist is taken as is
        
        Returns:
            None
              
        Raises:
            CharpyErr : if `bytelist' has not the correct format
        """
        try:
            self._buf = bytelist_to_bytes(bytelist)
        except Exception:
            raise(CharpyErr('invalid argument: {0}'.format(bytelist)))
        if bitlen is None or bitlen <= 0 or bitlen > 8*len(bytelist):
            self._len_bit = 8*len(bytelist)
        else:
            self._len_bit = bitlen
        self._cur = 0
        self._concat = []
    
    def to_bytelist(self, bitlen=None):
        """Provide the bytelist of the charpy instance, starting at the current 
        cursor position and ending after the given bitlen
        
        Args:
            bitlen (integer) : length in bits for the requested bytelist
                if None, the whole charpy bytelist is returned
        
        Returns:
            bytelist (list of integer) : the current charpy bytelist
                if not byte-aligned, it is padded with 0 bits rightmost
        
        Raises:
            CharpyErr : if `bitlen' is negative or overflow the maximum bitlen
        """
        if self._concat: self._pack()
        if bitlen is None:
            # get the whole charpy buffer
            bitlen = self._len_bit - self._cur
        elif bitlen < 0:
            raise(CharpyErr('negative bitlen: {0}'.format(bitlen))) 
        elif self._cur + bitlen > self._len_bit:
            raise(CharpyErr('bitlen overflow: {0}, max {1}'\
                            .format(bitlen, self._len_bit-self._cur)))
        elif bitlen == 0:
            return []
        off_byte, off_bit = self._cur >>3, self._cur % 8
        len_byte, len_bit = bitlen >>3, bitlen % 8
        if off_bit == 0:
            # aligned access
            if len_bit == 0:
                return bytes_to_bytelist(self._buf[off_byte:off_byte+len_byte])
            else:
                ret = bytes_to_bytelist(self._buf[off_byte:off_byte+len_byte+1])
                ret[-1] &= ((1<<len_bit)-1)<<(8-len_bit)
                return ret
        else:
            # unaligned access
            if off_bit + len_bit > 8:
                ret = bytes_lshift(self._buf[off_byte:off_byte+len_byte+2],
                                   off_bit)[:-1]
            else:
                ret = bytes_lshift(self._buf[off_byte:off_byte+len_byte+1],
                                   off_bit)
                if len_bit == 0:
                    return bytes_to_bytelist(ret[:-1])
            # len_bit > 0
            # need to zero last bits of the last byte
            ret = bytes_to_bytelist(ret)
            ret[-1] &= ((1<<len_bit)-1)<<(8-len_bit)
            return ret
    
    def get_bytelist(self, bitlen=None):
        """Consume the bytelist of the charpy instance, starting at the current 
        cursor position and ending after the given bitlen
        
        the charpy instance's cursor is incremented according to bitlen
        
        Args:
            bitlen (integer) : length in bits for the requested bytelist
                if None, the whole charpy bytelist is returned
        
        Returns:
            bytelist (list of integer) : the current charpy bytelist
                if not byte-aligned, it is padded with 0 bits rightmost
        
        Raises:
            CharpyErr : if `bitlen' is negative or overflow the maximum bitlen
        """
        if self._concat: self._pack()
        if bitlen is None:
            # get the whole charpy buffer
            bitlen = self._len_bit - self._cur
        elif bitlen < 0:
            raise(CharpyErr('negative bitlen: {0}'.format(bitlen))) 
        elif self._cur + bitlen > self._len_bit:
            raise(CharpyErr('bitlen overflow: {0}, max {1}'\
                            .format(bitlen, self._len_bit-self._cur)))
        elif bitlen == 0:
            return []
        off_byte, off_bit = self._cur >>3, self._cur % 8
        len_byte, len_bit = bitlen >>3, bitlen % 8
        self._cur += bitlen
        if off_bit == 0:
            # aligned access
            if len_bit == 0:
                return bytes_to_bytelist(self._buf[off_byte:off_byte+len_byte])
            else:
                ret = bytes_to_bytelist(self._buf[off_byte:off_byte+len_byte+1])
                ret[-1] &= ((1<<len_bit)-1)<<(8-len_bit)
                return ret
        else:
            # unaligned access
            if off_bit + len_bit > 8:
                ret = bytes_lshift(self._buf[off_byte:off_byte+len_byte+2],
                                   off_bit)[:-1]
            else:
                ret = bytes_lshift(self._buf[off_byte:off_byte+len_byte+1],
                                   off_bit)
                if len_bit == 0:
                    return bytes_to_bytelist(ret[:-1])
            # len_bit > 0
            # need to zero last bits of the last byte
            ret = bytes_to_bytelist(ret)
            ret[-1] &= ((1<<len_bit)-1)<<(8-len_bit)
            return ret

    def set_bitlist(self, bitlist=[]):
        """Reinitialize the charpy instance and its cursor by setting a list of
        binary integer values into it
        
        Args:
            bitlist (iterable of integer) : iterable of 0 and 1
        
        Returns:
            None
              
        Raises:
            CharpyErr : if `bitlist' has not the correct format
        """
        try:
            self._buf = bitlist_to_bytes(bitlist)
        except Exception:
            raise(CharpyErr('invalid argument: {0}'.format(bitlist)))
        self._len_bit = len(bitlist)
        self._cur = 0
        self._concat = []
    
    def to_bitlist(self, bitlen=None):
        """Provide the bitlist of the charpy instance, starting at the current 
        cursor position and ending after the given bitlen
        
        Args:
            bitlen (integer) : length for the requested bitlist
                if None, the whole charpy bitlist is returned
        
        Returns:
            bitlist (list of integer) : the current charpy bitlist
        
        Raises:
            CharpyErr : if `bitlen' is negative or overflow the maximum bitlen
        """
        if self._concat: self._pack()
        if bitlen is None:
            # get the whole charpy buffer
            bitlen = self._len_bit - self._cur
        elif bitlen < 0:
            raise(CharpyErr('negative bitlen: {0}'.format(bitlen))) 
        elif self._cur + bitlen > self._len_bit:
            raise(CharpyErr('bitlen overflow: {0}, max {1}'\
                            .format(bitlen, self._len_bit-self._cur)))
        elif bitlen == 0:
            return []
        off_byte, off_bit = self._cur >>3, self._cur % 8
        len_byte, len_bit = bitlen >>3, bitlen % 8
        if off_bit == 0:
            # aligned access
            if len_bit:
                return bytes_to_bitlist( \
                        self.to_bytes(bitlen))[:len_bit-8]
            else:
                return bytes_to_bitlist(self.to_bytes(bitlen))
        else:
            self._cur -= off_bit
            ret = bytes_to_bitlist(self.to_bytes(bitlen+off_bit))
            self._cur += off_bit
            return ret[off_bit:bitlen+off_bit]
    
    def get_bitlist(self, bitlen=None):
        """Consume the bitlist of the charpy instance, starting at the current 
        cursor position and ending after the given bitlen
        
        the charpy instance's cursor is incremented according to bitlen
        
        Args:
            bitlen (integer) : length for the requested bitlist
                if None, the whole charpy bitlist is returned
        
        Returns:
            bitlist (list of integer) : the current charpy bitlist
        
        Raises:
            CharpyErr : if `bitlen' is negative or overflow the maximum bitlen
        """
        if self._concat: self._pack()
        if bitlen is None:
            # get the whole charpy buffer
            bitlen = self._len_bit - self._cur
        elif bitlen < 0:
            raise(CharpyErr('negative bitlen: {0}'.format(bitlen))) 
        elif self._cur + bitlen > self._len_bit:
            raise(CharpyErr('bitlen overflow: {0}, max {1}'\
                            .format(bitlen, self._len_bit-self._cur)))
        elif bitlen == 0:
            return []
        off_byte, off_bit = self._cur >>3, self._cur % 8
        len_byte, len_bit = bitlen >>3, bitlen % 8
        if off_bit == 0:
            # aligned access
            if len_bit:
                ret = bytes_to_bitlist( \
                        self.to_bytes(bitlen))[:len_bit-8]
            else:
                ret = bytes_to_bitlist(self.to_bytes(bitlen))
            self._cur += bitlen
            return ret
        else:
            # unaligned access
            # restore an aligned cursor to get a byte array
            self._cur -= off_bit
            ret = bytes_to_bitlist(self.to_bytes(bitlen+off_bit))
            self._cur += off_bit + bitlen
            return ret[off_bit:bitlen+off_bit]
    
    def set_uint(self, val=0, bitlen=None):
        """Reinitialize the charpy instance and its cursor by setting an 
        arbitrary unsigned integer value into it
        
        big endian representation is used (most significant byte leftmost, 
        least significant byte rightmost)
        
        Args:
            val (integer) : unsigned integer
            bitlen (integer) : number of bits to be used to store the value
                if less than required by the value, value is majored to the 
                maximum uint value according to bitlen
                if None, encoding is done in the minimum number of bits
        
        Returns:
            None
        
        Raises:
            CharpyErr : if `val' has not the correct type or is negative
        """
        if not isinstance(val, integer_types):
            raise(CharpyErr('invalid argument type: {0}'\
                            .format(type(val).__name__)))
        elif val < 0:
            raise(CharpyErr('invalid argument value: {0}'.format(val)))
        elif bitlen is None or bitlen < 0:
            # Python 2.7 and 3 built-in
            bitlen = val.bit_length()
        if bitlen == 0:
            self._buf = b''
        else:
            self._buf = uint_to_bytes(val, bitlen)
        self._len_bit = bitlen
        self._cur = 0
        self._concat = []
    
    def append_uint(self, val=0, bitlen=None):
        """Append an unsigned integer value at the end of the charpy instance
        
        big endian representation is used (most significant byte leftmost, 
        least significant byte rightmost)
        
        Args:
            val (integer) : unsigned integer
            bitlen (integer) : number of bits to be used to store the value
                if less than required by the value, value is majored to the 
                maximum uint value according to bitlen
                if None, encoding is done in the minimum number of bits
        
        Returns:
            None
        
        Raises:
            CharpyErr : if `val' has not the correct type or is negative
        """
        if not isinstance(val, integer_types):
            raise(CharpyErr('invalid argument type: {0}'\
                            .format(type(val).__name__)))
        elif val < 0:
            raise(CharpyErr('invalid argument value: {0}'.format(val)))
        elif bitlen is None or bitlen < 0:
            # Python 2.7 and 3 built-in
            bitlen = val.bit_length()
        elif bitlen == 0:
            return
        self._concat.append( (TYPE_UINT, val, bitlen) )
    
    def to_uint(self, bitlen=None):
        """Provide the unsigned integer value of the charpy instance, starting 
        at the current cursor position and ending after the given bitlen
        
        Args:
            bitlen (integer) : length in bits for the requested unsigned integer
                if None, the whole charpy unsigned integer value is returned
        
        Returns:
            uint (integer) : an unsigned integer value
                or None if cursor is at the end of charpy or bitlen is null
        
        Raises:
            CharpyErr : if `bitlen' is negative or overflow the maximum bitlen
        """
        if self._concat: self._pack()
        if bitlen is None:
            # get the whole charpy buffer
            bitlen = self._len_bit - self._cur
        elif bitlen < 0:
            raise(CharpyErr('negative bitlen: {0}'.format(bitlen))) 
        elif self._cur + bitlen > self._len_bit:
            raise(CharpyErr('bitlen overflow: {0}, max {1}'\
                            .format(bitlen, self._len_bit-self._cur)))
        elif bitlen == 0:
            return None
        off_byte, off_bit = self._cur >>3, self._cur % 8
        if off_bit == 0:
            # aligned access
            return bytes_to_uint(self._buf[off_byte:1+off_byte+(bitlen>>3)], bitlen)
        else:
            # unaligned access
            # convert from a fully-aligned byte buffer with an extended length
            # bytes_to_uint takes care of converting only `bitlen+off_bit' bits
            # and finally zero the extra left-most bits
            return bytes_to_uint(self._buf[off_byte:2+off_byte+(bitlen>>3)],
                                 bitlen+off_bit) & ((1<<bitlen)-1)
    
    def get_uint(self, bitlen=None):
        """Consume the unsigned integer value of the charpy instance, starting 
        at the current cursor position and ending after the given bitlen
        
        the charpy instance's cursor is incremented according to bitlen
        
        Args:
            bitlen (integer) : length in bits for the requested unsigned integer
                if None, the whole charpy unsigned integer value is returned
        
        Returns:
            uint (integer) : an unsigned integer value
                or None if cursor is at the end or bitlen is null
        
        Raises:
            CharpyErr : if `bitlen' is negative or overflow the maximum bitlen
        """
        if self._concat: self._pack()
        if bitlen is None:
            # get the whole charpy buffer
            bitlen = self._len_bit - self._cur
        elif bitlen < 0:
            raise(CharpyErr('negative bitlen: {0}'.format(bitlen))) 
        elif self._cur + bitlen > self._len_bit:
            raise(CharpyErr('bitlen overflow: {0}, max {1}'\
                            .format(bitlen, self._len_bit-self._cur)))
        elif bitlen == 0:
            return None
        off_byte, off_bit = self._cur >>3, self._cur % 8
        self._cur += bitlen
        if off_bit == 0:
            # aligned access
            return bytes_to_uint(self._buf[off_byte:1+off_byte+(bitlen>>3)], bitlen)
        else:
            # unaligned access
            # convert from a fully-aligned byte buffer with an extended length
            # bytes_to_uint takes care of converting only `bitlen+off_bit' bits
            # and finally zero the extra left-most bits
            return bytes_to_uint(self._buf[off_byte:2+off_byte+(bitlen>>3)],
                                 bitlen+off_bit) & ((1<<bitlen)-1)
    
    def set_int(self, val=0, bitlen=None):
        """Reinitialize the charpy instance and its cursor by setting an 
        arbitrary signed integer value into it
        
        big endian representation is used (most significant byte leftmost,
        least significant byte rightmost) and 2's complement representation
        
        Args:
            val (integer) : signed integer
            bitlen (integer) : number of bits to be used to store the value
                if less than required by the absolute value, value is minored or
                majored to the maximum absolute value according to bitlen
                if None, encoding is done in the minimum number of bits (can be
                +1 to the real minimum of bits)
        
        Returns:
            None
        
        Raises:
            CharpyErr : if `val' has not the correct type
        """
        if not isinstance(val, integer_types):
            raise(CharpyErr('invalid argument type: {0}'\
                            .format(type(val).__name__)))
        elif bitlen is None or bitlen < 0:
            # Python built-in int.bit_length() does not take the sign into
            # account, and we add another bit of dynamic to avoid any issue
            bitlen = 1 + val.bit_length()
        elif bitlen == 0:
            self._buf = b''
            self._len_bit = 0
            self._cur = 0
            self._concat = []
            return
        #
        if val < 0:
            valmax = 1 << (bitlen-1)
            if val >= -valmax:
                # negative integer, sign bit + 2's complement
                self._buf = uint_to_bytes((valmax<<1) + val, bitlen)
            else:
                # minoring to the minimum possible negative value
                if bitlen % 8:
                    self._buf = b'\x80' + (bitlen>>3) * b'\0'
                else:
                    self._buf = b'\x80' + ((bitlen>>3)-1) * b'\0'
        else:
            self._buf = uint_to_bytes(val, bitlen)
        self._len_bit = bitlen
        self._cur = 0
        self._concat = []
    
    def append_int(self, val=0, bitlen=None):
        """Append a signed integer value at the end of the charpy instance
        
        big endian representation is used (most significant byte leftmost,
        least significant byte rightmost) and 2's complement representation
        
        Args:
            val (integer) : signed integer
            bitlen (integer) : number of bits to be used to store the value
                if less than required by the absolute value, value is minored or
                majored to the maximum absolute value according to bitlen
                if None, encoding is done in the minimum number of bits (can be
                +1 to the real minimum of bits)
        
        Returns:
            None
        
        Raises:
            CharpyErr : if `val' has not the correct type
        """
        if not isinstance(val, integer_types):
            raise(CharpyErr('invalid argument type: {0}'\
                            .format(type(val).__name__)))
        elif bitlen is None or bitlen < 0:
            bitlen =  1 + val.bit_length()
        elif bitlen == 0:
            return
        self._concat.append( (TYPE_INT, val, bitlen) )
    
    def to_int(self, bitlen=None):
        """Provide the signed integer value of the charpy instance, starting 
        at the current cursor position and ending after the given bitlen
        
        Args:
            bitlen (integer) : length in bits for the requested signed integer
                if None, the whole charpy signed integer value is returned
        
        Returns:
            uint (integer) : a signed integer value
                or None if cursor is at the end of charpy or bitlen is smaller 
                than 2
        
        Raises:
            CharpyErr : if `bitlen' is negative or overflow the maximum bitlen
        """
        if self._concat: self._pack()
        if bitlen is None:
            # get the whole charpy buffer
            bitlen = self._len_bit - self._cur
        elif bitlen < 0:
            raise(CharpyErr('negative bitlen: {0}'.format(bitlen))) 
        elif self._cur + bitlen > self._len_bit:
            raise(CharpyErr('bitlen overflow: {0}, max {1}'\
                            .format(bitlen, self._len_bit-self._cur)))
        elif bitlen == 0:
            return None
        off_byte, off_bit = self._cur >>3, self._cur % 8
        if off_bit == 0:
            # aligned access
            val = bytes_to_uint(self._buf[off_byte:1+off_byte+(bitlen>>3)], bitlen)
        else:
            # unaligned access
            # convert from a fully-aligned byte buffer with an extended length
            # bytes_to_uint takes care of converting only `bitlen+off_bit' bits
            # and finally zero the extra left-most bits
            val = bytes_to_uint(self._buf[off_byte:2+off_byte+(bitlen>>3)],
                                bitlen+off_bit) & ((1<<bitlen)-1)
        mask = 1<<(bitlen-1)
        if val & mask:
            # negative integer
            return (val&(mask-1)) - mask
        else:
            return val
    
    def get_int(self, bitlen=None):
        """Consume the signed integer value of the charpy instance, starting 
        at the current cursor position and ending after the given bitlen
        
        the charpy instance's cursor is incremented according to bitlen
        
        Args:
            bitlen (integer) : length in bits for the requested signed integer
                if None, the whole charpy signed integer value is returned
        
        Returns:
            uint (integer) : a signed integer value
                or None if cursor is at the end of charpy or bitlen is smaller 
                than 2
        
        Raises:
            CharpyErr : if `bitlen' is negative or overflow the maximum bitlen
        """
        if self._concat: self._pack()
        if bitlen is None:
            # get the whole charpy buffer
            bitlen = self._len_bit - self._cur
        elif bitlen < 0:
            raise(CharpyErr('negative bitlen: {0}'.format(bitlen))) 
        elif self._cur + bitlen > self._len_bit:
            raise(CharpyErr('bitlen overflow: {0}, max {1}'\
                            .format(bitlen, self._len_bit-self._cur)))
        elif bitlen == 0:
            return None
        off_byte, off_bit = self._cur >>3, self._cur % 8
        self._cur += bitlen
        if off_bit == 0:
            # aligned access
            val = bytes_to_uint(self._buf[off_byte:1+off_byte+(bitlen>>3)], bitlen)
        else:
            # unaligned access
            # convert from a fully-aligned byte buffer with an extended length
            # bytes_to_uint takes care of converting only `bitlen+off_bit' bits
            # and finally zero the extra left-most bits
            val = bytes_to_uint(self._buf[off_byte:2+off_byte+(bitlen>>3)],
                                bitlen+off_bit) & ((1<<bitlen)-1)
        mask = 1<<(bitlen-1)
        if val & mask:
            # negative integer
            return (val&(mask-1)) - mask
        else:
            return val
    
    def set_uint_le(self, val=0, bitlen=None):
        """Reinitialize the charpy instance and its cursor by setting an 
        arbitrary unsigned integer value into it
        
        little endian representation is used (least significant byte leftmost, 
        most significant byte rightmost)
        
        Args:
            val (integer) : unsigned integer
            bitlen (integer) : number of bits to be used to store the value
                if less than required by the value, value is majored to the 
                maximum uint value according to bitlen
                if None, encoding is done in the minimum number of bits
                if not byte-aligned, `bitlen' is extended
        
        Returns:
            None
        
        Raises:
            CharpyErr : if `val' has not the correct type or is negative
        """
        if not isinstance(val, integer_types):
            raise(CharpyErr('invalid argument type: {0}'\
                            .format(type(val).__name__)))
        elif val < 0:
            raise(CharpyErr('invalid argument value: {0}'.format(val)))
        elif bitlen is None or bitlen < 0:
            # Python 2.7 and 3 built-in
            bitlen = val.bit_length()
        if bitlen == 0:
            self._buf = b''
        elif bitlen % 8:
            bitlen += 8 - (bitlen%8)
            self._buf = uint_le_to_bytes(val, bitlen)
        else:
            self._buf = uint_le_to_bytes(val, bitlen)
        self._len_bit = bitlen
        self._cur = 0
        self._concat = []
    
    def append_uint_le(self, val=0, bitlen=None):
        """Append an unsigned integer value at the end of the charpy instance
        
        little endian representation is used (least significant byte leftmost, 
        most significant byte rightmost)
        
        Args:
            val (integer) : unsigned integer
            bitlen (integer) : number of bits to be used to store the value
                if less than required by the value, value is majored to the 
                maximum uint value according to bitlen
                if None, encoding is done in the minimum number of bits
                if not byte-aligned, `bitlen' is extended
        
        Returns:
            None
        
        Raises:
            CharpyErr : if `val' has not the correct type or is negative
        """
        if not isinstance(val, integer_types):
            raise(CharpyErr('invalid argument type: {0}'\
                            .format(type(val).__name__)))
        elif val < 0:
            raise(CharpyErr('invalid argument value: {0}'.format(val)))
        elif bitlen is None or bitlen < 0:
            # Python 2.7 and 3 built-in
            bitlen = val.bit_length()
            if bitlen % 8:
                bitlen += 8 - (bitlen%8)
        elif bitlen == 0:
            return
        elif bitlen % 8:
            bitlen += 8 - (bitlen%8)
        self._concat.append( (TYPE_UINT_LE, val, bitlen) )
    
    def to_uint_le(self, bitlen=None):
        """Provide the unsigned integer value of the charpy instance, starting 
        at the current cursor position and ending after the given bitlen, using
        the little endian format
        
        Args:
            bitlen (integer) : length in bits for the requested unsigned integer
                if None, the whole charpy unsigned integer value is returned
                if not byte-aligned, `bitlen' is lowered
        
        Returns:
            uint (integer) : an unsigned integer value
                or None if cursor is at the end of charpy or bitlen is null
        
        Raises:
            CharpyErr : if `bitlen' is negative or overflow the maximum bitlen
        """
        if self._concat: self._pack()
        if bitlen is None:
            # get the whole charpy buffer
            bitlen = self._len_bit - self._cur
            if bitlen % 8:
                bitlen -= bitlen%8
        elif bitlen < 0:
            raise(CharpyErr('negative bitlen: {0}'.format(bitlen))) 
        elif self._cur + bitlen > self._len_bit:
            raise(CharpyErr('bitlen overflow: {0}, max {1}'\
                            .format(bitlen, self._len_bit-self._cur)))
        elif bitlen == 0:
            return None
        elif bitlen % 8:
            bitlen -= bitlen%8
        off_byte, off_bit = self._cur >>3, self._cur % 8
        if off_bit == 0:
            # aligned access
            return bytes_to_uint_le(self._buf[off_byte:off_byte+(bitlen>>3)],
                                    bitlen)
        else:
            # unaligned access: shift left the buffer to restore alignment
            buf = bytes_lshift(self._buf[off_byte:1+off_byte+(bitlen>>3)],
                               off_bit)
            return bytes_to_uint_le(buf, bitlen)
    
    def get_uint_le(self, bitlen=None):
        """Consume the unsigned integer value of the charpy instance, starting 
        at the current cursor position and ending after the given bitlen, using
        the little endian format
        
        the charpy instance's cursor is incremented according to bitlen
        
        Args:
            bitlen (integer) : length in bits for the requested unsigned integer
                if None, the whole charpy unsigned integer value is returned
                if not byte-aligned, `bitlen' is lowered
        
        Returns:
            uint (integer) : an unsigned integer value
                or None if cursor is at the end or bitlen is null
        
        Raises:
            CharpyErr : if `bitlen' is negative or overflow the maximum bitlen
        """
        if self._concat: self._pack()
        if bitlen is None:
            # get the whole charpy buffer
            bitlen = self._len_bit - self._cur
            if bitlen % 8:
                bitlen -= bitlen%8
        elif bitlen < 0:
            raise(CharpyErr('negative bitlen: {0}'.format(bitlen))) 
        elif self._cur + bitlen > self._len_bit:
            raise(CharpyErr('bitlen overflow: {0}, max {1}'\
                            .format(bitlen, self._len_bit-self._cur)))
        elif bitlen == 0:
            return None
        elif bitlen % 8:
            bitlen -= bitlen%8
        off_byte, off_bit = self._cur >>3, self._cur % 8
        self._cur += bitlen
        if off_bit == 0:
            # aligned access
            return bytes_to_uint_le(self._buf[off_byte:off_byte+(bitlen>>3)],
                                    bitlen)
        else:
            # unaligned access: shift left the buffer to restore alignment
            buf = bytes_lshift(self._buf[off_byte:1+off_byte+(bitlen>>3)],
                               off_bit)
            return bytes_to_uint_le(buf, bitlen)
    
    def set_int_le(self, val=0, bitlen=None):
        """Reinitialize the charpy instance and its cursor by setting an 
        arbitrary signed integer value into it
        
        little endian representation is used (least significant byte leftmost, 
        most significant byte rightmost) and 2's complement representation
        
        Args:
            val (integer) : signed integer
            bitlen (integer) : number of bits to be used to store the value
                if less than required by the absolute value, value is minored or
                majored to the maximum absolute value according to bitlen
                if None, encoding is done in the minimum number of bits (can be
                +1 to the real minimum of bits)
                if not byte-aligned, `bitlen' is extended
        
        Returns:
            None
        
        Raises:
            CharpyErr : if `val' has not the correct type
        """
        if not isinstance(val, integer_types):
            raise(CharpyErr('invalid argument type: {0}'\
                            .format(type(val).__name__)))
        elif bitlen is None or bitlen < 0:
            # Python built-in int.bit_length() does not take the sign into
            # account, and we add another bit of dynamic to avoid any issue
            bitlen = 1 + val.bit_length()
            if bitlen % 8:
                bitlen += 8 - (bitlen%8)
        elif bitlen == 0:
            self._buf = b''
            self._len_bit = 0
            self._cur = 0
            self._concat = []
            return
        elif bitlen % 8:
            bitlen += 8 - (bitlen%8)
        #
        if val < 0:
            valmax = 1 << (bitlen-1)
            if val >= -valmax:
                # negative integer, sign bit + 2's complement
                self._buf = uint_le_to_bytes((valmax<<1) + val, bitlen)
            else:
                # minoring to the minimum possible negative value
                self._buf = b'\x80' + ((bitlen>>3)-1) * b'\0'
        else:
            self._buf = uint_le_to_bytes(val, bitlen)
        self._len_bit = bitlen
        self._cur = 0
        self._concat = []
    
    def append_int_le(self, val=0, bitlen=None):
        """Append a signed integer value at the end of the charpy instance
        
        little endian representation is used (least significant byte leftmost, 
        most significant byte rightmost) and 2's complement representation
        
        Args:
            val (integer) : signed integer
            bitlen (integer) : number of bits to be used to store the value
                if less than required by the absolute value, value is minored or
                majored to the maximum absolute value according to bitlen
                if None, encoding is done in the minimum number of bits (can be
                +1 to the real minimum of bits)
                if not byte-aligned, `bitlen' is extended
        
        Returns:
            None
        
        Raises:
            CharpyErr : if `val' has not the correct type
        """
        if not isinstance(val, integer_types):
            raise(CharpyErr('invalid argument type: {0}'\
                            .format(type(val).__name__)))
        elif bitlen is None or bitlen < 0:
            bitlen =  1 + val.bit_length()
            if bitlen % 8:
                bitlen += 8 - (bitlen%8)
        elif bitlen == 0:
            return
        elif bitlen % 8:
            bitlen += 8 - (bitlen%8)
        self._concat.append( (TYPE_INT_LE, val, bitlen) )
    
    def to_int_le(self, bitlen=None):
        """Provide the signed integer value of the charpy instance, starting 
        at the current cursor position and ending after the given bitlen, 
        using the little endian format
        
        Args:
            bitlen (integer) : length in bits for the requested signed integer
                if None, the whole charpy signed integer value is returned
        
        Returns:
            uint (integer) : a signed integer value
                or None if cursor is at the end of charpy or bitlen is smaller 
                than 2
                if not byte-aligned, `bitlen' is lowered
        
        Raises:
            CharpyErr : if `bitlen' is negative or overflow the maximum bitlen
        """
        if self._concat: self._pack()
        if bitlen is None:
            # get the whole charpy buffer
            bitlen = self._len_bit - self._cur
            if bitlen % 8:
                bitlen -= bitlen% 8
        elif bitlen < 0:
            raise(CharpyErr('negative bitlen: {0}'.format(bitlen))) 
        elif self._cur + bitlen > self._len_bit:
            raise(CharpyErr('bitlen overflow: {0}, max {1}'\
                            .format(bitlen, self._len_bit-self._cur)))
        elif bitlen == 0:
            return None
        elif bitlen % 8:
            bitlen -= bitlen%8
        off_byte, off_bit = self._cur >>3, self._cur % 8
        if off_bit == 0:
            # aligned access
            val = bytes_to_uint_le(self._buf[off_byte:off_byte+(bitlen>>3)],
                                   bitlen)
        else:
            # unaligned access: shift left the buffer to restore alignment
            buf = bytes_lshift(self._buf[off_byte:1+off_byte+(bitlen>>3)],
                               off_bit)
            val = bytes_to_uint_le(buf, bitlen)
        mask = 1<<(bitlen-1)
        if val & mask:
            # negative integer
            return (val&(mask-1)) - mask
        else:
            return val
    
    def get_int_le(self, bitlen=None):
        """Consume the signed integer value of the charpy instance, starting 
        at the current cursor position and ending after the given bitlen, 
        using the little endian format
        
        the charpy instance's cursor is incremented according to bitlen
        
        Args:
            bitlen (integer) : length in bits for the requested signed integer
                if None, the whole charpy signed integer value is returned
        
        Returns:
            uint (integer) : a signed integer value
                or None if cursor is at the end of charpy or bitlen is smaller 
                than 2
                if not byte-aligned, `bitlen' is lowered
        
        Raises:
            CharpyErr : if `bitlen' is negative or overflow the maximum bitlen
        """
        if self._concat: self._pack()
        if bitlen is None:
            # get the whole charpy buffer
            bitlen = self._len_bit - self._cur
            if bitlen % 8:
                bitlen -= bitlen% 8
        elif bitlen < 0:
            raise(CharpyErr('negative bitlen: {0}'.format(bitlen))) 
        elif self._cur + bitlen > self._len_bit:
            raise(CharpyErr('bitlen overflow: {0}, max {1}'\
                            .format(bitlen, self._len_bit-self._cur)))
        elif bitlen == 0:
            return None
        elif bitlen % 8:
            bitlen -= bitlen%8
        off_byte, off_bit = self._cur >>3, self._cur % 8
        self._cur += bitlen
        if off_bit == 0:
            # aligned access
            val = bytes_to_uint_le(self._buf[off_byte:off_byte+(bitlen>>3)],
                                   bitlen)
        else:
            # unaligned access: shift left the buffer to restore alignment
            buf = bytes_lshift(self._buf[off_byte:1+off_byte+(bitlen>>3)],
                               off_bit)
            val = bytes_to_uint_le(buf, bitlen)
        mask = 1<<(bitlen-1)
        if val & mask:
            # negative integer
            return (val&(mask-1)) - mask
        else:
            return val
    
    #--------------------------------------------------------------------------#
    # Python built-ins override
    #--------------------------------------------------------------------------#
    
    __len__ = len_bit
    __repr__ = repr
    __index__ = to_uint
    if python_version < 3:
        __str__ = to_bytes
    else:
        __bytes__ = to_bytes
    
    def __bool__(self):
        if self.len_bit() == 0:
            return False
        else:
            return True
    
    def __getitem__(self, key):
        if isinstance(key, integer_types):
            if key < 0:
                raise(IndexError('Charpy does not support negative index'))
            elif key >= self.len_bit():
                raise(IndexError('Charpy index out of range'))
            cur = self._cur
            self._cur += key
            ret = self.to_bitlist(1)[0]
            self._cur = cur
            return ret
        elif isinstance(key, slice):
            if key.start:
                if key.start < 0:
                    raise(IndexError('Charpy does not support negative index'))
                elif key.start >= self.len_bit():
                    return []
                start = key.start
            else:
                start = 0
            if key.stop:
                if key.stop < start:
                    raise(IndexError('Charpy does not support retro indexing'))
                elif key.stop > self.len_bit():
                    stop = self.len_bit()
                else:
                    stop = key.stop
            else:
                stop = self.len_bit()
            cur = self._cur
            self._cur += start
            if key.step:
                ret = self.to_bitlist(stop-start)[::key.step]
            else:
                ret = self.to_bitlist(stop-start)
            self._cur = cur
            return ret
        else:
            raise(TypeError('Charpy indices must be integers, not {0}'\
                            .format(type(key).__name__)))
    def __iter__(self):
        return iter(self.to_bitlist())
    
    # those comparisons are broken, but this is still funny !
    def __lt__(self, other):
        if not isinstance(other, Charpy):
            raise(TypeError('unorderable types: Charpy() < {0}()'\
                            .format(type(other).__name__)))
        suint = self.to_uint()
        ouint = other.to_uint()
        if suint == ouint:
            # if both uint values are equal, compare the number of bits
            return self.len_bit() < other.len_bit()
        else:
            return suint < ouint
    
    def __le__(self, other):
        if not isinstance(other, Charpy):
            raise(TypeError('unorderable types: Charpy() <= {0}()'\
                            .format(type(other).__name__)))
        if self.__eq__(other):
            return True
        else:
            return self.__lt__(other)
    
    def __eq__(self, other):
        if not isinstance(other, Charpy):
            raise(TypeError('unorderable types: Charpy() == {0}()'\
                            .format(type(other).__name__)))
        return self.to_bytes() == other.to_bytes()
    
    def __ne__(self, other):
        if not isinstance(other, Charpy):
            raise(TypeError('unorderable types: Charpy() != {0}()'\
                            .format(type(other).__name__)))
        return self.to_bytes() != other.to_bytes()
    
    def __gt__(self, other):
        if not isinstance(other, Charpy):
            raise(TypeError('unorderable types: Charpy() > {0}()'\
                            .format(type(other).__name__)))
        suint = self.to_uint()
        ouint = other.to_uint()
        if suint == ouint:
            # if both uint values are equal, compare the number of bits
            return self.len_bit() > other.len_bit()
        else:
            return suint > ouint
    
    def __ge__(self, other):
        if not isinstance(other, Charpy):
            raise(TypeError('unorderable types: Charpy() >= {0}()'\
                            .format(type(other).__name__)))
        if self.__eq__(other):
            return True
        else:
            return self.__gt__(other)

