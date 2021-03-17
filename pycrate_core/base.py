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
# * File Name : pycrate_core/base.py
# * Created : 2016-03-02
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = ['Buf', 'BufAuto', 'NullTermStr',
           'String', 'UTF8String', 'UTF16String', 'UTF32String',
           'Uint', 'Uint8', 'Uint16', 'Uint24', 'Uint32', 'Uint48', 'Uint64',
           'Int', 'Int8', 'Int16', 'Int24', 'Int32', 'Int48', 'Int64',
           'UintLE', 'Uint8LE', 'Uint16LE', 'Uint24LE', 'Uint32LE', 'Uint48LE', 'Uint64LE',
           'IntLE', 'Int8LE', 'Int16LE', 'Int24LE', 'Int32LE', 'Int48LE', 'Int64LE']


import sys
python_version = sys.version_info[0]

from .utils  import *
from .charpy import Charpy, CharpyErr
from .elt    import Atom, EltErr, REPR_RAW, REPR_HEX, REPR_BIN, REPR_HD, REPR_HUM
from .elt    import _with_json

if _with_json:
    from binascii import hexlify, unhexlify


#------------------------------------------------------------------------------#
# Basic types - bytes' buffers
#------------------------------------------------------------------------------#

class Buf(Atom):
    
    TYPES       = flatten(bytes_types, )
    TYPENAMES   = get_typenames(*TYPES)
    DEFAULT_VAL = b''
    DEFAULT_BL  = 0
    PAD_VAL     = b'\0'
    
    #--------------------------------------------------------------------------#
    # format routines
    #--------------------------------------------------------------------------#
    
    def _chk_val(self, *args):
        if args:
            val = args[0]
        else:
            val = self._val
        if not isinstance(val, self.TYPES + (NoneType,) ):
            raise(EltErr('{0} [_chk_val]: val type is {1}, expecting {2}'\
                  .format(self._name, type(val).__name__, self.TYPENAMES)))
        elif val is not None and self._bl is not None and self._blauto is None:
            bytelen = self._bl>>3
            if self._bl%8:
                bytelen += 1
            if len(val) < bytelen:
                raise(EltErr('{0} [_chk_val]: val length underflow, {1} bytes instead of {2}'\
                      .format(self._name, len(val), bytelen)))
            elif len(val) > bytelen:
                raise(EltErr('{0} [_chk_val]: val length overflow, {1} bytes instead of {2}'\
                      .format(self._name, len(val), bytelen)))
    
    def get_val(self):
        """Returns the value of self
        
        Args:
            None
        
        Returns:
            value (bytes) : value computed, default to empty bytes
        
        Raises:
            EltErr : if self._SAFE_DYN is enabled and the value produced 
                dynamically has not the correct type
        """
        # follow the value resolution order:
        # 1) raw value
        if self._val is not None:
            return self._val
        
        # 2) value automation
        elif self._valauto is not None:
            val = self._valauto()
            if self._SAFE_DYN:
                self._chk_val(val)
            return val
        
        # 3) padded value (different from Atom.get_val())
        elif self._bl is not None:
            if self._bl % 8:
                return (1 + (self._bl>>3)) * self.PAD_VAL
            else:
                return (self._bl>>3) * self.PAD_VAL
        
        # 4) default value
        else:
            return self.DEFAULT_VAL
    
    def set_bl(self, bl=None):
        """Set the raw length in bits of self
        
        Args:
            bl (int) : raw bit length, default to None
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and bl is not integer
        """
        if bl is None:
            try:
                del self._bl
            except Exception:
                pass
        else:
            if self._SAFE_STAT:
                self._chk_bl(bl)
            self._bl = bl
            # in case a raw value is already set, pad it if necessary
            # TODO: in case previous bl was not byte-aligned, shifting padding
            # is necessary
            if self._val is not None and self._valauto is None:
                if bl % 8:
                    l = 1 + (bl>>3)
                else:
                    l = bl>>3
                diff = l - len(self._val)
                if diff > 0:
                    self._val += diff * self.PAD_VAL
                elif diff < 0:
                    self._val = self._val[:diff]
    
    def _get_bl_from_val(self):
        return 8 * len(self.get_val())
    
    def set_num(self, num):
        self.set_bl(num*8)
    
    def get_num(self):
        return self.get_len()
    
    __call__ = get_val
    
    #--------------------------------------------------------------------------#
    # conversion routines
    #--------------------------------------------------------------------------#
    
    def _to_pack(self):
        """Produces a tuple ready to be packed with pack_val() according to its
        internal value
        """
        if not self.get_trans():
            return [(TYPE_BYTES, self.get_val(), self.get_bl())]
        else:
            return []
    
    def _from_char(self, char):
        """Consume the charpy intance and set its internal value according to it
        """
        if self.get_trans():
            return
        if self._blauto is not None:
            bl = self._blauto()
            if self._SAFE_DYN:
                self._chk_bl(bl)
        elif self._bl is not None:
            bl = self._bl
        else:
            bl = None
        #
        try:
            self._val = char.get_bytes(bl)
        except CharpyErr as err:
            raise(CharpyErr('{0} [_from_char]: {1}'.format(self._name, err)))
        except Exception as err:
            raise(EltErr('{0} [_from_char]: {1}'.format(self._name, err)))
    
    #--------------------------------------------------------------------------#
    # json interface
    #--------------------------------------------------------------------------#
    
    if _with_json:
        
        def _from_jval(self, val):
            try:
                self.set_val(unhexlify(val))
            except Exception:
                raise(EltErr('{0} [_from_jval]: invalid format, {1!r}'.format(self._name, val)))
        
        def _to_jval(self):
            return hexlify(self.get_val()).decode()


# BufAuto is used when a Buf requires to have its length automatically computed
# (i.e. in get_bl()) also when building the value (i.e. calling get_val())
# and not only at parsing (i.e. in _from_char())
class BufAuto(Buf):
    
    #--------------------------------------------------------------------------#
    # format routines
    #--------------------------------------------------------------------------#
    
    def get_val(self):
        """Returns the value of self
        
        Args:
            None
        
        Returns:
            value (bytes) : value computed, default to empty bytes
        
        Raises:
            EltErr : if self._SAFE_DYN is enabled and the value produced 
                dynamically has not the correct type
        """
        # follow the value resolution order:
        # 1) raw value
        if self._val is not None:
            return self._val
        
        # 2) value automation
        elif self._valauto is not None:
            val = self._valauto()
            if self._SAFE_DYN:
                self._chk_val(val)
            return val
        
        # 3) padded value (different from Buf.get_val())
        bl = self.get_bl()
        if bl is not None:
            if bl % 8:
                return (1 + (bl>>3)) * self.PAD_VAL
            else:
                return (bl>>3) * self.PAD_VAL
        
        # 4) default value
        else:
            return self.DEFAULT_VAL
    
    def get_bl(self):
        """Returns the length in bits of self
        
        Args:
            None
        
        Returns:
            bl (int) : length in bits computed
                default to class attribute DEFAULT_BL
        """
        # follow the value resolution order:
        # 0) transparency
        if self.get_trans():
            return 0
        
        # 1) raw bl
        elif self._bl is not None:
            return self._bl
        
        # 2) bl automation
        elif self._blauto is not None:
            bl = self._blauto()
            if self._SAFE_DYN:
                self._chk_bl(bl)
            return bl
        
        # 3) no bl defined, return the bl computed from the value set
        elif self._val is not None or self._valauto is not None:
            return self._get_bl_from_val()
        
        # 4) no bl defined, no value defines, return the default one
        else:
            return self.DEFAULT_BL
    
    __call__ = get_val


# Null terminated string
# only different from Buf when consuming a buffer at parsing
class NullTermStr(Buf):
    
    def _from_char(self, char):
        """Consume the charpy intance and set its internal value according to it
        Stops consuming char in case a null byte is found
        """
        if self.get_trans():
            return
        #
        if self._blauto is not None:
            bl = self._blauto()
            if self._SAFE_DYN:
                self._chk_bl(bl)
        elif self._bl is not None:
            bl = self._bl
        else:
            bl = None
        #
        try:
            buf = char.to_bytes(bl)
        except CharpyErr as err:
            raise(CharpyErr('{0} [_from_char]: {1}'.format(self._name, err)))
        else:
            eos = buf.find(b'\0')
            if eos < 0:
                val = buf
            else:
                val = buf[:eos+1]
            try:
                self.set_val(val)
            except Exception as err:
                raise(EltErr('{0} [_from_char]: {1}'.format(self._name, err)))
            else:
                char.forward(8*len(val))


#------------------------------------------------------------------------------#
# Encoded string
#------------------------------------------------------------------------------#

class String(Atom):
    
    # CODEC can be any of the string codec supported by Python
    # e.g. utf8, utf16, utf32...
    CODEC = 'utf8'
    
    if python_version <= 2:
        TYPES   = (unicode, )
    else:
        TYPES   = (str, )
    TYPENAMES   = get_typenames(*TYPES)
    DEFAULT_VAL = u''
    DEFAULT_BL  = 0
    
    #--------------------------------------------------------------------------#
    # format routines
    #--------------------------------------------------------------------------#
    # Warning: there is no specific processing against fixed bit / byte length
    # because it is highly improbable to have such encoded string with fixed
    # length.
    # however, in case some fixed length is applied to such type, things could
    # fail silently...
    
    def _get_bl_from_val(self):
        return 8 * len(self.get_val().encode(self.CODEC))
    
    #--------------------------------------------------------------------------#
    # conversion routines
    #--------------------------------------------------------------------------#
    
    def _to_pack(self):
        """Produces a tuple ready to be packed with pack_val() according to its
        internal value
        """
        if not self.get_trans():
            return [(TYPE_BYTES, self.get_val().encode(self.CODEC), self.get_bl())]
        else:
            return []
    
    def _from_char(self, char):
        """Consume the charpy intance and set its internal value according to it
        """
        if self.get_trans():
            return
        if self._blauto is not None:
            bl = self._blauto()
            if self._SAFE_DYN:
                self._chk_bl(bl)
        elif self._bl is not None:
            bl = self._bl
        else:
            bl = None
        #
        try:
            buf = char.get_bytes(bl)
        except CharpyErr as err:
            raise(CharpyErr('{0} [_from_char]: {1}'.format(self._name, err)))
        except Exception as err:
            raise(EltErr('{0} [_from_char]: {1}'.format(self._name, err)))
        else:
            try:
                self._val = buf.decode(self.CODEC)
            except Exception as err:
                raise(EltErr('{0} [_from_char], invalid encoding: {1}'\
                      .format(self._name, err)))
    
    #--------------------------------------------------------------------------#
    # json interface
    #--------------------------------------------------------------------------#
    
    if _with_json:
        
        def _from_jval(self, val):
            self.set_val(val)
        
        def _to_jval(self):
            return self.get_val()


class UTF8String(String):
    CODEC = 'utf8'


class UTF16String(String):
    CODEC = 'utf16'


class UTF32String(String):
    CODEC = 'utf32'


#------------------------------------------------------------------------------#
# Basic types - integral values
#------------------------------------------------------------------------------#

class Uint(Atom):
    
    TYPES       = flatten(integer_types, )
    TYPENAMES   = get_typenames(*TYPES)
    DEFAULT_VAL = 0
    DEFAULT_BL  = 0
    
    _SAFE_VALAUTO = False
    
    #--------------------------------------------------------------------------#
    # format routines
    #--------------------------------------------------------------------------#
    
    def _get_val_min(self):
        return 0
    
    def _get_val_max(self):
        return (1 << self.get_bl()) - 1
        
    def get_val(self):
        # follow the value resolution order:
        # 1) raw value
        if self._val is not None:
            return self._val
        
        # 2) value automation
        elif self._valauto is not None:
            val = self._valauto()
            if self._SAFE_DYN:
                self._chk_val(val)
            elif self._SAFE_VALAUTO:
                if val < self._get_val_min():
                    return self._get_val_min()
                elif val > self._get_val_max():
                    return self._get_val_max()
            return val
        
        # 3) default value
        else:
            return self.DEFAULT_VAL
    
    def _chk_val(self, *args):
        if args:
            val = args[0]
        else:
            val = self._val
        if not isinstance(val, self.TYPES + (NoneType,) ):
            raise(EltErr('{0} [_chk_val]: val type is {1}, expecting {2}'\
                  .format(self._name, type(val).__name__, self.TYPENAMES)))
        elif val is not None:
            if val < 0:
                raise(EltErr('{0} [_val_chk]: val underflow, val {1}'\
                      .format(self._name, val)))
            elif self._bl is not None and self._blauto is None and val > (2**self._bl)-1:
                raise(EltErr('{0} [_val_chk]: val overflow, bl {1}, val {2}'\
                      .format(self._name, self._bl, val)))
    
    def _get_bl_from_val(self):
        # Python int.bit_length() API, nice
        return self.get_val().bit_length()
    
    __call__ = get_val
    
    #--------------------------------------------------------------------------#
    # conversion routines
    #--------------------------------------------------------------------------#
    
    def _to_pack(self):
        """Produces a tuple ready to be packed with pack_val() according to its
        internal value
        """
        if not self.get_trans():
            return [(TYPE_UINT, self.get_val(), self.get_bl())]
        else:
            return []
    
    def _from_char(self, char):
        """Consume the charpy intance and set its internal value according to
        it
        """
        if self.get_trans():
            return
        #
        if self._blauto is not None:
            bl = self._blauto()
            if self._SAFE_DYN:
                self._chk_bl(bl)
        elif self._bl is not None:
            bl = self._bl
        else:
            bl = None
        #
        try:
            self._val = char.get_uint(bl)
        except CharpyErr as err:
            raise(CharpyErr('{0} [_from_char]: {1}'.format(self._name, err)))
    
    #--------------------------------------------------------------------------#
    # json interface
    #--------------------------------------------------------------------------#
    
    if _with_json:
        
        def _from_jval(self, val):
            try:
                self.set_val(val)
            except Exception:
                raise(EltErr('{0} [_from_jval]: invalid format, {1!r}'.format(self._name, val)))
        
        def _to_jval(self):
            return self.get_val()


class Uint8(Uint):
    _bl = 8


class Uint16(Uint):
    _bl = 16


class Uint24(Uint):
    _bl = 24


class Uint32(Uint):
    _bl = 32


class Uint48(Uint):
    _bl = 48


class Uint64(Uint):
    _bl = 64


class Int(Atom):
    
    TYPES       = flatten(integer_types, )
    TYPENAMES   = get_typenames(*TYPES)
    DEFAULT_VAL = 0
    DEFAULT_BL  = 0
    
    _SAFE_VALAUTO = False
    
    #--------------------------------------------------------------------------#
    # format routines
    #--------------------------------------------------------------------------#
    
    def _get_val_min(self):
        return -1 << (self.get_bl()-1)
    
    def _get_val_max(self):
        return (1 << (self.get_bl()-1)) - 1
    
    def get_val(self):
        # follow the value resolution order:
        # 1) raw value
        if self._val is not None:
            return self._val
        
        # 2) value automation
        elif self._valauto is not None:
            val = self._valauto()
            if self._SAFE_DYN:
                self._chk_val(val)
            elif self._SAFE_VALAUTO:
                if val < self._get_val_min():
                    return self._get_val_min()
                elif val > self._get_val_max():
                    return self._get_val_max()
            return val
        
        # 3) default value
        else:
            return self.DEFAULT_VAL
    
    def _chk_val(self, *args):
        if args:
            val = args[0]
        else:
            val = self._val
        if not isinstance(val, self.TYPES + (NoneType,) ):
            raise(EltErr('{0} [_chk_val]: val type is {1}, expecting {2}'\
                  .format(self._name, type(val).__name__, self.TYPENAMES)))
        elif val is not None and self._bl is not None and self._blauto is None:
            if val < -(1<<(self._bl-1)):
                raise(EltErr('{0} [_val_chk]: val underflow, bl {1}, val {2}'\
                      .format(self._name, self._bl, val)))
            elif val > (1<<(self._bl-1))-1:
                raise(EltErr('{0} [_val_chk]: val overflow, bl {1}, val {2}'\
                      .format(self._name, self._bl, val)))
    
    def _get_bl_from_val(self):
        # because the length in bits is not defined,
        # we can't use the 2's complement convention, 
        # so we just return 1 additional bit for the sign
        return 1 + self.get_val().bit_length()
    
    __call__ = get_val
    
    #--------------------------------------------------------------------------#
    # conversion routines
    #--------------------------------------------------------------------------#
    
    def _to_pack(self):
        """Produces a tuple ready to be packed with pack_val() according to its
        internal value
        """
        if not self.get_trans():
            return [(TYPE_INT, self.get_val(), self.get_bl())]
        else:
            return []
    
    def _from_char(self, char):
        """Consume the charpy intance and set its internal value according to
        it
        """
        if self.get_trans():
            return
        #
        if self._blauto is not None:
            bl = self._blauto()
            if self._SAFE_DYN:
                self._chk_bl(bl)
        elif self._bl is not None:
            bl = self._bl
        else:
            bl = None
        #
        try:
            self._val = char.get_int(bl)
        except CharpyErr as err:
            raise(CharpyErr('{0} [_from_char]: {1}'.format(self._name, err)))
    
    #--------------------------------------------------------------------------#
    # json interface
    #--------------------------------------------------------------------------#
    
    if _with_json:
        
        def _from_jval(self, val):
            try:
                self.set_val(val)
            except Exception:
                raise(EltErr('{0} [_from_jval]: invalid format, {1!r}'.format(self._name, val)))
        
        def _to_jval(self):
            return self.get_val()


class Int8(Int):
    _bl = 8


class Int16(Int):
    _bl = 16


class Int24(Int):
    _bl = 24


class Int32(Int):
    _bl = 32


class Int48(Int):
    _bl = 48


class Int64(Int):
    _bl = 64


class UintLE(Atom):
    TYPES       = flatten(integer_types, )
    TYPENAMES   = get_typenames(*TYPES)
    DEFAULT_VAL = 0
    DEFAULT_BL  = 0
    
    #--------------------------------------------------------------------------#
    # format routines
    #--------------------------------------------------------------------------#
    def _chk_val(self, *args):
        if args:
            val = args[0]
        else:
            val = self._val
        if not isinstance(val, self.TYPES + (NoneType,) ):
            raise(EltErr('{0} [_chk_val]: val type is {1}, expecting {2}'\
                  .format(self._name, type(val).__name__, self.TYPENAMES)))
        elif val is not None:
            if val < 0:
                raise(EltErr('{0} [_val_chk]: val underflow, val {1}'\
                      .format(self._name, val)))
            elif self._bl is not None and self._blauto is None and val > (1<<self._bl)-1:
                raise(EltErr('{0} [_val_chk]: val overflow, bl {1}, val {2}'\
                      .format(self._name, self._bl, val)))
    
    def _chk_bl(self, *args):
        if args:
            bl = args[0]
        else:
            bl = self._bl
        if not isinstance(bl, integer_types + (NoneType,)):
            raise(EltErr('{0} [_chk_bl]: bl type is {1}, expecting integer'\
                  .format(self._name, type(bl).__name__)))
        if bl is not None and bl % 8:
            raise(EltErr('{0} [set_bl]: bl value is {1}, expecting multiple of 8'\
                  .format(self._name, bl)))
    
    def _get_bl_from_val(self):
        # little endian requires byte-alignment
        bl = self.get_val().bit_length()
        if bl % 8:
            return bl + (8 - (bl%8))
        else:
            return bl
    
    #--------------------------------------------------------------------------#
    # conversion routines
    #--------------------------------------------------------------------------#
    
    def _to_pack(self):
        """Produces a tuple ready to be packed with pack_val() according to its
        internal value
        """
        if not self.get_trans():
            return [(TYPE_UINT_LE, self.get_val(), self.get_bl())]
        else:
            return []
    
    def _from_char(self, char):
        """Consume the charpy intance and set its internal value according to
        it
        """
        if self.get_trans():
            return
        #
        if self._blauto is not None:
            bl = self._blauto()
            if self._SAFE_DYN:
                self._chk_bl(bl)
        elif self._bl is not None:
            bl = self._bl
        else:
            bl = None
        #
        try:
            self._val = char.get_uint_le(bl)
        except CharpyErr as err:
            raise(CharpyErr('{0} [_from_char]: {1}'.format(self._name, err)))
    
    #--------------------------------------------------------------------------#
    # json interface
    # value converted to integer
    #--------------------------------------------------------------------------#
    
    if _with_json:
        
        def _from_jval(self, val):
            try:
                self.set_val(val)
            except Exception:
                raise(EltErr('{0} [_from_jval]: invalid format, {1!r}'.format(self._name, val)))
        
        def _to_jval(self):
            return self.get_val()


class Uint8LE(UintLE):
    _bl = 8


class Uint16LE(UintLE):
    _bl = 16


class Uint24LE(UintLE):
    _bl = 24


class Uint32LE(UintLE):
    _bl = 32


class Uint48LE(UintLE):
    _bl = 48


class Uint64LE(UintLE):
    _bl = 64


class IntLE(Atom):
    TYPES       = flatten(integer_types, )
    TYPENAMES   = get_typenames(*TYPES)
    DEFAULT_VAL = 0
    DEFAULT_BL  = 0
    
    #--------------------------------------------------------------------------#
    # format routines
    #--------------------------------------------------------------------------#
    
    def _chk_val(self, *args):
        if args:
            val = args[0]
        else:
            val = self._val
        if not isinstance(val, self.TYPES + (NoneType,) ):
            raise(EltErr('{0} [_chk_val]: val type is {1}, expecting {2}'\
                  .format(self._name, type(val).__name__, self.TYPENAMES)))
        elif val is not None and self._bl is not None and self._blauto is None:
            if val < -(1<<(self._bl-1)):
                raise(EltErr('{0} [_val_chk]: val underflow, bl {1}, val {2}'\
                      .format(self._name, self._bl, val)))
            elif val > (1<<(self._bl-1))-1:
                raise(EltErr('{0} [_val_chk]: val overflow, bl {1}, val {2}'\
                      .format(self._name, self._bl, val)))
    
    def _chk_bl(self, *args):
        if args:
            bl = args[0]
        else:
            bl = self._bl
        if not isinstance(bl, integer_types + (NoneType,)):
            raise(EltErr('{0} [_chk_bl]: bl type is {1}, expecting integer'\
                  .format(self._name, type(bl).__name__)))
        if bl is not None and bl % 8:
            raise(EltErr('{0} [set_bl]: bl value is {1}, expecting multiple of 8'\
                  .format(self._name, bl)))
    
    def _get_bl_from_val(self):
        bl = 1 + self.get_val().bit_length()
        if bl % 8:
            return bl + (8 - (bl%8))
        else:
            return bl
    
    #--------------------------------------------------------------------------#
    # conversion routines
    #--------------------------------------------------------------------------#
    
    def _to_pack(self):
        """Produces a tuple ready to be packed with pack_val() according to its
        internal value
        """
        if not self.get_trans():
            return [(TYPE_INT_LE, self.get_val(), self.get_bl())]
        else:
            return []
    
    def _from_char(self, char):
        """Consume the charpy intance and set its internal value according to
        it
        """
        if self.get_trans():
            return
        #
        if self._blauto is not None:
            bl = self._blauto()
            if self._SAFE_DYN:
                self._chk_bl(bl)
        elif self._bl is not None:
            bl = self._bl
        else:
            bl = None
        #
        try:
            self._val = char.get_int_le(bl)
        except CharpyErr as err:
            raise(CharpyErr('{0} [_from_char]: {1}'.format(self._name, err)))
    
    #--------------------------------------------------------------------------#
    # json interface
    # value converted to integer
    #--------------------------------------------------------------------------#
    
    if _with_json:
        
        def _from_jval(self, val):
            try:
                self.set_val(val)
            except Exception:
                raise(EltErr('{0} [_from_jval]: invalid format, {1!r}'.format(self._name, val)))
        
        def _to_jval(self):
            return self.get_val()


class Int8LE(IntLE):
    _bl = 8


class Int16LE(IntLE):
    _bl = 16


class Int24LE(IntLE):
    _bl = 24


class Int32LE(IntLE):
    _bl = 32


class Int48LE(IntLE):
    _bl = 48


class Int64LE(IntLE):
    _bl = 64

