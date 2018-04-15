# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.3
# *
# * Copyright 2017. Benoit Michau. ANSSI.
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
# * File Name : pycrate_csn1/csnobj.py
# * Created : 2017-06-12
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from pycrate_core.charpy import *

from .utils import *

#------------------------------------------------------------------------------#
# CSN.1 runtime
#------------------------------------------------------------------------------#

global _root_obj # for referencing the root object name, in case of self reference
_root_obj = None


class CSN1Obj(Element):
    """Parent class to handle CSN.1 objects encoding and decoding and definition
    
    internal attributes:
        - name: str, named of the object,
            can be a null-string in case of anonymous object
        - num : int, number of repetition for the object
            default is 1, it can be >= 0
            or == -1, in this case, there is an undefined number of repetition 
            -> until there is no more buffer to decode, or
            -> until the object starts with a fixed value and this value is not
            present anymore in the buffer to decode
        - lref: int, backward reference to a field into the parent object (which 
            has to be a list), enforces the length in bits during decoding
    
    This class must not be used directly, only CSN1Bit, CSN1List, CSN1Alt, CSN1Val,
    CSN1Ref and CSN1SelfRef.
    """
    
    #_REPR = 'B' # value always represented with bit-string
    _REPR = 'V' # value represented with their original type (uint -default- or bit-string)
    
    _name = ''
    _num  = 1
    _lref = None
    _root = False
    
    def __init__(self, **kw):
        if 'name' in kw and kw['name']:
            self._name = kw['name']
        if 'root' in kw and kw['root']:
            self._root = True
        if 'num' in kw and (kw['num'] == -1 or kw['num'] > 1):
            self._num  = kw['num']
        if 'lref' in kw and kw['lref'] is not None:
            self._lref = kw['lref']
    
    def repr(self):
        global _root_obj
        if self._root:
            root_obj  = _root_obj
            _root_obj = self
        #
        if self._val is not None:
            if self._num != 1:
                # multiple iteration of the object's value
                content   = []
                _num      = self._num
                _val      = self._val
                self._num = 1
                for val in _val:
                    self._val = val
                    content.append( self._repr_val() )
                self._num = _num
                self._val = _val
                if self._name:
                    ret = '<%s: [%s]>' % (self._name, ', '.join(content))
                else:
                    ret = '<[%s]>' % ', '.join(content)
            else:
                if self._name:
                    ret = '<%s: %s>' % (self._name, self._repr_val())
                else:
                    ret = '<%s>' % self._repr_val()
        else:
            # only print the class name when not value is set
            ret = '<%s(%s)>' % (self._name, self.__class__.__name__)
        #
        if self._root:
            _root_obj = root_obj
        #
        return ret
    
    __repr__ = repr
    
    def show(self):
        # don't print the class name when values are set
        global _root_obj
        if self._root:
            root_obj  = _root_obj
            _root_obj = self
        #
        if self._val is not None:
            if self._num != 1:
                # multiple iteration of the object's value
                content   = []
                _num      = self._num
                _val      = self._val
                self._num = 1
                for val in _val:
                    self._val = val
                    content.append( self._show_val().replace('\n', '\n ') )
                self._num = _num
                self._val = _val
                if self._name:
                    ret = '<%s: [%s]>' % (self._name, ',\n'.join(content))
                else:
                    ret = '<[%s]>' % ',\n'.join(content)
            else:
                if self._name:
                    ret = '<%s: %s>' % (self._name, self._show_val())
                else:
                    ret = '<%s>' % self._show_val()
        else:
            ret = '<%s(%s)>' % (self._name, self.__class__.__name__)
        #
        if self._root:
            _root_obj = root_obj
        #
        return ret
    
    #--------------------------------------------------------------------------#
    # value management
    #--------------------------------------------------------------------------#
    
    def set_val(self, val):
        self._val = val
    
    def get_val(self):
        return self._val
    
    def __call__(self):
        return self._val
    
    #--------------------------------------------------------------------------#
    # object common API with pycrate_core.elt.Element 
    #--------------------------------------------------------------------------#
    
    #def _from_char_obj(self, char):
    #    raise(CSN1Err('not implemented'))
    # 
    #def _to_pack_obj(self):
    #    raise(CSN1Err('not implemented'))
    
    def _from_char(self, char, lref=None):
        global _root_obj
        #
        if self._root:
            root_obj  = _root_obj
            _root_obj = self
        #
        if lref is not None:
            # shorten the char buffer
            char_lb = char._len_bit
            if isinstance(lref, str_types):
                # CSN1Bit._type == CSN1T_BSTR
                char._len_bit = char._cur + bitstr_to_uint(lref)
            else:
                char._len_bit = char._cur + lref
            assert( char._len_bit <= char_lb )
        #
        if self._num == 1:
            self._from_char_obj(char)
        elif self._num > 1:
            val = []
            for i in range(self._num):
                self._from_char_obj(char)
                val.append( self._val )
            self._val = val
        elif self._num == -1:
            val = []
            while char.len_bit():
                try:
                    char_cur = char._cur
                    self._from_char_obj(char)
                except (CharpyErr, CSN1InvalidValueErr):
                    # we went to far, have to exit the loop
                    char._cur = char_cur
                    break
                else:
                    val.append( self._val )
            self._val = val
        else:
            assert()
        #
        if lref is not None:
            # restore the original char buffer length
            char._len_bit = char_lb
        #
        if self._root:
            _root_obj = root_obj
    
    def _to_pack(self):
        global _root_obj
        #
        if self._root:
            root_obj  = _root_obj
            _root_obj = self
        #
        ret = []
        if self._num == 1:
            ret.extend( self._to_pack_obj() )
        elif self._num > 1:
            # self._val is a list
            assert( isinstance(self._val, list) and len(self._val) == self._num )
            _num = self._num
            _val = self._val
            self._num = 1
            for val in _val:
                self._val = val
                ret.extend( self._to_pack_obj() )
            self._num = _num
            self._val = _val
        elif self._num == -1:
            # self._val is a list
            assert( isinstance(self._val, list) )
            _num = self._num
            _val = self._val
            self._num = 1
            for val in _val:
                self._val = val
                ret.extend( self._to_pack_obj() )
            self._num = _num
            self._val = _val
        else:
            assert()
        #
        if self._root:
            _root_obj = root_obj
        #
        return ret
    
    def get_bl(self):
        # this is required to support .bin() and .hex()
        # we use _to_pack() because counting bits for CSN1Alt depends on the
        # value set and needs value propagation and so on... and it's hard...
        if self._val is None:
            return 0
        else:
            return sum([p[2] for p in self._to_pack()])
    
    def from_bytes(self, buf):
        if isinstance(buf, bytes_types):
            char = Charpy(buf)
        else:
            char = buf
        self._from_char(char)
    
    def to_bytes(self):
        if self._val is None:
            return b''
        else:
            return pack_val( *self._to_pack() )[0]
    
    # TODO: implement _from_char / _to_pack methods building structures
    # with Envelope() and Atom() elements... hard work
    def from_bytes_ws(self, buf):
        pass
    
    def to_bytes_ws(self, buf):
        pass
    
    def _clone_get_kw(self):
        kw = {}
        if self._name:
            kw['name'] = self._name
        if self._num != self.__class__._num:
            kw['num'] = self._num
        if self._lref != self.__class__._lref:
            kw['lref'] = self._lref
        if self._root != self.__class__._root:
            kw['root'] = self._root
        return kw
     
    def clone(self):
        """Returns a independant instance of self, all internal attributes
        are cloned except value
        """
        raise(CSN1Err('not implemented'))


class CSN1Bit(CSN1Obj):
    """Class to handle a CSN.1 bit field
    
    specific internal attributes:
        - bit : number of bits in the bit field (default 1)
        - type: CSN1T_UINT (default) or CSN1T_BSTR, how the value is handled
        - dict: dictionnary for value representation
        - val : uint (type CSN1T_UINT) or bit string (type CSN1T_BSTR)
    """
    
    _bit  = 1
    _type = CSN1T_UINT
    _dict = None
    
    def __init__(self, **kw):
        CSN1Obj.__init__(self, **kw)
        if 'bit' in kw and kw['bit'] > 1:
            self._bit  = kw['bit']
        if 'type' in kw and kw['type'] != self.__class__._type:
            self._type = kw['type']
        if 'dict' in kw and kw['dict'] is not None:
            self._dict = kw['dict']
        self._val = None
    
    def _repr_val(self):
        if self._REPR == 'B' and self._type == CSN1T_UINT:
            val = uint_to_bitstr(self._val, self._bit)
        else:
            val = self._val
        if self._dict and self._val[1] in self._dict:
            return '%r (%s)' % (val, self._dict[self._val])
        else:
            # int or bit-string
            return val.__repr__()
    
    _show_val = _repr_val
    
    def _from_char_obj(self, char):
        if self._type == CSN1T_UINT:
            self._val = char.get_uint(self._bit)
        elif self._type == CSN1T_BSTR:
            self._val = uint_to_bitstr(char.get_uint(self._bit), self._bit)
        else:
            assert()
    
    def _to_pack_obj(self):
        if self._type == CSN1T_UINT:
            return [(CSN1T_UINT, self._val, self._bit)]
        else:
            return [(CSN1T_UINT, int(self._val, 2), self._bit)]
    
    def clone(self):
        kw = self._clone_get_kw()
        if self._bit != self.__class__._bit:
            kw['bit'] = self._bit
        if self._type != self.__class__._type:
            kw['type'] = self._type
        if self._dict != self.__class__._dict:
            kw['dict'] = self._dict
        return self.__class__(**kw)


class CSN1List(CSN1Obj):
    """Class to handle a CSN.1 list of CSN1Obj instances
    
    specific internal attributes:
        - list: list of CSN1Obj instances
        - val : list of CSN1Obj values
    """
    # ENC_LREF enables to automatically encode length determinant
    ENC_LREF = True
    
    _list  = []
    
    def __init__(self, **kw):
        CSN1Obj.__init__(self, **kw)
        if 'list' in kw and kw['list']:
            self._list = kw['list']
        self._val  = None
    
    def _repr_val(self):
        content = []
        for i, val in enumerate(self._val):
            Obj = self._list[i]
            obj_val  = Obj._val
            Obj._val = val
            content.append( Obj.repr() )
            Obj._val = obj_val
        if not content:
            return '[]'
        else:
            return '[' + ''.join(content) + ']'
    
    def _show_val(self):
        content = []
        for i, val in enumerate(self._val):
            Obj = self._list[i]
            obj_val  = Obj._val
            Obj._val = val
            content.append( Obj.show().replace('\n', '\n ') )
            Obj._val = obj_val
        if not content:
            return '[]'
        else:
            return '[\n ' + '\n '.join(content) + ']'
    
    def _from_char_obj(self, char):
        self._val, char_err = [], False
        for Obj in self._list:
            obj_val = Obj._val
            if Obj._lref:
                lref = self._val[Obj._lref]
                try:
                    Obj._from_char(char, lref)
                except CharpyErr:
                    char_err = True
            elif isinstance(Obj, CSN1Val):
                try:
                    val = char.get_uint(len(Obj._val))
                except CharpyErr:
                    char_err = True
                else:
                    if int(Obj._val, 2) != val:
                        Obj._val = obj_val
                        raise(CSN1InvalidValueErr())
            else:
                try:
                    Obj._from_char(char)
                except CharpyErr:
                    char_err = True
            #
            if not char_err:
                self._val.append( Obj._val )
                Obj._val = obj_val
            else:
                Obj._val = obj_val
                break
    
    def _to_pack_obj(self):
        ret = []
        if self.ENC_LREF:
            ret_cur = []
            for i, val in enumerate(self._val):
                ret_cur.append( len(ret) )
                Obj = self._list[i]
                if isinstance(Obj, CSN1Val):
                    ret.append( (CSN1T_UINT, int(Obj._val, 2), len(Obj._val)) )
                else:
                    obj_val  = Obj._val
                    Obj._val = val
                    ret.extend( Obj._to_pack() )
                    Obj._val = obj_val
                    #
                    if Obj._lref:
                        # get the length in bits corresponding to the encoded object
                        obj_len = sum( [e[2] for e in ret[ret_cur[-1]:]] )
                        # set it to the length object backward in ret
                        len_val = ret[ret_cur[Obj._lref-1]]
                        if obj_len >= (1<<len_val[-1]):
                            raise(CSN1Err('{0}: length prefix overflow, {1}'\
                                  .format(self._name, obj_len)))
                        # reassign the object value
                        ret[ret_cur[Obj._lref-1]] = (len_val[0], obj_len, len_val[2])
        else:
            for i, val in enumerate(self._val):
                Obj = self._list[i]
                if isinstance(Obj, CSN1Val):
                    ret.append( (CSN1T_UINT, int(Obj._val, 2), len(Obj._val)) )
                else:
                    obj_val  = Obj._val
                    Obj._val = val
                    ret.extend( Obj._to_pack_obj() )
                    Obj._val = obj_val
        return ret
    
    def clone(self):
        kw = self._clone_get_kw()
        if self._list:
            kw['list'] = [Obj.clone() for Obj in self._list]
        return self.__class__(**kw)
        

class CSN1Alt(CSN1Obj):
    """Class to handle a CSN.1 alternative between multiple list of CSN1Obj 
    instances
    
    specific internal attributes:
        - alt : dict of { bit string : list of CSN1Obj instances }
        - klen: length of the bit-string required for selecting an alternative
        - kdic: dictionnary of {key bit-string: alternative name}
        - val : list of CSN1Obj values
    """
    # ENC_LREF enables to automatically encode length determinant
    ENC_LREF = True
    
    _alt  = {}
    _klen = 1
    _kdic = None
    
    def __init__(self, **kw):
        CSN1Obj.__init__(self, **kw)
        if 'alt' in kw and kw['alt']:
            self._alt = kw['alt']
        if 'klen' in kw and kw['klen'] != 1:
            self._klen = kw['klen']
        if 'kdic' in kw and kw['kdic']:
            self._kdic = kw['kdic']
        self._val  = None
    
    def _repr_val(self):
        if not self._val:
            return '{}'
        else:
            k, kval = self._val[0], int(self._val[0], 2)
            if self._kdic and kval in self._kdic:
                alt_name = self._kdic[kval]
            else:
                alt_name = self._alt[k][0]
            alt_list = self._alt[k][1]
            if alt_name:
                pref = '{%r (%s): [' % (k, alt_name)
            else:
                pref = '{%r, [' % k
            content = []
            for i, val in enumerate(self._val[1:]):
                Obj = alt_list[i]
                obj_val  = Obj._val
                Obj._val = val
                content.append( Obj.repr() )
                Obj._val = obj_val
            if not content:
                return pref + ']}'
            else:
                return pref + ''.join(content) + ']}'
    
    def _show_val(self):
        if not self._val:
            return '{}'
        else:
            k, kval = self._val[0], int(self._val[0], 2)
            if self._kdic and kval in self._kdic:
                alt_name = self._kdic[kval]
            else:
                alt_name = self._alt[k][0]
            alt_list = self._alt[k][1]
            if alt_name:
                pref = '{%r (%s): [\n ' % (k, alt_name)
            else:
                pref = '{%r, [\n ' % k
            content = []
            for i, val in enumerate(self._val[1:]):
                Obj = alt_list[i]
                obj_val  = Obj._val
                Obj._val = val
                content.append( Obj.show().replace('\n', '\n ') )
                Obj._val = obj_val
            if not content:
                return pref[:-2] + ']}'
            else:
                return pref + '\n '.join(content) + ']}'
    
    def _from_char_obj(self, char):
        self._val = []
        # 
        # 1) select alternative
        if '' in self._alt and char.len_bit() > 0:
            k = ''
        elif None in self._alt and char.len_bit() == 0:
            # not entering any alternative
            #self._val = None
            return
        else:
            k = uint_to_bitstr(char.get_uint(self._klen), self._klen)
            if k not in self._alt:
                raise(CSN1Err('{0}: invalid alternative key, {1!r}'.format(self._name, k)))
        obj_list = self._alt[k][1]
        self._val.append(k)
        #
        # 2) decode alternative
        char_err = False
        for Obj in obj_list:
            obj_val = Obj._val
            if Obj._lref:
                lref = self._val[Obj._lref]
                try:
                    Obj._from_char(char, lref)
                except CharpyErr:
                    char_err = True
            elif isinstance(Obj, CSN1Val):
                try:
                    val = char.get_uint(len(Obj._val))
                except CharpyErr:
                    char_err = True
                else:
                    if int(Obj._val, 2) != val:
                        Obj._val = obj_val
                        raise(CSN1InvalidValueErr())
            else:
                try:
                    Obj._from_char(char)
                except CharpyErr:
                    char_err = True
            #
            if not char_err:
                self._val.append( Obj._val )
                Obj._val = obj_val
            else:
                Obj._val = obj_val
                break
    
    def _to_pack_obj(self):
        ret = []
        if not self._val and None in self._alt:
            return ret
        # encode alternative selector
        k = self._val[0]
        assert( isinstance(k, str_types) )
        ret.append( (CSN1T_UINT, int(k, 2), len(k)) )
        obj_list = self._alt[k][1]
        #
        # encode alternative list
        if self.ENC_LREF:
            ret_cur = []
            for i, val in enumerate(self._val[1:]):
                ret_cur.append( len(ret) )
                Obj = obj_list[i]
                if isinstance(Obj, CSN1Val):
                    ret.append( (CSN1T_UINT, int(Obj._val, 2), len(Obj._val)) )
                else:
                    obj_val  = Obj._val
                    Obj._val = val
                    ret.extend( Obj._to_pack() )
                    Obj._val = obj_val
                    #
                    if Obj._lref:
                        # get the length in bits corresponding to the encoded object
                        obj_len = sum( [e[2] for e in ret[ret_cur[-1]:]] )
                        # set it to the length object backward in ret
                        len_val = ret[ret_cur[Obj._lref-1]]
                        if obj_len >= (1<<len_val[2]):
                            raise(CSN1Err('{0}: length prefix overflow, {1}'\
                                  .format(self._name, obj_len)))
                        # reassign the object value
                        ret[ret_cur[Obj._lref-1]] = (len_val[0], obj_len, len_val[2])
        else:
            for i, val in enumerate(self._val):
                Obj = obj_list[i]
                if isinstance(Obj, CSN1Val):
                    ret.append( (CSN1T_UINT, int(Obj._val, 2), len(Obj._val)) )
                else:
                    obj_val  = Obj._val
                    Obj._val = val
                    ret.extend( Obj._to_pack_obj() )
                    Obj._val = obj_val
        return ret
    
    def clone(self):
        kw = self._clone_get_kw()
        if self._alt:
            kw['alt'] = {k: (self._alt[k][0], [Obj.clone() for Obj in self._alt[k][1]]) for k in self._alt}
        if self._klen != self.__class__._klen:
            kw['klen'] = self._klen
        if self._kdic != self.__class__._kdic:
            kw['kdic'] = self._kdic
        return self.__class__(**kw)


class CSN1Val(CSN1Obj):
    """Class to handle a CSN.1 value
    
    specific internal attributes:
        - val: bit string
    """
    
    _val = ''
    
    def __init__(self, **kw):
        CSN1Obj.__init__(self, **kw)
        if 'val' in kw and kw['val']:
            self._val = kw['val']
    
    def _repr_val(self):
        return self._val.__repr__()
    
    _show_val = _repr_val
    
    def _from_char_obj(self, char):
        assert()
    
    def _to_pack_obj(self):
        assert()
    
    def clone(self):
        kw = self._clone_get_kw()
        if self._val != self.__class__._val:
            kw['val'] = self._val
        return self.__class__(**kw)
        

class CSN1Ref(CSN1Obj):
    """Class to handle a reference to another CSN.1 object
    
    specific internal attributes:
        - obj: ASN1Obj instance
        - val: value according to obj
    """
    
    _obj = None
    
    def __init__(self, **kw):
        CSN1Obj.__init__(self, **kw)
        if 'obj' in kw and kw['obj']:
            self._obj = kw['obj']
        self._val = None
    
    def _repr_val(self):
        obj_val        = self._obj._val
        self._obj._val = self._val
        obj_repr       = self._obj.repr()
        self._obj._val = obj_val
        return obj_repr
    
    def _show_val(self):
        obj_val        = self._obj._val
        self._obj._val = self._val
        obj_repr       = self._obj.show()
        self._obj._val = obj_val
        return obj_repr
    
    def _from_char_obj(self, char):
        obj_val = self._obj._val
        self._obj._from_char(char)
        self._val = self._obj._val
        self._obj._val = obj_val
    
    def _to_pack_obj(self):
        obj_val = self._obj._val
        self._obj._val = self._val
        ret = self._obj._to_pack()
        self._obj._val = obj_val
        return ret
    
    def clone(self):
        kw = self._clone_get_kw()
        kw['obj'] = self._obj.clone()
        return self.__class__(**kw)


class CSN1SelfRef(CSN1Obj):
    """Class to handle a reference to the root CSN1 object
    
    specific internal attributes:
        - val: value according to the roo object
    """
    
    def __init__(self, **kw):
        CSN1Obj.__init__(self, **kw)
        self._val  = None
    
    def _repr_val(self):
        global _root_obj
        root_obj_val   = _root_obj._val
        _root_obj._val = self._val
        root_obj_repr  = _root_obj.repr()
        _root_obj._val = root_obj_val
        return root_obj_repr
    
    def _show_val(self):
        global _root_obj
        root_obj_val   = _root_obj._val
        _root_obj._val = self._val
        root_obj_repr  = _root_obj.show()
        _root_obj._val = root_obj_val
        return root_obj_repr
    
    def _from_char_obj(self, char):
        global _root_obj
        if _root_obj is None:
            raise(CSN1Err('{0}: no root object referenced'.format(self._name)))
        # preserve already existing root object value
        root_obj_val = _root_obj._val
        _root_obj._from_char(char)
        self._val = _root_obj._val
        # restore initial value
        _root_obj._val = root_obj_val
    
    def _to_pack_obj(self):
        global _root_obj
        if _root_obj is None:
            raise(CSN1Err('{0}: no root object referenced'.format(self._name)))
        # preserve already existing root object value
        root_obj_val = _root_obj._val
        _root_obj._val = self._val
        ret = _root_obj._to_pack()
        # restore initial value
        _root_obj._val = root_obj_val
        return ret
    
    def clone(self):
        return self.__class__(**self._clone_get_kw())

