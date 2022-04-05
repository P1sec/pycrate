# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
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
# * File Name : pycrate_asn1rt/wrapper.py
# * Created : 2017-10-26
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from pycrate_core.utils import TYPE_BYTES, uint_to_hex, bytes_to_uint, bytes_to_bitstr
from pycrate_core.elt   import Element
from pycrate_core.elt   import _with_json


def gen_ber_wrapper(obj, asn_acquire=lambda:None, asn_release=lambda:None):
    """generates a class that wraps an ASN.1 object `obj'.
    
    The generated class is a sub-class of Element,
    from the pycrate_core.elt module.
    It is usable (almost) like any other Element from the pycrate_core.elt.
    
    _from_char() and _to_pack() methods call the BER codec for decoding and
    encoding.
    
    asn_acquire and asn_release are functions that lock and unlock all the ASN
    objects of the module: this prevents multi-threading issues.
    
    
    Args:
        obj: ASN1Obj instance
        asn_acquire: callable, return None or raise
        asn_release: callable, return None or raise
    
    Returns:
        class: Python sub-class of Element, wrapping obj
    """
    
    class _ASNWrapper(Element):
        """Special Element that wraps an ASN.1 object, and use BER codec for
        serializing value
        """
        
        OBJ = obj
        
        # default attributes value
        _env        = None
        _hier       = 0
        _val        = None
        _bl         = None
        _trans      = None
        _transauto  = None
        
        __attrs__ = ('_env',
                     '_name',
                     '_hier',
                     '_val',
                     '_bl',
                     '_buf',
                     '_trans',
                     '_transauto')
        
        def __init__(self, *args, **kw):
            self.__class__.__name__ = str(obj._name)
            
            # element name in kw, or first args
            if len(args):
                self._name = str(args[0])
            elif 'name' in kw:
                self._name = str(kw['name'])
            # if not provided, it's the class name
            else:
                self._name = self.__class__.__name__
            
            # element hierarchy
            if 'hier' in kw:
                self._hier = kw['hier']
            
            # element transparency
            if 'trans' in kw:
                self._trans = kw['trans']
            
            # element value
            if 'val' in kw:
                self.set_val(kw['val'])
            
            if self._SAFE_STAT:
                self._chk_hier()
                self._chk_trans()
        
        # value and bit length handling
        # using the ASN1Obj methods from pycrate_asn1rt.asnobj:
        # set_val(), get_val() and __call__()
        
        def set_val(self, val):
            if val is None:
                self._val = None
                self._bl  = 0
                self._buf = b''
            else:
                self._asn_acquire()
                self.OBJ.set_val(val)
                self._val = self.OBJ._val
                self._buf = self.OBJ.to_ber()
                self._bl  = 8*len(self._buf)
                self._asn_release()
        
        def get_val(self):
            return self._val
        
        __call__ = get_val
        
        def get_bl(self):
            return self._bl
        
        # decoding / encoding
        # using the ASN.1 BER codec
        
        def _from_char(self, char):
            buf = char.get_bytes()
            self._asn_acquire()
            self.OBJ.from_ber(buf)
            self._val = self.OBJ._val
            self._asn_release()
            self._buf = buf
            self._bl  = 8*len(buf)
        
        def _to_pack(self):
            if self._val is None:
                return []
            else:
                return [(TYPE_BYTES, self._buf, self._bl)]
        
        # representation
        
        def repr(self):
            return '<%s [~ASN1~] : %s>' % (self._name, repr(self._val))
        
        __repr__ = repr
        
        def show(self):
            self._asn_acquire()
            self.OBJ._val = self._val
            ret = '<%s [~ASN1~] : %s>' % (self._name, self.OBJ.to_asn1())
            self._asn_release()
            return ret
        
        def hex(self):
            b = self.to_bytes()
            if not b:
                return ''
            else:
                return uint_to_hex(bytes_to_uint(b, 8*len(b)), 8*len(b))
        
        def bin(self):
            b = self.to_bytes()
            if not b:
                return ''
            else:
                bytes_to_bitstr(b)
        
        # cloning
        
        def clone(self):
            return self.__class__(val=self._val,
                                  trans=self._trans,
                                  hier=self._hier)
        
        # ASN directory acquisition and release, requires to be defined
        # for each specific module
        
        def _asn_acquire(self):
            return asn_acquire()
        
        def _asn_release(self):
            return asn_release()
        
        if _with_json:
            
            def _from_jval(self, val):
                self._asn_acquire()
                self.OBJ._from_jval(val)
                self._val = self.OBJ._val
                self._buf = self.OBJ.to_ber()
                self._bl  = 8*len(self._buf)
                self._asn_release()
                if self.OBJ._SAFE_BND:
                    self.OBJ._safechk_bnd(self.OBJ._val)
            
            def _to_jval(self):
                self._asn_acquire()
                self.OBJ._val = self._val
                self._buf = self.OBJ.to_ber()
                self._bl = 8*len(self._buf)
                ret = self.OBJ._to_jval()
                self._asn_release()
                return ret
    
    #
    return _ASNWrapper

