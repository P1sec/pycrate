# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2017. Benoit Michau. ANSSI.
# * Copyright 2018. Benoit Michau. P1Sec.
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
# * File Name : pycrate_asn1rt/asnobj_class.py
# * Created : 2017-01-31
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils   import *
from .err     import *
from .dictobj import *
from .glob    import *
from .refobj  import *
from .setobj  import *
from .asnobj  import *
from .asnobj_construct import SEQ


class CLASS(ASN1Obj):
    __doc__ = """
ASN.1 CLASS object type

This is a special object not intended to be encoded / decoded, 
but used as reference and lookup table for OPEN TYPE determination

Single value: Python dict
    keys are fields' identifier (str),
    values are ASN1Obj single value, values set or type, specific to each
    field

Specific attributes:
    
    - cont: ASN1Dict {ident (str): ASN1Obj instance},
        provides the content of the CHOICE object
    
    - root_mand: list of identifiers (str),
        provides the list of mandatory components in the root part
    
    - root_opt: list of identifiers (str),
        provides the list of optional components in the root part

Specific method:
    
    __call__(*args)
    args can be used to filter out part of the value available in _val attribute
    
    if args is None,
        it returns the _val attribute
    
    if args is a single identifier (str),
        it returns the list of values for this field
    
    if args are an identifier (str) and the corresponding value (single value for 
    the field corresponding to the single identifier),
        it returns the CLASS value corresponding to this field with this value
    

%s
""" % ASN1Obj_docstring
    
    TYPE  = TYPE_CLASS
    TAG   = None
    
    # this is to always enumerate all class set of values,
    # for when the UNIQUE field is actually not unique and the class set is
    # not defined at the module root (and hence has not _lut attribute)
    _CLASET_MULT = False
     
    def _safechk_val(self, val):
        if not isinstance(val, dict) or not all([k in self._cont for k in val]):
            raise(ASN1ObjErr('{0}: invalid value, {1!r}'.format(self.fullname(), val)))
        # check for OPTIONAL / DEFAULT root values
        if not all([k in val for k in self._root_mand]):
            raise(ASN1ObjErr('{0}: missing mandatory value, {1!r}'.format(self.fullname(), val)))
        #for (k, v) in val.items():
        #    self._cont[k]._safechk_val(v)
    
    def __call__(self, *args):
        # calling CLASS enables to get lists of values or values corresponding
        # to identifiers
        if len(args) == 0:
            return self._val
        if len(args) >= 1:
            name = args[0]
        if len(args) >= 2:
            val = args[1]
        else:
            val = None
        #
        if name not in self._cont:
            raise(ASN1ObjErr('{0}: invalid identifier, {1}'\
                  .format(self.fullname(), name)))
        #
        if self._mode == MODE_VALUE:
            if name not in self._val:
                # `name' is not present in the class value
                # should be an OPTIONAL component
                return None
            elif val is None:
                # return the value for the given identifier
                return self._val[name]
            elif val == self._val[name]:
                # returns the list of fields' value associated
                return self._val
            else:
                return None
        #
        elif self._mode == MODE_SET:
            if val is None:
                # TODO: it may be more accurate to return an ASN1Set instead of a list
                values = []
                # return all the values for the given identifier
                if self._val.root:
                    for v in self._val.root:
                        try:
                            values.append(v[name])
                        except KeyError:
                            # `name' is not present in the class value
                            # should be an OPTIONAL component
                            pass
                if self._val.ext:
                    for v in self._val.ext:
                        try:
                            values.append(v[name])
                        except KeyError:
                            # `name' is not present in the class value
                            # should be an OPTIONAL component
                            pass
                return values
            else:
                if self._val.root:
                    for v in self._val.root:
                        try:
                            if v[name] == val:
                                return v
                        except KeyError:
                            pass
                if self._val.ext:
                    for v in self._val.ext:
                        try:
                            if v[name] == val:
                                return v
                        except KeyError:
                            pass
                return None
    
    def get(self, key, val):
        # this is using the _lut attribute, which is built at module init
        # for every CLASS set defined at the root of a module
        if hasattr(self, '_lut'):
            if key == self._lut['__key__']:
                # WARNING: val is not always a basic value (e.g. INTEGER),
                # but can be a constructed value, hence a dict or a list
                # We need to make it hashable for Python
                if isinstance(val, list):
                    val = tuple(val)
                elif isinstance(val, dict):
                    val = tuple(sorted(val.items()))
                try:
                    return self._lut[val]
                except KeyError:
                    return (CLASET_NONE, None)
        if self._CLASET_MULT:
            ret = self.get_mult(key, val)
            if len(ret) > 1:
                return (CLASET_MULT, ret)
            elif ret:
                return (CLASET_UNIQ, ret[0])
            else:
                (CLASET_NONE, None)
        else:
            ret = self.get_uniq(key, val)
            if ret:
                return (CLASET_UNIQ, ret)
            else:
                return (CLASET_NONE, None)
    
    def get_uniq(self, name, val):
        # this is using an enumeration of all CLASS set of values,
        # and returns the first corresponding value found
        ret = None
        if self._mode != MODE_SET:
            return ret
        if self._val.root:
            for v in self._val.root:
                try:
                    if v[name] == val:
                        return v
                except KeyError:
                    pass
        if self._val.ext:
            for v in self._val.ext:
                try:
                    if v[name] == val:
                        return v
                except KeyError:
                    pass
        return ret
    
    def get_mult(self, name, val):
        # this is using a complete enumeration of all CLASS set of values,
        # and returns the list of corresponding values found
        ret = []
        if self._mode != MODE_SET:
            return ret
        if self._val.root:
            for v in self._val.root:
                try:
                    if v[name] == val:
                        ret.append(v)
                except KeyError:
                    pass
        if self._val.ext:
            for v in self._val.ext:
                try:
                    if v[name] == val:
                        ret.append(v)
                except KeyError:
                    pass
        return ret
    
    # this is very experimental... and may certainly raise() in case of 
    # MODE_SET or MODE_TYPE field setting
    def from_asn1(self, txt):
        return SEQ.from_asn1(self, txt)
    
    def to_asn1(self, val=None):
        return SEQ.to_asn1(self, val)
    
