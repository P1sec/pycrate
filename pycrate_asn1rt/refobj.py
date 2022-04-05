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
# * File Name : pycrate_asn1rt/refobj.py
# * Created : 2017-01-31
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils import integer_types, NoneType
from .err  import ASN1Err
from .glob import GLOBAL


RefObj_docstring = """
Init args:
    called (2-tuple): name of the referenced ASN.1 module and object
    ced_path (list of str or int): path of the specific content referenced 
        inside the called object, can be empty
"""

class ASN1Ref(object):
    __doc__ = """
    Generic parent class to handle cross-reference between user-defined ASN.1 
    objects
    
    %s
    """ % RefObj_docstring
    
    KW = ('called', 'ced_path')
    
    def __init__(self, called, ced_path=[]):
        self.called   = called
        self.ced_path = ced_path
    
    # methods for emulating a dictionnary
    # this enables to reference path within ASN.1 objects in the form of 
    # list of str or int; e.g. path = ['const', 0, 'root', 0, 'ub'] 
    def __getitem__(self, kw):
        if kw in self.KW:
            return getattr(self, kw)
        else:
            return object.__getitem__(self, kw)
    
    def __setitem__(self, kw, arg):
        if kw in self.KW:
            return setattr(self, kw, arg)
        else:
            return object.__setitem__(self, kw, arg)
    
    def __eq__(self, other):
        # enable ASN1Ref equality test
        if type(other) != type(self):
            return False
        if other.called != self.called:
            return False
        if other.ced_path != self.ced_path:
            return False
        return True
    
    def __hash__(self):
        # enable the construction of set of unique references
        if hasattr(self, 'name'):
            return hash(self.name)
        else:
            return hash(self.called) + hash(tuple(self.ced_path))
    
    def _safechk(self):
        if not isinstance(self.called, (NoneType, tuple)):
            raise(ASN1Err('{0}: invalid called'.format(self.__class__.__name__)))
        if not isinstance(self.ced_path, list) or \
        not all([isinstance(e, (str, integer_types)) for e in self.ced_path]):
            raise(ASN1Err('{0}: invalid ced_path'.format(self.__class__.__name__)))
    
    def copy(self):
        """
        returns an equal but independent copy of self
        """
        if isinstance(self.called, tuple):
            return self.__class__(tuple(self.called), self.ced_path[:])
        else:
            assert()


class ASN1RefType(ASN1Ref):
    __doc__ = """
    Class to handle a reference to a user-defined ASN.1 type object
    e.g. MyNewType ::= MyType
    
    %s
    """ % RefObj_docstring
    
    def __repr__(self):
        # self.called is 2-tuple
        # self.ced_path is empty
        assert(isinstance(self.called, tuple))
        return 'ASN1RefType({0}.{1})'.format(self.called[0], self.called[1])
    
    def get(self):
        try:
            return GLOBAL.MOD[self.called[0]][self.called[1]]
        except:
            return None


class ASN1RefInstOf(ASN1Ref):
    __doc__ = """
    Class to handle a reference to a subclass of TYPE-IDENTIFIER
    e.g. MyTypeIdent ::= TYPE-IDENTIFIER
         MyInstOf ::= INSTANCE OF MyTypeIdent
    
    %s
    """ % RefObj_docstring
    
    def __repr__(self):
        # self.called is 2-tuple
        # self.ced_path is empty
        return 'ASN1RefInstOf({0}.{1})'.format(self.called[0], self.called[1])


class ASN1RefChoiceComp(ASN1Ref):
    __doc__ = """
    Class to handle a reference to a (chain of) component(s) within a 
    user-defined ASN.1 CHOICE object
    e.g. MyNewType ::= alt32<alt3<MyChoice
    
    %s
    """ % RefObj_docstring
    
    def __repr__(self):
        # self.called is 2-tuple
        # self.ced_path is not empty
        assert(isinstance(self.called, tuple))
        return 'ASN1RefChoiceComp({0}<{1}.{2})'\
               .format('<'.join(self.ced_path), self.called[0], self.called[1])
    
    def get(self):
        try:
            cho = GLOBAL.MOD[self.called[0]][self.called[1]]
            return cho.get_at(self.ced_path)
        except:
            return None


class ASN1RefClassField(ASN1Ref):
    __doc__ = """
    Class to handle a reference to a (chain of) field(s) within a user-defined 
    ASN.1 CLASS object
    e.g. MyNewType ::= MYCLASS.&field3.&field32
    
    %s
    """ %  RefObj_docstring
    
    def __repr__(self):
        # self.called is 2-tuple
        # self.ced_path is not empty
        assert(isinstance(self.called, tuple))
        return 'ASN1RefClassField({0}.{1}.&{2})'\
               .format(self.called[0], self.called[1], '.&'.join(self.ced_path))
    
    def get(self):
        try:
            cla = GLOBAL.MOD[self.called[0]][self.called[1]]
            return cla.get_at(self.ced_path)
        except:
            return None


class ASN1RefClassIntern(ASN1Ref):
    __doc__ = """
    Class to handle an local reference within a user-defined ASN.1 CLASS, 
    from one field to another
    e.g. MYCLASS ::= CLASS {
           &MyType,
           &myVal &MyType }
    
    %s
    """ % RefObj_docstring
    
    def __repr__(self):
        # self.called is None
        # self.ced_path is not empty
        return 'ASN1RefClassIntern(&{0})'.format('.&'.join(self.ced_path))


class ASN1RefClassValField(ASN1Ref):
    __doc__ = """
    Class to handle a reference to a field within a user-defined ASN.1 CLASS 
    value
    e.g. MyType ::= myClassValue.&MyType
    
    %s
    """ % RefObj_docstring
    
    def __repr__(self):
        # self.called is 2-tuple
        # self.ced_path is not empty
        assert(isinstance(self.called, tuple))
        return 'ASN1RefClassValField({0}.{1}.&{2})'\
               .format(self.called[0], self.called[1], '.&'.join(self.ced_path))

