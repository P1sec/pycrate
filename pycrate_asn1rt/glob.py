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
# * File Name : pycrate_asn1rt/glob.py
# * Created : 2017-01-31
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils   import asnlog, name_to_defin
from .err     import ASN1Err
from .dictobj import ASN1Dict


#------------------------------------------------------------------------------#
# ASN.1 global directory: GLOBAL
#------------------------------------------------------------------------------#

# When processing a set of ASN.1 modules, all user-defined objects are put in a
# GLOBAL class: it serves as a container for accessing all the objects at 
# runtime

def make_GLOBAL(global_name=None):
    '''
    returns an new empty GLOBAL class for containing a set of ASN.1 modules
    
    class attributes of GLOBAL:
    
    - MOD : ASN1Dict containing module's objects withinin ASN1Dict, indexed by module's names
    MOD[$mod_name] = ASN1Dict([('_oid_'    : module oid),
                               ('_obj_'    : list of all objects name),
                               ('_type_'   : list of types name),
                               ('_set_'    : list of sets name),
                               ('_val_'    : list of values name),
                               ('_class_'  : list of classes name),
                               ('_param_'  : list of parameterized objects name),
                               ('$objname': ASN1Obj instance),
                               ... ])
    '''
    
    class GLOBAL(object):
        #
        # dict indexed by modules' name and containing modules' objects
        MOD = ASN1Dict()
        
        # OID lookup table (OID value: OID name)
        OID = {}
        
        @classmethod
        def clear(cla):
            cla.MOD.clear()
            cla.OID.clear()
    
    if isinstance(global_name, str):
        GLOBAL.__name__ = global_name
    
    return GLOBAL

GLOBAL = make_GLOBAL()


def export_all(scope, GLOB=GLOBAL):
    """
    export all objects from GLOBAL.MOD to the given scope, e.g.
    >>> export_all(globals())
    
    WNG: in case of object name clash between modules, only the last object
    exported will be available in the given scope
    """
    for mod_name in GLOB.MOD:
        for obj_name in GLOB.MOD[mod_name]:
            name = name_to_defin(obj_name)
            if name in scope:
                asnlog('WNG: duplicate object\'s name {0}'.format(name))
            scope[name] = GLOBAL.MOD[mod_name][obj_name]

def get_asnobj(Ref, GLOB=GLOBAL):
    """
    returns the ASN.1 object according the provided Ref (ASN1Ref)
    """
    try:
        Mod = GLOB.MOD[Ref.called[0]]
    except KeyError:
        raise(ASN1Err('invalid type reference to module {0}'.format(Ref.called[0])))
    try:
        Obj = Mod[Ref.called[1]]
    except KeyError:
        raise(ASN1Err('invalid type reference to object {0} in module {1}'.format(Ref.called[1], Ref.called[0])))
    return Obj

def get_asnobj_tup(Tup, GLOB=GLOBAL):
    """
    returns the ASN.1 object according the provided refeference Tup (2-tuple)
    """
    try:
        Mod = GLOB.MOD[Tup[0]]
    except KeyError:
        raise(ASN1Err('invalid type reference to module {0}'.format(Tup[0])))
    try:
        Obj = Mod[Tup[1]]
    except KeyError:
        raise(ASN1Err('invalid type reference to object {0} in module {1}'.format(Tup[1], Tup[0])))
    return Obj
