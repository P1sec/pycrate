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
# * File Name : pycrate_asn1c/extractor.py
# * Created : 2016-11-30
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils   import *
from .dictobj import *
from .refobj  import *

def get_objs(Obj):
    """returns the list with all ASN1Obj contained within an ASN1Obj
    """
    objs = []
    if Obj._const:
        objs.extend( _get_objs_from_const(Obj._const, Obj._type) )
    if Obj._type in TYPE_CONSTRUCT and Obj._cont:
        objs.extend( _get_objs_from_cont(Obj._cont) )
    if Obj._type == TYPE_OPEN and Obj._val:
        if Obj._mode == MODE_VALUE:
            objs.extend( _get_objs_from_valopen(Obj._val[0]) )
        elif Obj._mode == MODE_SET:
            for val in Obj._val['root']:
                objs.extend( _get_objs_from_valopen(val[0]) )
            if Obj._val['ext']:
                for val in Obj._val['ext']:
                    objs.extend( _get_objs_from_valopen(val[0]) )
    elif Obj._type == TYPE_CLASS and Obj._val:
        if Obj._mode == MODE_VALUE:
            objs.extend( _get_objs_from_valclass(Obj._val) )
        elif Obj._mode == MODE_SET:
            for val in Obj._val['root']:
                objs.extend( _get_objs_from_valclass(val) )
            if Obj._val['ext']:
                for val in Obj._val['ext']:
                    objs.extend( _get_objs_from_valclass(val) )
    return objs

def _get_objs_from_const(consts, type=None):
    objs = []
    for const in consts:
        if const['type'] == CONST_VAL:
            if type == TYPE_OPEN:
                for val in const['root']:
                    objs.extend( _get_objs_from_valopen(val) )
                if const['ext']:
                    for val in const['ext']:
                        objs.extend( _get_objs_from_valopen(val) )
            elif type == TYPE_CLASS:
                for val in const['root']:
                    objs.extend( _get_objs_from_valclass(val) )
                if const['ext']:
                    for val in const['ext']:
                        objs.extend( _get_objs_from_valclass(val) )
        elif const['type'] == CONST_TABLE:
            objs.append( const['tab'] )
            objs.extend( get_objs(const['tab']) )
        elif const['type'] == CONST_COMPS:
            for dic in const['root']:
                # get any key except '_abs' and '_pre'
                idents = list(dic.keys())
                idents.remove('_abs')
                idents.remove('_pre')
                for ident in idents:
                    objs.extend( _get_objs_from_const(dic[ident]['const'], type) )
            if const['ext']:
                for dic in const['ext']:
                    # get any key except '_abs' and '_pre'
                    idents = list(dic.keys())
                    idents.remove('_abs')
                    idents.remove('_pre')
                    for ident in idents:
                        objs.extend( _get_objs_from_const(dic[ident]['const'], type) )  
        elif const['type'] == CONST_CONTAINING:
            objs.append( const['obj'] )
            objs.extend( get_objs(const['obj']) )
    return objs

def _get_objs_from_cont(cont):
    objs = []
    if isinstance(cont, ASN1Dict):
        for ident in cont:
            objs.append( cont[ident] )
            objs.extend( get_objs(cont[ident]) )
    elif hasattr(cont, '_type'):
        objs.append( cont )
        objs.extend( get_objs(cont) )
    elif cont is None:
        pass
    else:
        assert()
    return objs

def _get_objs_from_valopen(val):
    objs = []
    if hasattr(val, '_type'):
        objs.append( val )
        objs.extend( get_objs(val) )
    elif isinstance(val, ASN1Ref):
        pass
    else:
        assert()
    return objs

def _get_objs_from_valclass(val):
    objs = []
    if isinstance(val, ASN1Dict):
        for ident in val:
            objs.extend( _get_objs_from_valclass(val[ident]) )
    elif isinstance(val, dict):
        # this is a root / set dict of a set within a value
        for v in val['root']:
            objs.extend( _get_objs_from_valclass(v) )
        if val['ext']:
            for v in val['ext']:
                objs.extend( _get_objs_from_valclass(v) )  
    elif hasattr(val, '_type'):
        objs.append( val )
        objs.extend( get_objs(val) )
    elif isinstance(val, ASN1Ref):
        pass
    else:
        #assert()
        # this can be actually any value
        pass
    return objs
