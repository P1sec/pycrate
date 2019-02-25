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
# * File Name : pycrate_asn1c/glob.py
# * Created : 2016-03-02
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .dictobj import ASN1Dict

#------------------------------------------------------------------------------#
# ASN.1 global directory: GLOBAL
#------------------------------------------------------------------------------#

# When processing a set of ASN.1 modules, all user-defined objects are put in a
# GLOBAL class: it serves as a container for accessing all the objects at 
# runtime

def make_GLOBAL(global_name=None):
    """
    returns an new empty GLOBAL class for containing a set of ASN.1 modules
    
    class attributes of GLOBAL:
    
    - COMP : dict containing compilation parameters, keys:
        - ORDER : list or None, to force an order in which ASN.1 objects have to be compiled
        - NS    : dict containing the namespace defined when compiling an ASN.1 object, keys:
            - mod : str, name of the current module
            - par : dict with object's formal parameter names and objects
            - loc : dict with module's local names and objects
            - imp : dict with module's imported names and objects
    
    - MOD : ASN1Dict containing module's objects withinin ASN1Dict, indexed by module's names
    MOD[$mod_name] = ASN1Dict([('_name_'   : module name),
                               ('_oidstr_' : module textual oid), 
                               ('_oid_'    : module oid),
                               ('_tag_'    : module tagging option),
                               ('_ext_'    : module extensibility option),
                               ('_exp_'    : list of exported objects name or None),
                               ('_imp_'    : dict of imported objects name as index 
                                             and corresponding module name),
                               ('_obj_'    : list of all objects name),
                               ('_type_'   : list of types name),
                               ('_set_'    : list of sets name),
                               ('_val_'    : list of values name),
                               ('_class_'  : list of classes name),
                               ('_param_'  : list of parameterized objects name),
                               ('$obj_name': ASN1Obj instance),
                               ... ]) 
    
    - ERR : ASN1Dict containg ASN.1 objects for which compilation failed, 
            indexed by their name
    """
    
    class GLOBAL(object):
        #
        _DEFAULT_PREDEF = False
        #
        # compilation parameters
        COMP = {'ORDER'  : None,
                'DONE'   : [],
                # namespace when compiling an ASN.1 definition
                'NS'     : {'mod'    : '',
                            'tag'    : 'EXPLICIT',
                            'ext'    : None, 
                            'obj'    : {},
                            'par'    : None,
                            'path'   : [],
                            'setpar' : [],
                            'setdisp': 0}
                }
        #
        # dict indexed by modules' name and containing modules' objects
        MOD  = ASN1Dict((
            ('_IMPL_', ASN1Dict()),
            ('_USER_', ASN1Dict())
            ))
        #
        # stores objects in error when compilation fails
        ERR  = ASN1Dict()
        
        @classmethod
        def clear(cla):
            cla.COMP['PREDEF'] = cla._DEFAULT_PREDEF
            cla.COMP['ORDER'] = None
            cla.COMP['DONE'] = []
            impl, user = cla.MOD['_IMPL_'], cla.MOD['_USER_']
            impl.clear()
            user.clear()
            cla.MOD.clear()
            cla.MOD['_IMPL_'] = impl
            cla.MOD['_USER_'] = user
            cla.ERR.clear()
            cla.clear_comp_ns()
        
        @classmethod
        def clear_comp_ns(cla):
            cla.COMP['NS']['mod']     = ''
            cla.COMP['NS']['name']    = ''
            cla.COMP['NS']['tag']     = 'EXPLICIT'
            cla.COMP['NS']['ext']     = None
            cla.COMP['NS']['obj']     = {}
            cla.COMP['NS']['par']     = None
            cla.COMP['NS']['path']    = []
            cla.COMP['NS']['setpar']  = []
            cla.COMP['NS']['setdisp'] = 0

    
    if isinstance(global_name, str):
        GLOBAL.__name__ = global_name
    
    return GLOBAL

GLOBAL = make_GLOBAL()

