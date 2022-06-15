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
# * File Name : pycrate_asn1c/asnobj.py
# * Created : 2016-05-12
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from binascii  import hexlify, unhexlify

from .utils   import *
from .utils   import _RE_IDENT, _RE_TYPEREF, _RE_WORD
from .err     import *
from .glob    import *
from .refobj  import *
from .setobj  import *
from .dictobj import *

#///////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\#
#------------------------------------------------------------------------------#
# debugging directives
#------------------------------------------------------------------------------#
#\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\///////////////////////////////////////#

_DEBUG_PARAM        = False
_DEBUG_PARAM_PT     = False
_DEBUG_PARAM_VAL    = False
_DEBUG_PARAM_SET    = False
_DEBUG_PARAM_TYPE   = False
#
_DEBUG_SYNTAX_GRP   = False
_DEBUG_SYNTAX_OGRP  = False
#
_DEBUG_SET_VAL      = False


# method tracer, to be used as a decorator
#_TRACE_NAME = ['ROS', ]
_TRACE_NAME = None
def tracemethod(meth, *args, **kwargs):
    def wrapper(*args, **kwargs):
        if _TRACE_NAME is None or GLOBAL.COMP['NS']['name'] in _TRACE_NAME:
            asnlog('---------------------------TRACE (%s)---------------------------'\
                   % GLOBAL.COMP['NS']['name'])
            asnlog('{0}.{1} :: {2}.{3}()'.format(
                   GLOBAL.COMP['NS']['mod'], GLOBAL.COMP['NS']['name'],
                   args[0].fullname(), meth.__name__))
            asnlog('    args   : {0!r}'.format(args[1:]))
            asnlog('    kwargs : {0!r}'.format(kwargs))
            asnlog('    NS path: {0!r}'.format(GLOBAL.COMP['NS']['path']))
            asnlog('    NS set : setdisp {0!r}, setpar {1!r}'.format(
                   GLOBAL.COMP['NS']['setdisp'], GLOBAL.COMP['NS']['setpar']))
        ret = meth(*args, **kwargs)
        if _TRACE_NAME is None or GLOBAL.COMP['NS']['name'] in _TRACE_NAME:
            asnlog('    ret    : {0!r}'.format(ret)) 
        return ret
    return wrapper

#///////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\#
#------------------------------------------------------------------------------#
# functions for processing paths inside ASN1Obj
#------------------------------------------------------------------------------#
#\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\///////////////////////////////////////#

def get_asnobj(mod_name, obj_name):
    """
    returns the ASN1Obj instance with the given obj_name in the module with the
    given mod_name
    """
    try:
        mod = GLOBAL.MOD[mod_name]
    except KeyError:
        raise(ASN1Err('module {0}, undefined'.format(mod_name)))
    # it is possible to import an object from a module which itsel imports it...
    while obj_name in mod['_imp_']:
        try:
            mod = GLOBAL.MOD[mod['_imp_'][obj_name]]
        except KeyError:
            raise(ASN1Err('module {0}, undefined'.format(mod_name)))
    try:
        obj = mod[obj_name]
    except KeyError:
        raise(ASN1Err('object {0} in module {1}, undefined'.format(obj_name, mod_name)))
    else:
        return obj

def _get_path_objs(Obj, path=[]):
    """
    returns the list of objects along the path, starting from Obj
    """
    if not path:
        return []
    L = []
    item = Obj
    for step in path:
        try:
            item = item[step]
        except Exception as err:
            raise(ASN1Err('_get_path_objs: {0}'.format(err)))
        else:
            L.append(item)
    return L

def _get_path_last_obj(Obj, path=[]):
    """
    returns the last object at the end of the path, starting from Obj
    """
    if not path:
        return Obj
    item = Obj
    for step in path:
        try:
            item = item[step]
        except Exception as err:
            raise(ASN1Err('_get_path_last_obj: {0}'.format(err)))
    return item

def _get_copy(Obj):
    """
    returns a copy of the Python object Obj, but with identical content
    """
    # copy a mutable / instance object into a new one but with the same 
    # referred content
    if isinstance(Obj, list):
        return Obj[:]
    elif isinstance(Obj, dict):
        return dict(Obj)
    elif isinstance(Obj, (ASN1Dict, ASN1Range, ASN1Ref, ASN1Obj)):
        return Obj.copy()
    else:
        raise(ASN1Err('_asncopy: unsupported object, {0}'.format(type(Obj))))

def _get_path_copy(Obj, path=[]):
    """
    returns a copy of all objects along the path, except the last one, 
    starting from Obj
    """
    path_objs = _get_path_objs(Obj, path)
    ind = len(path)-1
    item = path_objs[ind]
    for obj in reversed(path_objs[:-1]):
        objcopy = _get_copy(obj)
        objcopy[path[ind]] = item
        item = objcopy
        ind -= 1
    return item

#///////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\#
#------------------------------------------------------------------------------#
# functions for processing the global current path
#------------------------------------------------------------------------------#
#\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\///////////////////////////////////////#

def _path_ext(ext):
    # append an extension to the root and current path if different
    GLOBAL.COMP['NS']['path'][0].extend(ext)
    if len(GLOBAL.COMP['NS']['path']) > 1:
        GLOBAL.COMP['NS']['path'][-1].extend(ext)
    #
    #asnlog('[DBG] _path_ext({0!r}), {1}.{2}'\
    #       .format(ext, GLOBAL.COMP['NS']['mod'], GLOBAL.COMP['NS']['name']))
    #asnlog('    {0!r}'.format(GLOBAL.COMP['NS']['path']))

def _path_trunc(depth):
    assert( depth >= 0 )
    # truncate for the given depth the root and current path if different
    assert( len(GLOBAL.COMP['NS']['path'][0]) >= depth )
    del GLOBAL.COMP['NS']['path'][0][-depth:]
    if len(GLOBAL.COMP['NS']['path']) > 1:
        assert( len(GLOBAL.COMP['NS']['path'][-1]) >= depth )
        del GLOBAL.COMP['NS']['path'][-1][-depth:]
    #
    #asnlog('[DBG] _path_trunc({0!r}), {1}.{2}'\
    #       .format(depth, GLOBAL.COMP['NS']['mod'], GLOBAL.COMP['NS']['name']))
    #asnlog('    {0!r}'.format(GLOBAL.COMP['NS']['path']))

def _path_stack(new_path):
    GLOBAL.COMP['NS']['path'].append( new_path )
    #
    #asnlog('[DBG] _path_stack({0!r}), {1}.{2}'\
    #       .format(new_path, GLOBAL.COMP['NS']['mod'], GLOBAL.COMP['NS']['name']))
    #asnlog('    {0!r}'.format(GLOBAL.COMP['NS']['path']))

def _path_pop():
    assert( len(GLOBAL.COMP['NS']['path']) > 0 )
    #
    #asnlog('[DBG] _path_pop(), {0}.{1}'\
    #       .format(GLOBAL.COMP['NS']['mod'], GLOBAL.COMP['NS']['name']))
    #asnlog('    {0!r}'.format(GLOBAL.COMP['NS']['path']))
    #
    return GLOBAL.COMP['NS']['path'].pop()

def _path_root():
    return GLOBAL.COMP['NS']['path'][0]

def _path_cur():
    return GLOBAL.COMP['NS']['path'][-1]

def _path_all():
    return GLOBAL.COMP['NS']['path']

#///////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\#
#------------------------------------------------------------------------------#
# ASN1Obj, parent Python class to parse and compile any ASN.1 object
#------------------------------------------------------------------------------#
#\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\///////////////////////////////////////#

ASN1Obj_docstring = """
Attributes:

- name: str, the identifier of the object

- mode: str (MODE_*), the mode of the object after compilation.
    - MODE_TYPE : ASN.1 subtype or subclass
    - MODE_VALUE: ASN.1 value
    - MODE_SET  : ASN.1 set of values
    
- type: str (TYPE_*), the native ASN.1 type of the object.
    
- param: None or ASN1Dict, lists the formal parameters of the object.
    If defined, each item has the following format:
    {str (parameter name) : {'obj': None or ASN1Obj (parameter governor),
                             'ref': list of referrers}}
    Each referrer is the path from the root object to where the parameter has 
    to be set.

- tag: None or list, contains the explicit tagging of the ASN.1 type.
    If defined, it has the following format:
    [int (tag value),
     str (tag class, TAG_CONTEXT_SPEC / TAG_PRIVATE / TAG_APPLICATION / 
                     TAG_UNIVERSAL),
     str (tag mode,  TAG_IMPLICIT / TAG_EXPLICIT)]

- typeref: None or ASN1Ref, provides the subtype of the object in case it
    derives from another user-defined one (and not a native one).

- cont: type-dependent.

- root: None or list of str, provides the identifiers of the root content if 
    defined.

- ext: None or list of str, provides the identifiers of the extended content if
    defined.

- const: list of dict, lists all the constraints of the object; list is empty by
    default.
    Each constraint dict has the following format:
        {'text': str,
         'type': str,
         'keys': list of str, ... 
          $key from keys: depends of $type}

- val: None for MODE_TYPE,
       single_value (type-dependent) for MODE_VALUE,
       dict for MODE_SET.
    For set of values, the dict has the following format:
    {'root': list of single_value,
     'ext' : None or empty list or list of single_value}


Attributes required when defined as component of a constructed or CLASS type:

- parent: None or ASN1Obj, indicates the parent ASN.1 object container.

- flag: None or dict, lists the specific behavior of components.
    The following dict items can be set:
    - FLAG_OPT : None, means OPTIONAL when present
    - FLAG_DEF : int, provides a DEFAULT single_value when present
    - FLAG_UNIQ: None, means UNIQUE when present
    - FLAG_DEFBY: ASN1RefAnyDefBy, provides an identifier

- group: None or int, indicates the extension group index of components.


Attributes used during compilation and linking time:
    
- ref: list of ASN1Ref, lists all the references to other ASN.1 user-defined 
    ASN1Obj used in the object.
    It is used to track cross-references between objects.

- cache: dict, hosts the cached fully defined internal content of the objects.
    It is enabled through the class attribute _CACHE_ENABLED.
"""

ASN1SyntaxForm_docstring = """
ASN.1 definitions syntax format:

1) MODE_TYPE object:

# global object:
Name [param] ::= [tag] type [cont, ext] [const]
Name [param] ::= [tag] typeref [arg] [const]

# local object:
[name] [tag] type [cont, ext] [const] [flag]
[name] [tag] typeref [arg] [const] [flag]

# except within CLASS objects, for OPEN TYPE:
&Name [flag]

2) MODE_VALUE and MODE_SET object

# global object:
name [param] [tag] type [cont, ext] [const] ::= value or { set }
name [param] [tag] typeref [arg] [const] ::= value or { set }

# local MODE_VALUE object within CLASS object:
&name [tag] type [cont, ext] [const] [flag]
&name [tag] typeref [arg] [const] [flag]

# local MODE_SET object within CLASS object:
&Name [tag] type [cont, ext] [const] [flag]
&Name [tag] typeref [arg] [const] [flag]

3) When typeref is used to define an ASN.1 object,
the following attributes of typeref are "inherited":
- param
- tag, if not overriden by any local tag declared
- type
- cont / ext
- const, which are complemented by any other const in the refchain and locally 
  declared
"""

class ASN1Obj(object):
    __doc__ = """
    ASN1Obj is the parent class for all ASN.1 objects (type, value, set, class, 
    class_value, class_set, but also constructed types' components and 
    classes' fields, parameters, type-inclusion constraints, ...).
    
    It is also used as intermediate object during the compilation stage, when
    user-defined ASN.1 subtypes are by definition not known in advance.
    
    %s

    Additional attributes for SEQUENCE, SET and CLASS objects:
    - root_mand: list of str, lists all non-optional identifiers in the root 
        content
    - root_opt: list of str, lists all identifiers from the root content that
        are optional or have a default value
    
    Additional attributes for SEQUENCE and SET objects:
    - ext_ident: dict with identifier (str) : extended group index (int), for
        extended component
    - ext_group: dict with extended group index (int) : list of 
        identifiers (str), for extended component
    - cont_tags: dict with tag (int, str -tag class-): identifier
    
    Additional attribute for the CLASS object:
    - syntax: ASN1Dict with identifier (str) : 3-tuple 
        (pre-keyword, post-keyword, opt-group-id)
    
    %s
    """ % (ASN1Obj_docstring, ASN1SyntaxForm_docstring)
    
    # to cache internal structures
    # enable it only after the compilation stage has ended
    _CACHE_ENABLED = False
    
    # content parser dispatcher
    _PARSE_CONT_DISPATCH = {
        TYPE_INT     : '_parse_cont_int',
        TYPE_BIT_STR : '_parse_cont_int',
        TYPE_ENUM    : '_parse_cont_enum',
        TYPE_CHOICE  : '_parse_cont_choice',
        TYPE_SEQ_OF  : '_parse_cont_seqof',
        TYPE_SET_OF  : '_parse_cont_seqof',
        TYPE_SEQ     : '_parse_cont_seq',
        TYPE_SET     : '_parse_cont_seq',
        TYPE_CLASS   : '_parse_cont_class'
        }
    
    # value parser dispatcher
    _PARSE_VALUE_DISPATCH = {
        TYPE_NULL       : '_parse_value_null',
        TYPE_BOOL       : '_parse_value_bool',
        TYPE_INT        : '_parse_value_int',
        TYPE_REAL       : '_parse_value_real',
        TYPE_ENUM       : '_parse_value_enum',
        TYPE_BIT_STR    : '_parse_value_bitstr',
        TYPE_OCT_STR    : '_parse_value_octstr',
        TYPE_OID        : '_parse_value_oid',
        TYPE_REL_OID    : '_parse_value_oid',
        TYPE_STR_IA5    : '_parse_value_str',
        TYPE_STR_PRINT  : '_parse_value_str',
        TYPE_STR_NUM    : '_parse_value_str',
        TYPE_STR_VIS    : '_parse_value_str',
        TYPE_STR_BMP    : '_parse_value_str',
        TYPE_STR_UTF8   : '_parse_value_str',
        TYPE_STR_ISO646 : '_parse_value_str',
        TYPE_STR_TELE   : '_parse_value_str',
        TYPE_STR_VID    : '_parse_value_str',
        TYPE_STR_GRAPH  : '_parse_value_str',
        TYPE_STR_T61    : '_parse_value_str',
        TYPE_STR_GENE   : '_parse_value_str',
        TYPE_STR_UNIV   : '_parse_value_str_univ',
        TYPE_OBJ_DESC   : '_parse_value_str',
        TYPE_TIME_GEN   : '_parse_value_timegen',
        TYPE_TIME_UTC   : '_parse_value_timeutc',
        TYPE_CHOICE     : '_parse_value_choice',
        TYPE_SEQ        : '_parse_value_seq',
        TYPE_SEQ_OF     : '_parse_value_seqof',
        TYPE_SET        : '_parse_value_set',
        TYPE_SET_OF     : '_parse_value_seqof',
        TYPE_OPEN       : '_parse_value_open',
        TYPE_ANY        : '_parse_value_open',
        TYPE_EXT        : '_parse_value_seq',
        TYPE_EMB_PDV    : '_parse_value_seq',
        TYPE_CHAR_STR   : '_parse_value_seq',
        TYPE_CLASS      : '_parse_value_class',
        TYPE_TYPEIDENT  : '_parse_value_class',
        TYPE_ABSSYNT    : '_parse_value_class'
        }
    
    # lookup shortcuts for basic objects specific values
    _VALUE_BOOL = {'TRUE': True, 'FALSE': False}
    _VALUE_REAL = {'MINUS-INFINITY': (-1, None, None),
                   'PLUS-INFINITY' : ( 1, None, None),
                   'NOT-A-NUMBER'  : ( 0, None, None)}
    
    # ASN.1 types supporting the definition of range of values
    # WNG: for _String types, only ascii characters are supported
    _RANGE_TYPE_STR = (TYPE_STR_IA5, TYPE_STR_PRINT, TYPE_STR_VIS)
    _RANGE_TYPE     = (TYPE_INT, TYPE_REAL) + _RANGE_TYPE_STR
    
    
    # the following keywords are used to identify all ASN.1 object attributes
    KW = ('name', 'mode',
          'parnum', 'param',
          'tag', 'type', 'typeref',
          'cont', 'ext', 'parent',
          'const', 
          'val',
          'flag', 'group',
          'ref', 'msg'
          'cache')
        
    #--------------------------------------------------------------------------#
    # initialization and generation methods
    #--------------------------------------------------------------------------#
    
    def __init__(self, name='', mode=MODE_TYPE, type=None, parent=None):
        self._name      = name
        self._mode      = mode
        self._type      = type
        self._typeref   = None
        self._parent    = parent
        self.init_common_attr()
    
    def init_common_attr(self):
        # for all user-defined ASN.1 objects
        self._parnum    = None
        self._param     = None
        self._tag       = None
        self._cont      = None
        self._root      = None
        self._ext       = None
        self._const     = []
        self._val       = None
        # for ASN.1 objects included in constructed types
        self._flag      = None
        self._group     = None
        # for tracking references
        self._ref       = set()
        # for storing any transfer syntax
        self._msg       = None
        # for caching temporary results
        self._cache     = {}
    
    def init_cache(self):
        self._cache     = {}
    
    def _init_from_obj(self, Obj):
        # this is used by all ASN.1 objects defined at the end of this file
        # in order to initialize from an existing ASN1Obj instance
        if Obj is None:
            self._name          = ''
            self._mode          = MODE_TYPE
            self._type          = self.TYPE
            self._typeref       = None
            self.init_common_attr()
            self._parent        = None
            self._text_def      = ''
            if self.TYPE in (TYPE_CLASS, TYPE_TYPEIDENT, TYPE_ABSSYNT):
                self._syntax = None
        elif isinstance(Obj, ASN1Obj) and Obj._type == self.TYPE:
            self._name          = Obj._name
            self._mode          = Obj._mode
            self._typeref       = Obj._typeref
            self._parent        = None # this must be set manually after init
            # common attributes
            self._parnum        = Obj._parnum
            self._param         = Obj._param
            self._tag           = Obj._tag
            self._cont          = Obj._cont
            self._root          = Obj._root
            self._ext           = Obj._ext
            self._const         = Obj._const
            self._val           = Obj._val
            self._flag          = Obj._flag
            self._group         = Obj._group
            self._ref           = Obj._ref
            self._msg           = None
            self._cache         = {}
            if hasattr(Obj, '_root_mand') and hasattr(Obj, '_root_opt'):
                assert(Obj._type in (TYPE_SEQ, TYPE_SET, TYPE_CHOICE, TYPE_CLASS,
                       TYPE_REAL, TYPE_EXT, TYPE_EMB_PDV, TYPE_CHAR_STR))
                self._root_mand = Obj._root_mand
                self._root_opt  = Obj._root_opt
            if hasattr(Obj, '_ext_ident') and hasattr(Obj, '_ext_group'):
                assert(Obj._type in (TYPE_SEQ, TYPE_SET, TYPE_CHOICE, TYPE_REAL, 
                       TYPE_EXT, TYPE_EMB_PDV, TYPE_CHAR_STR))
                self._ext_ident = Obj._ext_ident
                self._ext_group = Obj._ext_group
            if hasattr(Obj, '_syntax'):
                assert(Obj._type in (TYPE_CLASS, TYPE_TYPEIDENT, TYPE_ABSSYNT))
                self._syntax    = Obj._syntax
            elif Obj._type in (TYPE_CLASS, TYPE_TYPEIDENT, TYPE_ABSSYNT):
                self._syntax    = None
            # textual definition
            self._text_def      = Obj._text_def
            if hasattr(self, '_text_decl'):
                self._text_decl = Obj._text_decl
        else:
            raise(ASN1ObjErr('{0}: invalid initializer'.format(self.TYPE)))
    
    def gen(self, **kwargs):
        for kw in self.KW:
            if kw in kwargs:
                setattr(self, '_%s' % kw, kwargs[kw])
        return self.resolve()
    
    #--------------------------------------------------------------------------#
    # user-friendly generic representation
    #--------------------------------------------------------------------------#
    
    def __repr__(self):
        if self._typeref is not None:
            if isinstance(self._typeref, (ASN1RefType, ASN1RefInstOf)):
                try:
                    typeref = self._typeref.called[1]
                except AttributeError:
                    # .called is ASN1RefParam
                    typeref = repr(self._typeref.called)
            elif isinstance(self._typeref, ASN1RefChoiceComp):
                try:
                    typeref = '%s<' % self._typeref.called[1] + \
                              '<'.join(self._typeref.ced_path)
                except AttributeError:
                    # .called is ASN1RefParam
                    typeref = '%s<' % repr(self._typeref.called) + \
                              '<'.join(self._typeref.ced_path)
            elif isinstance(self._typeref, ASN1RefClassField):
                try:
                    typeref = '%s.&' % self._typeref.called[1] + \
                              '.&'.join(self._typeref.ced_path)
                except AttributeError:
                    # .called is ASN1RefParam
                    typeref = '%s.&' % repr(self._typeref.called) + \
                              '.&'.join(self._typeref.ced_path)
            elif isinstance(self._typeref, ASN1RefClassIntern):
                typeref = '&%s' % '.&'.join(self._typeref.ced_path)
            elif isinstance(self._typeref, ASN1RefClassValField):
                try:
                    typeref = '%s.&%s' % (self._typeref.called[1],
                                          '.&'.join(self._typeref.ced_path))
                except AttributeError:
                    # .called is ASN1RefParam
                    typeref = '%s.&%s' % (repr(self._typeref.called),
                                          '.&'.join(self._typeref.ced_path))
            else:
                assert()
        else:
            typeref = None
        #
        if self._mode == MODE_TYPE:
            if typeref is not None:
                return '<%s ([%s] %s)>' % (self._name,
                                           typeref,
                                           self._type)
            else:
                return '<%s (%s)>' % (self._name,
                                      self._type)
        elif self._mode == MODE_VALUE:
            if self._val is not None:
                val = self._val
            else:
                val = ' '
            if typeref is not None:
                return '<%s ([%s] %s): %s>' % (self._name,
                                               typeref,
                                               self._type,
                                               val)
            else:
                return '<%s (%s): %s>' % (self._name,
                                          self._type,
                                          val)
        elif self._mode == MODE_SET:
            if self._val is not None:
                if self._val['ext'] is not None:
                    ext = ', ...'
                elif self._val['ext']:
                    ext = ', ..., %s' % repr(self._val['ext'])[1:-1]
                else:
                    ext = ''
                val = repr(self._val['root'])[1:-1] + ext
            else:
                val = ' '
            if typeref is not None:
                return '<%s ([%s] %s): %s>' % (self._name,
                                               typeref,
                                               self._type,
                                               val)
            else:
                return '<%s (%s): %s>' % (self._name,
                                          self._type,
                                          val)
    
    def __call__(self):
        return self._val
    
    #--------------------------------------------------------------------------#
    # type resolution and generation
    #--------------------------------------------------------------------------#
    
    def copy(self):
        # this is used to create a new ASN1Obj instance which has its internal
        # attributes bounded to the ones of self
        # WNG: this only works with definitive objects (which have a .TYPE 
        # attribute)
        # clone._parent is not bounded
        clone = self.__class__(self)
        clone._val = self._val
        return clone
    
    def get_typeref(self):
        """
        returns the ASN1Obj corresponding to the typeref of self,
        or None when self inherits directly from an ASN.1 native type
        """
        if self._typeref is None:
            return None
        elif self._CACHE_ENABLED and 'typeref' in self._cache:
            return self._cache['typeref']
        ref = self._typeref
        #
        #
        if isinstance(ref, ASN1RefType):
            assert( ref.ced_path == [] )
            if isinstance(ref.called, ASN1RefParam):
                tr = GLOBAL.COMP['NS']['par'][ref.called.name]['gov']
            else:
                try:
                    tr = get_asnobj(ref.called[0], ref.called[1])
                except ASN1Err as Err:
                    raise(ASN1ProcTextErr('{0}: {1}'\
                          .format(self.fullname(), Err)))
            if tr._type is None or tr._mode is None:
                # type or mode not yet compiled
                raise(ASN1ProcLinkErr('{0}: {1!r}'\
                      .format(self.fullname(), ref)))
        #
        #
        elif isinstance(ref, ASN1RefClassField):
            assert( len(ref.ced_path) >= 1 )
            if isinstance(ref.called, ASN1RefParam):
                cla = GLOBAL.COMP['NS']['par'][ref.called.name]['gov']
                if cla.get_cont() is None:
                    # this means the governor is solely a MODE_TYPE, TYPE_CLASS
                    # without defined content until parameterization
                    # hence, typeref resolution will only happen at parameterization
                    # WNG: here, we return only a "virtual" object 
                    tr = ASN1Obj(name='{0}.&{1}'.format(ref.called.name, '.&'.join(ref.ced_path)),
                                 type=TYPE_OPEN)
                    tr._text_def = ''
                    tr = tr.resolve()
                    return tr
            else:
                try:
                    cla = get_asnobj(ref.called[0], ref.called[1])
                except ASN1Err as Err:
                    raise(ASN1ProcTextErr('{0}: {1}'\
                          .format(self.fullname(), Err)))
            if cla._type is None or cla._mode is None:
                # type or mode not yet compiled
                raise(ASN1ProcLinkErr('{0}: {1!r}'\
                      .format(self.fullname(), ref)))
            elif cla._type not in (TYPE_CLASS, TYPE_TYPEIDENT, TYPE_ABSSYNT) \
            or cla._mode not in (MODE_TYPE, MODE_SET):
                raise(ASN1ProcTextErr('{0}: {1!r}, invalid object'\
                      .format(self.fullname(), ref)))
            # support chained field references:
            # e.g. MeLesCasse.&Un.&Gros.&Emmerdement
            classpath = ref.ced_path[:]
            cp_ok = [cla._name]
            while len(classpath) > 1:
                cla_cont = cla.get_cont()
                if cla_cont is None:
                    # cont not yet compiled
                    raise(ASN1ProcLinkErr('{0}: ASN1RefClassField into {1}'\
                          .format(self.fullname(), '.&'.join(cp_ok))))
                cp_ok.append(classpath[0])
                try:
                    tr = cla_cont[classpath[0]]
                except KeyError:
                    raise(ASN1ProcTextErr('{0}: ASN1RefClassField into {1}, undefined'\
                          .format(self.fullname(), '.&'.join(cp_ok))))
                if tr._typeref is None:
                    # CLASS locally defined within CLASS
                    cla = tr
                else:
                    try:
                        cla = tr.get_typeref()
                    except ASN1ProcLinkErr as LinkErr:
                        # enrich the linking error with local info
                        LinkErr.args = ('{0}: {1}'.format(self.fullname(), LinkErr.args[0]), )
                        raise(LinkErr)
                    except ASN1Err as Err:
                        # enrich any other error with local info
                        Err.args = ('{0}: {1}'.format(self.fullname(), Err.args[0]), )
                        raise(Err)
                del classpath[0]
                if cla._type is None or cla._mode is None:
                    # type or mode not yet compiled
                    raise(ASN1ProcLinkErr('{0}: ASN1RefClassField into {1}'\
                          .format(self.fullname(), '.&'.join(cp_ok))))
                elif cla._type not in (TYPE_CLASS, TYPE_TYPEIDENT, TYPE_ABSSYNT) \
                or cla._mode not in (MODE_TYPE, MODE_SET):
                    raise(ASN1ProcTextErr('{0}: ASN1RefClassField into {1}, invalid object'\
                          .format(self.fullname(), '.&'.join(cp_ok))))
            cla_cont = cla.get_cont()
            if cla_cont is None:
                # cont not yet compiled
                raise(ASN1ProcLinkErr('{0}: ASN1RefClassField into {1}'\
                      .format(self.fullname(), '.&'.join(cp_ok))))
            cp_ok.append(classpath[0])
            try:
                tr = cla_cont[classpath[0]]
            except KeyError:
                raise(ASN1ProcTextErr('{0}: {1!r} undefined'\
                      .format(self.fullname(), ref)))
        #
        #
        elif isinstance(ref, ASN1RefClassIntern):
            assert( self._parent is not None and self._parent._type == TYPE_CLASS )
            assert( len(ref.ced_path) >= 1 )
            cla = self._parent
            classpath = ref.ced_path[:]
            cp_ok = [cla._name]
            while len(classpath) > 1:
                cla_cont = cla.get_cont()
                if cla_cont is None:
                    # cont not yet compiled
                    raise(ASN1ProcLinkErr('{0}: ASN1RefClassIntern into {1}'\
                          .format(self.fullname(), '.&'.join(cp_ok))))
                cp_ok.append(classpath[0])
                try:
                    tr = cla_cont[classpath[0]]
                except KeyError:
                    raise(ASN1ProcTextErr('{0}: ASN1RefClassIntern into {1}, undefined'\
                          .format(self.fullname(), '.&'.join(cp_ok))))
                if tr._typeref is None:
                    # CLASS locally defined within CLASS
                    cla = tr
                else:
                    try:
                        cla = tr.get_typeref()
                    except ASN1ProcLinkErr as LinkErr:
                        # enrich the linking error with local info
                        LinkErr.args = ('{0}: {1}'.format(self.fullname(), LinkErr.args[0]), )
                        raise(LinkErr)
                    except ASN1Err as Err:
                        # enrich any other error with local info
                        Err.args = ('{0}: {1}'.format(self.fullname(), Err.args[0]), )
                        raise(Err)
                del classpath[0]
                if cla._type is None or cla._mode is None:
                    # type or mode not yet compiled
                    raise(ASN1ProcLinkErr('{0}: ASN1RefClassIntern into {1}'\
                          .format(self.fullname(), '.&'.join(cp_ok))))
                elif cla._type != TYPE_CLASS or cla._mode not in (MODE_TYPE, MODE_SET):
                    raise(ASN1ProcTextErr('{0}: ASN1RefClassIntern into {1}, invalid object'\
                          .format(self.fullname(), '.&'.join(cp_ok))))
            cla_cont = cla.get_cont()
            if cla_cont is None:
                # cont not yet compiled
                raise(ASN1ProcLinkErr('{0}: ASN1RefClassIntern into {1}'\
                      .format(self.fullname(), '.&'.join(cp_ok))))
            cp_ok.append(classpath[0])
            try:
                tr = cla_cont[classpath[0]]
            except KeyError:
                raise(ASN1ProcTextErr('{0}: {1!r} undefined'\
                      .format(self.fullname(), ref)))
        #
        #
        elif isinstance(ref, ASN1RefClassValField):
            assert( len(ref.ced_path) >= 1 )
            if isinstance(ref.called, ASN1RefParam):
                # this means the governor is MODE_VALUE, TYPE_CLASS
                # without defined value until parameterization
                # hence, typeref resolution will only happen during parameterization
                tr = ASN1Obj(name='{0}.&{1}'.format(ref.called.name, '.&'.join(ref.ced_path)),
                             type=TYPE_OPEN)
                return tr
            else:    
                try:
                    cla = get_asnobj(ref.called[0], ref.called[1])
                except ASN1Err as Err:
                    raise(ASN1ProcTextErr('{0}: {1}'\
                          .format(self.fullname(), Err)))
            if cla._type is None or cla._mode is None or cla._val is None:
                # type or mode or value not yet compiled
                raise(ASN1ProcLinkErr('{0}: {1!r}'\
                      .format(self.fullname(), ref)))
            elif cla._type not in (TYPE_CLASS, TYPE_TYPEIDENT, TYPE_ABSSYNT) \
            or cla._mode != MODE_VALUE:
                raise(ASN1ProcTextErr('{0}: {1!r}, invalid object'\
                      .format(self.fullname(), ref)))
            claval = cla._val
            # support chained field references:
            # e.g. meLesCasse.&un.&gros.&Emmerdement
            classpath = ref.ced_path[:]
            cp_ok = [cla._name]
            while len(classpath) > 0:
                cp_ok.append(classpath[0])
                try:
                    claval = claval[classpath[0]]
                except KeyError:
                    raise(ASN1ProcTextErr('{0}: ASN1RefClassValField into {1}, undefined'\
                          .format(self.fullname(), '.&'.join(cp_ok))))
                del classpath[0]
            tr = claval
            if not isinstance(tr, ASN1Obj):
                raise(ASN1ProcTextErr('{0}: {1!r}, invalid object'\
                      .format(self.fullname(), ref)))
        #
        #
        elif isinstance(ref, ASN1RefChoiceComp):
            assert( len(ref.ced_path) >= 1 )
            if isinstance(ref.called, ASN1RefParam):
                cho = GLOBAL.COMP['NS']['par'][ref.called.name]['gov']
            else: 
                try:
                    cho = get_asnobj(ref.called[0], ref.called[1])
                except ASN1Err as Err:
                    raise(ASN1ProcTextErr('{0}: {1}'\
                          .format(self.fullname(), Err)))
            if cho._type is None or cho._mode is None:
                # type or mode not yet compiled
                raise(ASN1ProcLinkErr('{0}: {1!r}'\
                      .format(self.fullname(), ref))) 
            elif cho._type != TYPE_CHOICE or cho._mode not in (MODE_TYPE, MODE_SET):
                raise(ASN1ProcTextErr('{0}: {1!r}, invalid object'\
                      .format(self.fullname(), ref)))
            # support chained CHOICE references:
            # e.g. emmerdement < gros < un < CasseLesBonbons
            choicepath = ref.ced_path[:]
            cp_ok = [cho._name]
            while len(choicepath) > 1:
                cho_cont = cho.get_cont()
                if cho_cont is None:
                    # cont not yet compiled
                    raise(ASN1ProcLinkErr('{0}: ASN1RefChoiceComp into {1}'\
                          .format(self.fullname(), '<'.join(cp_ok))))
                cp_ok.append(choicepath[0])
                try:
                    tr = cho_cont[choicepath[0]]
                except KeyError:
                    raise(ASN1ProcTextErr('{0}: ASN1RefChoiceComp into {1}, undefined'\
                          .format(self.fullname(), '<'.join(cp_ok))))
                if tr._typeref is None:
                    # CHOICE locally defined within CHOICE
                    cho = tr
                else:
                    try:
                        cho = tr.get_typeref()
                    except ASN1ProcLinkErr as LinkErr:
                        # enrich the linking error with local info
                        LinkErr.args = ('{0}: {1}'.format(self.fullname(), LinkErr.args[0]), )
                        raise(LinkErr)
                    except ASN1Err as Err:
                        # enrich any other error with local info
                        Err.args = ('{0}: {1}'.format(self.fullname(), Err.args[0]), )
                        raise(Err)
                del choicepath[0]
                if cho._type is None or cho._mode is None:
                    # type or mode not yet compiled
                    raise(ASN1ProcLinkErr('{0}: ASN1RefChoiceComp into {1}'\
                          .format(self.fullname(), '<'.join(cp_ok))))
                elif cho._type != TYPE_CHOICE or cho._mode not in (MODE_TYPE, MODE_SET):
                    raise(ASN1ProcTextErr('{0}: ASN1RefChoiceComp into {1}, invalid object'\
                          .format(self.fullname(), '<'.join(cp_ok))))
            cho_cont = cho.get_cont()
            if cho_cont is None:
                # cont not yet compiled
                raise(ASN1ProcLinkErr('{0}: ASN1RefChoiceComp into {1}'\
                      .format(self.fullname(), '<'.join(cp_ok))))
            cp_ok.append(choicepath[0])
            try:
                tr = cho_cont[choicepath[0]]
            except KeyError:
                raise(ASN1ProcTextErr('{0}: {1!r}, undefined'\
                      .format(self.fullname(), ' < '.join(cp_ok))))
        #
        #
        elif isinstance(ref, ASN1RefInstOf):
            # we need to get the special TYPE-IDENTIFIER (sub)class referenced within _typeref
            # and build a SEQUENCE from it
            try:
                tid = get_asnobj(ref.called[0], ref.called[1])
            except ASN1Err as Err:
                raise(ASN1ProcTextErr('{0}: {1}'.format(self.fullname(), Err)))
            seq = ASN1Obj(name=self._name, mode=MODE_TYPE, type=TYPE_SEQ)
            seq._text_def = self._text_def
            seq._cont = ASN1Dict()
            seq._cont['type-id'] = ASN1Obj(name='type-id', mode=MODE_TYPE)
            seq._cont['type-id']._text_def = ''
            seq._cont['type-id']._typeref = ASN1RefClassField(called=ref.called, ced_path=['id'])
            seq._cont['type-id'] = seq._cont['type-id'].resolve()
            seq._cont['value'] = ASN1Obj(name='value', mode=MODE_TYPE)
            seq._cont['value']._text_def = ''
            seq._cont['value']._typeref = ASN1RefClassField(called=ref.called, ced_path=['Type'])
            seq._cont['value']._tag = [0, TAG_CONTEXT_SPEC, TAG_EXPLICIT]
            seq._cont['value'] = seq._cont['value'].resolve()
            tr = seq.resolve()
        #
        # 
        # in case typeref has formal parameters not yet compiled
        # just raise
        if tr._parnum and tr._param is None:
            raise(ASN1ProcLinkErr('{0}: typeref {1} need to be compiled'\
                  .format(self.fullname(), tr._name)))
        self._cache['typeref'] = tr
        return tr
    
    def get_refchain(self):
        """
        returns the list of ASN1Obj instance(s) leading to the ultimate 
        user-defined object which inherits directly form a native ASN.1 type
        """
        if self._typeref is None:
            return []
        elif self._CACHE_ENABLED and 'refchain' in self._cache:
            return self._cache['refchain']
        #
        # 1) initialize the iterative process
        refchain = [self.get_typeref()]
        if self.fullname() == refchain[0].fullname():
            raise(ASN1ProcTextErr('{0}: self type reference'\
                  .format(self.fullname())))
        #
        # 2) iterate until we find the utlimate object with a native type
        while refchain[-1]._typeref is not None:
            refchain.append( refchain[-1].get_typeref() )
            if refchain[-1] in refchain[:-1]:
                raise(ASN1ProcTextErr('{0}: circular type reference, {1}'\
                      .format(self.fullname(),
                              [obj.fullname() for obj in refchain])))
        #
        if refchain[-1]._type is None:
            raise(ASN1ProcTextErr('{0}: no native type defined for {1}'\
                  .format(self.fullname(), refchain[-1].fullname())))
        #
        self._cache['refchain'] = refchain
        return refchain
    
    def resolve(self):
        """
        returns a new instance of self using the fully defined Python class
        (including TYPE and TAG attributes)
        """
        assert( self._type or self._typeref )
        if self._type is None:
            # if subtype of a user-defined type, get the refchain and the ASN.1
            # native type of the ultimate user-defined type
            refchain = self.get_refchain()
            native = refchain[-1]
            self._type = native._type
        New = ASN1ObjLUT[self._type](self)
        #
        # update self._parent if exists
        if self._parent is not None:
            New._parent = self._parent
        #
        # update the parent of objects in the content, if needed
        if New.TYPE in (TYPE_SEQ_OF, TYPE_SET_OF):
            if New._cont:
                if New._cont._parent == self:
                    # WNG: in certain cases of parameterization,
                    # this is not always true
                    New._cont._parent = New
                # and in case the component has a CONTAINING constraint
                # it needs to be updated too
                for const in New._cont._const:
                    if const['type'] == CONST_CONTAINING:
                        if const['obj']._parent == self:
                            const['obj']._parent = New
        elif New.TYPE in (TYPE_CHOICE, TYPE_SEQ, TYPE_SET, TYPE_CLASS):
            if New._cont:
                for Comp in New._cont.values():
                    if Comp._parent == self:
                        # WNG: in certain cases of parameterization,
                        # this is not always true
                        Comp._parent = New
                    # and in case components have a CONTAINING constraint
                    # it needs to be updated too
                    for const in Comp._const:
                        if const['type'] == CONST_CONTAINING:
                            if const['obj']._parent == self:
                                const['obj']._parent = New
        #
        return New
    
    def get_classref(self):
        """
        returns the ASN1Obj corresponding to the (parent) CLASS object 
        referenced by self in case its typeref is ASN1RefClassField, 
        ASN1RefClassIntern, ASN1RefClassValField or ASN1RefType to a CLASS,
        None otherwise 
        """
        if self._typeref is None:
            return None
        elif self._CACHE_ENABLED and 'classref' in self._cache:
            return self._cache['classref']
        #
        # get_classref() will always happen after get_typeref()
        # there is no need to rerun all the checks 
        ref = self._typeref
        #
        if isinstance(ref, ASN1RefType):
            tr = self.get_typeref()
            if tr._type in (TYPE_CLASS, TYPE_TYPEIDENT, TYPE_ABSSYNT):
                cr = tr
            else:
                cr = None
        elif isinstance(ref, (ASN1RefClassField, ASN1RefClassValField)):
            if isinstance(ref.called, ASN1RefParam):
                cr = self.get_param()[ref.called.name]['gov']
            else:     
                cr = get_asnobj(ref.called[0], ref.called[1])
        elif isinstance(self._typeref, ASN1RefClassIntern):
            cr = self._parent
        else:
            cr = None
        #
        self._cache['classref'] = cr
        return cr
    
    def _verif_typeref(self):
        # check if the typeref is compiled, otherwise raise() a link error
        tr = self.get_typeref()
        if tr is not None and not hasattr(tr, 'TYPE'):
            raise(ASN1ProcLinkErr('{0}: typeref not yet compiled'\
                  .format(self.fullname())))
    
    #--------------------------------------------------------------------------#
    # methods for emulating a dictionnary
    #--------------------------------------------------------------------------#
    # this enables to reference path within ASN.1 objects in the form of 
    # list of str or int; e.g. path = ['cont', 'choiceAlternative'] 
    
    def __getitem__(self, kw):
        #if kw in self.KW_TR:
        #    return getattr(self, 'get_%s' % kw)()
        #elif kw in self.KW:
        if kw in self.KW:
            return getattr(self, '_%s' % kw)
        else:
            return object.__getitem__(self, kw)
    
    # select_set() should be preferred over __setitem__()
    def __setitem__(self, kw, arg):
        if kw in self.KW:
            return setattr(self, '_%s' % kw, arg)
        else:
            return object.__setitem__(self, kw, arg)
    
    def select(self, path=[]):
        """
        returns the value of an attribute of self, by selecting its path
        """
        # this method is similar to _get_path_last_obj()
        if not path:
            return self
        else:
            obj = self
            path_ok = []
            for p in path:
                try:
                    obj = obj[p]
                except Exception as err:
                    raise(ASN1ObjErr('{0}: invalid path {1}, after {2}'\
                          .format(self.fullname(), path, path_ok)))
                else:
                    path_ok.append(p) 
            return obj
    
    def select_set(self, path=[], val=None):
        """
        sets a value to an attribute of self, by selecting its path
        
        WNG: in case the path leads to an attribute of a typeref, this is the
        typeref object that will be updated
        """
        if not path:
            return
        # select path elements until the last one
        obj = self.select( path[:-1] )
        try:
            if isinstance(obj, list) and path[-1] == len(obj):
                # appending a new element to an existing list
                obj.append(val)
            else:
                obj[path[-1]] = val
        except Exception as err:
            raise(ASN1ObjErr('{0}: invalid path {1}, last element'\
                  .format(self.fullname(), path)))
    
    # methods for transferring from / to a dictionnary 
    def get_internals(self):
        """
        returns a dictionnary containing all attributes' value of self 
        """
        ASN1ObjDict = {}
        for kw in self.KW:
            ASN1ObjDict[kw] = getattr(self, '_%s' % kw)
        return ASN1ObjDict
    
    def set_internals(self, ASN1ObjDict):
        """
        sets attributes' value(s) of self from a dictionnary
        """
        for kw in self.KW:
            try:
                setattr(self, '_%s' % kw, ASN1ObjDict[kw])
            except KeyError:
                pass
    
    #--------------------------------------------------------------------------#
    # methods for accessing internal attributes
    #--------------------------------------------------------------------------#
    
    def fullname(self):
        """
        returns the full name of self, including parent's name when self is a 
        component of a constructed type or a field of a CLASS type
        """
        if self._parent is None:
            return self._name
        elif self._CACHE_ENABLED and 'fullname' in self._cache:
            return self._cache['fullname']
        else:
            fn = '%s.%s' % (self._parent.fullname(), self._name)
            self._cache['fullname'] = fn
            return fn
    
    def get_parent_root(self):
        """
        returns the root parent (ASN1Obj) of self when it is a component of a 
        constructed type or a field of a CLASS type
        """
        # returns the ultimate parent of the ASN1Obj
        if self._parent is None:
            return self
        elif self._CACHE_ENABLED and 'parent_root' in self._cache:
            return self._cache['parent_root']
        Obj = self._parent
        while Obj is not None:
            parent = Obj._parent
            if parent is None:
                self._cache['parent_root'] = Obj
                return Obj
            else:
                Obj = parent
    
    def get_parent_path(self):
        """
        returns a list with the selection path from the root parent to self
        """
        # returns the selection path from the parent root to the ASN1Obj
        if self._CACHE_ENABLED and 'parent_path' in self._cache:
            return self._cache['parent_path']
        path = []
        son = self
        parent = son._parent
        while parent:
            if parent._type in (TYPE_SEQ_OF, TYPE_SET_OF):
                path.append( 'cont' )
            else:
                path.extend( [son._name, 'cont'] )
            son = parent
            parent = son._parent
        path.reverse()
        self._cache['parent_path'] = path
        return path
    
    def get_param(self):
        """
        returns the ASN1Dict with the formal parameters associated to self, or 
        None when the type is not parameterized
        """
        # in case of component / field of a constructed objects, parameters are
        # those of the root parent
        if self._parent is None:
            return self._param
        elif self._CACHE_ENABLED and 'param' in self._cache:
            return self._cache['param']
        else:
            p = self.get_parent_root()._param
            self._cache['param'] = p
            return p
    
    def get_tag(self):
        """
        returns the nearest specific tag (not universal) of self
        """
        if self._tag is not None:
            # 1) get local tag in priority, if exists
            return self._tag
        elif self._CACHE_ENABLED and 'tag' in self._cache:
            return self._cache['tag']
        else:
            # 2) or inherited tag if exists
            tr = self.get_typeref()
            if tr is None:
                tag = None
            else:
                self._verif_typeref()
                # 3) get the tag from typeref
                tag = tr.get_tag()
            self._cache['tag'] = tag
            return tag
    
    def get_tag_univ(self):
        """
        returns the UNIVERSAL tag of self
        """
        if self.TAG is None:
            return None
        else:
            return [self.TAG, TAG_UNIVERSAL, TAG_IMPLICIT]
    
    def get_tag_chain(self):
        """
        returns the list of tags of self, up to the UNIVERSAL one
        """
        raise(ASN1NotSuppErr())
    
    def get_cont(self, wext=False):
        """
        returns the content of self
        """
        if self._cont is not None:
            # 1) get local content if exists
            if wext:
                return self._cont, self._ext
            else:
                return self._cont
        #
        elif self._CACHE_ENABLED:
            # 2) get cached content if already set
            if wext and 'cont' in self._cache and 'ext' in self._cache:
                return self._cache['cont'], self._cache['ext']
            elif 'cont' in self._cache:
                return self._cache['cont']
        #
        # 3) or inherited content if exists
        tr = self.get_typeref()
        if tr is None:
            cont = None
        else:
            self._verif_typeref()
            # 3) get the content from typeref
            if wext:
                cont, ext = tr.get_cont(wext)
                self._cache['cont'] = cont
                self._cache['ext']  = ext
            else:
                cont = tr.get_cont(wext)
                self._cache['cont'] = cont
        if wext:
            return cont, ext
        else:
            return cont
    
    def get_cont_tags(self):
        """
        returns the list of tuple(tag, ident) for components within the content of self
        except for CHOICE, returns the ASN1Dict of ident: tag
        """
        if self._type not in (TYPE_CHOICE, TYPE_SEQ, TYPE_SET, TYPE_REAL, 
        TYPE_EXT, TYPE_EMB_PDV, TYPE_CHAR_STR):
            return None
        elif self._CACHE_ENABLED and 'cont_tags' in self._cache:
            return self._cache['cont_tags']
        else:
            cont_tags = []
            for ident, Comp in self.get_cont().items():
                tag = None
                # check the local tag
                if Comp._tag:
                    tag = Comp._tag
                    cont_tags.append( (tuple(tag[0:2]), ident) )
                else:
                    # check into the chain of type reference if one of it has
                    # a specific tag
                    refchain, ok = Comp.get_refchain(), False
                    for tr in refchain:
                        if tr._tag:
                            tag = tr._tag
                            cont_tags.append( (tuple(tag[0:2]), ident) )
                            ok = True
                            break
                    if not ok:
                        # get the universal tag
                        tag = Comp.get_tag_univ()
                    #
                    if tag is None:
                        assert( Comp._type in (TYPE_CHOICE, TYPE_OPEN, TYPE_ANY) )
                        if Comp._type == TYPE_CHOICE:
                            # need to check the tags of the content of CHOICE
                            # WNG, this is an ASN1Dict
                            Comp_tags = Comp.get_cont_tags()
                            for t in Comp_tags.keys():
                                cont_tags.append( (t[0:2], tuple([ident] + list(Comp_tags[t]))) )
                    elif not ok:
                        cont_tags.append( (tuple(tag[0:2]), ident) )
            #
            if self._type == TYPE_CHOICE:
                # sudo make me an ASN1Dict !
                choice_cont_tags = ASN1Dict(cont_tags)
                if len(choice_cont_tags) < len(cont_tags):
                    raise(ASN1ProcTextErr('{0}: duplicate tags within CHOICE content'\
                          .format(self.fullname())))
                cont_tags = choice_cont_tags
            self._cache['cont_tags'] = cont_tags
            return cont_tags   
    
    def get_root(self):
        """
        returns the list of identifiers in the root part of the content of self
        """
        if self._root is not None:
            # 1) get local root content if exists
            return self._root
        elif self._CACHE_ENABLED and 'root' in self._cache:
            return self._cache['root']
        else:
            # 2) or inherited root content if exists
            tr = self.get_typeref()
            if tr is None:
                root = None
            else:
                self._verif_typeref()
                # 3) get the root content from typeref
                root = tr.get_root()
            self._cache['root'] = root
            return root
    
    def get_root_mand(self):
        """
        returns the list of mandatory identifiers in the root part of the 
        content of self
        """
        if hasattr(self, '_root_mand'):
            # 1) get local root content if exists
            return self._root_mand
        elif self._CACHE_ENABLED and 'root_mand' in self._cache:
            return self._cache['root_mand']
        else:
            # 2) or inherited root content if exists
            tr = self.get_typeref()
            if tr is None:
                root_mand = None
            else:
                self._verif_typeref()
                # 3) get the mandatory root content from typeref
                root_mand = tr.get_root_mand()
            self._cache['root_mand'] = root_mand
            return root_mand
    
    def get_root_opt(self):
        """
        returns the list of optional identifiers in the root part of the content 
        of self
        """
        if hasattr(self, '_root_opt'):
            # 1) get local root content if exists
            return self._root_opt
        elif self._CACHE_ENABLED and 'root_opt' in self._cache:
            return self._cache['root_opt']
        else:
            # 2) or inherited root content if exists
            tr = self.get_typeref()
            if tr is None:
                root_opt = None
            else:
                self._verif_typeref()
                # 3) get the optional root content from typeref
                root_opt = tr.get_root_opt()
            self._cache['root_opt'] = root_opt
            return root_opt
    
    def get_ext(self):
        """
        returns the list of identifiers of the extended part of the content of 
        self
        """
        if self._ext is not None:
            # 1) get local extended content if exists
            return self._ext
        elif self._CACHE_ENABLED and 'ext' in self._cache:
            return self._cache['ext']
        else:
            # 2) or inherited extended content if exists
            tr = self.get_typeref()
            if tr is None:
                ext = None
            else:
                self._verif_typeref()
                # 3) get the extended content from typeref
                ext = tr.get_ext()
            self._cache['ext'] = ext
            return ext
    
    def get_ext_ident(self):
        """
        returns the dict of extended identifiers and associated optional group
        for the content of self
        """
        if hasattr(self, '_ext_ident'):
            return self._ext_ident
        elif self._CACHE_ENABLED and 'ext_ident' in self._cache:
            return self._cache['ext_ident']
        else:
            tr = self.get_typeref()
            if tr is None:
                ei = None
            else:
                self._verif_typeref()
                ei = tr.get_ext_ident()
            self._cache['ext_ident'] = ei
            return ei
    
    def get_ext_group(self):
        """
        returns the dict of optional group and associated extended identifiers
        for the content of self
        """
        if hasattr(self, '_ext_group'):
            return self._ext_group
        elif self._CACHE_ENABLED and 'ext_group' in self._cache:
            return self._cache['ext_group']
        else:
            tr = self.get_typeref()
            if tr is None:
                eg = None
            else:
                self._verif_typeref()
                eg = tr.get_ext_group()
            self._cache['ext_group'] = eg
            return eg
    
    def get_const(self):
        """
        returns the list of constraints applied to self
        """
        if self._CACHE_ENABLED and 'const' in self._cache:
            return self._cache['const']
        # build a list of constraints:
        const = []
        tr = self.get_typeref()
        # 1) add local constraints
        if self._const:
            const.extend(self._const)
        # 2) add inherited constraints, without their extended part,
        # only from non-parameterized objects
        # (because constraints are duplicated from parameterized objects)
        if tr is not None and tr.get_param() is None:
            self._verif_typeref()
            for c in tr.get_const():
                # remove extension from a copy of the constraint
                if 'ext' in c and c['ext']:
                    c = dict(c)
                    # TODO: ensure the alternative below is correct
                    # keep it extensible
                    c['ext'] = []
                    # remove entirely its extensibility
                    #c['ext'] = None
                const.append(c)
        self._cache['const'] = const
        return const
    
    def get_syntax(self):
        """
        returns the syntax ASN1Dict for CLASS ASN.1 object
        """
        if not hasattr(self, '_syntax'):
            return None
        elif self._syntax is not None:
            return self._syntax
        elif self._CACHE_ENABLED and 'syntax' in self._cache:
            return self._cache['syntax']
        else:
            tr = self.get_typeref()
            if tr is None:
                synt = None
            else:
                self._verif_typeref()
                synt = tr.get_syntax()
            self._cache['syntax'] = synt
            return synt
    
    def get_val(self):
        """
        returns the single value or ASN1Dict with the set of values of self
        """
        if self._val is not None:
            return self._val
        elif self._CACHE_ENABLED and 'val' in self._cache:
            return self._cache['val']
        else:
            tr = self.get_typeref()
            if tr is None:
                val = None
            else:
                self._verif_typeref()
                val = tr.get_val()
            self._cache['val'] = val
            return val      
    
    # methods specific to constructed components or CLASS fields
    def is_opt(self):
        if self._flag is not None:
            return FLAG_OPT in self._flag or FLAG_DEF in self._flag
        else:
            return False
    
    # method to test the compliance of constructed or CLASS objects' values
    def is_value_ok(self, value):
        if self._type in (TYPE_SEQ, TYPE_SET):
            # ensure all mandatory root components are in val
            if not all([ident in value for ident in self.get_root_mand()]):
                return False
            # ensure grouped extension are all presents when at least 1 is 
            # in value
            if any([ident in self.get_ext_ident() for ident in value]):
                for gid in self.get_ext_group():
                    idents = self.get_ext_group()[gid]
                    ok = [ident in value for ident in idents]
                    if any(ok) and not all(ok):
                        return False
        elif self._type == TYPE_CLASS:
            # ensure all mandatory root components are in val
            if not all([ident in value for ident in self.get_root_mand()]):
                return False
        return True
    
    #--------------------------------------------------------------------------#
    # ASN.1 syntactic parser for formal parameters
    #--------------------------------------------------------------------------#
    
    def parse_param(self, text):
        """
        parses the text corresponding to formal parameters within "{" and "}" 
        
        sets self._param with an ASN1Dict containing formal parameters:
            parameter_name (str): {'obj': parameter_governor (ASN1Obj or None),
                                   'ref': list of referrers (list of pathes)} 
        
        returns the rest of the text
        """
        # 1) extract the textual definitions of parameters
        rest, params = extract_multi(text)
        if params is None:
            self._param = None
            return rest
        if not params:
            raise(ASN1ProcTextErr('{0}: empty formal parameters'\
                  .format(self.fullname())))
        #
        self._param = ASN1Dict()
        GLOBAL.COMP['NS']['par'] = self._param
        for param in params:
            #
            # parse each formal parameter: split the 2 parts, name and governor
            offset = search_top_lvl_sep(param, ':')
            if not offset:
                #
                # 2.1) no param_governor, param_name alone (-> type for an open-type)
                m = match_typeref(param)
                if not m:
                    raise(ASN1ProcTextErr('{0}: invalid formal parameter, {1}'\
                          .format(self._name, param)))
                name = m.group(1)
                #
                # 2.2) create an empty / open object
                if name.isupper():
                    # CLASS object, with undefined content
                    Gov = ASN1Obj(name=name, type=TYPE_CLASS, mode=MODE_TYPE)
                else:
                    # OPEN type
                    Gov = ASN1Obj(name=name, type=TYPE_OPEN, mode=MODE_TYPE)
                Gov._text_def  = ''
                if param[m.end():]:
                    raise(ASN1ProcTextErr('{0}: invalid formal parameter, {1}'\
                          .format(self._name, param)))
            #
            elif len(offset) == 1:
                #
                # 3.1) param_governor : param_name (lo-case -> val, up-case -> set)
                text_gov, text_name = param[:offset[0]].strip(), \
                                      param[offset[0]+1:].strip()
                m = re.match(_RE_WORD, text_name)
                if not m:
                    raise(ASN1ProcTextErr('{0}: invalid formal parameter name, {1}'\
                          .format(self._name, text_name)))
                #
                # 3.2) parse the object definition
                Gov = ASN1Obj(name=m.group())
                if Gov._name[0].isupper():
                    Gov._mode = MODE_SET
                else:
                    Gov._mode = MODE_VALUE
                Gov._text_def = text_gov
                #
                if text_name[m.end():]:
                    raise(ASN1ProcTextErr('{0}: invalid formal parameter name, {1}'\
                          .format(self._name, text_name)))
                #
                _path_ext([Gov._name, 'gov'])
                _path_stack([])
                try:
                    text_gov = Gov.parse_def(text_gov)
                except ASN1Err as Err:
                    # enrich the exception that can happen when parsing the governor
                    # definition, with the fullname of self
                    Err.args = ('{0}: {1}'.format(self.fullname(), Err.args[0]), )
                    raise(Err)
                _path_pop()
                _path_trunc(2)
                #
                if text_gov:
                    raise(ASN1ProcTextErr('{0}, governor {1}: remaining textual definition, {2}'\
                          .format(self._name, Gov._name, text_gov)))
                #
                # 3.3) keep track of references made by governor in self
                if Gov._ref:
                    self._ref.update( Gov._ref )
            else:
                raise(ASN1ProcTextErr('{0}: invalid formal parameter, {1}'\
                      .format(self._name, param)))
            #
            if Gov._name in self._param:
                raise(ASN1ProcTextErr('{0}: duplicated formal parameter name, {1}'\
                      .format(self._name, Gov._name)))
            self._param[Gov._name] = {'gov': Gov.resolve(), 'ref': []}
        #
        # the GLOBAL namespace is updated in proc.asnobj_compile()
        return rest
    
    #--------------------------------------------------------------------------#
    # ASN.1 syntactic parser for object definition
    # parses: tag, type, content and constraints
    #--------------------------------------------------------------------------#
    
    def parse_def(self, text):
        """
        parses the text corresponding to the ASN.1 object definition
        
        sets:
        - self._tag
        - self._type and / or self._typeref
        - self._cont for native INTEGER, BIT STRING, ENUMERATED, 
        constructed and CLASS (also self._root and self._ext), or
        - self._const
        
        returns the rest of the text
        """
        text = self._parse_tag(text)
        text = self._parse_type(text)
        if text:
            text = self._parse_cont(text)
        #
        if self._type == TYPE_CLASS:
            if text:
                # extract SYNTAX content
                text = self._parse_class_syntax(text)
            else:
                self._syntax = None
        else:
            while text[0:1] == '(':
                # constraint
                rest = self._parse_const(text)
                if text == rest:
                    raise(ASN1ProcTextErr('{0}: missing closing parenthesis, {1}'\
                          .format(self.fullname(), text)))
                text = rest
        return text
    
    #--------------------------------------------------------------------------#
    # ASN.1 syntactic parser for tag
    #--------------------------------------------------------------------------#
    
    def _parse_tag(self, text):
        """
        parses the text corresponding to a tag within "[" and "]" 
            with tagging class (CONTEXT-SPECIFIC, PRIVATE, APPLICATION)
            and tagging mode (IMPLICIT / EXPLICIT)
        
        sets a list [tag_value, tag_class, tag_mode] in self._tag
            tag_value can be an ASN1RefPAram if referring to a parameter;
        
        returns the rest of the text
        """
        m = SYNT_RE_TAG.match(text)
        if not m:
            # no tag specified
            self._tag = None
            return text
        cla, valnum, valref = m.group(1), m.group(2), m.group(3)
        # 1) get TAG class
        if cla is None:
            cla = TAG_CONTEXT_SPEC
        # 2) get TAG value
        if valref:
            param = GLOBAL.COMP['NS']['par']
            if param and valref in param:
                # 2.1) valref corresponds to a formal parameter
                Gov = param[valref]['gov']
                self.__parse_value_ref_typechk(Gov, valref, TYPE_INT)
                val = ASN1RefValue(ASN1RefParam(valref))
                # add the referrer path to the formal parameter
                param[valref]['ref'].append( _path_root() + ['tag', 0] )
            else:
                # 2.2) valref corresponds to a global value
                try:
                    valmod = GLOBAL.COMP['NS']['obj'][valref]
                except KeyError:
                    raise(ASN1ProcTextErr('{0}: tag value {1}, undefined'\
                          .format(self.fullname(), valref)))
                try:
                    valobj = get_asnobj(valmod, valref)
                except ASN1Err as Err:
                    raise(ASN1ProcTextErr('{0}: {1}'\
                          .format(self.fullname(), Err)))
                if valobj._val is None:
                    # val not yet compiled
                    raise(ASN1ProcLinkErr('{0}: tag value {1}'\
                          .format(self.fullname(), valref)))
                self.__parse_value_ref_typechk(valobj, valref, TYPE_INT)
                val = valobj._val
                # keep track of the reference
                self._ref.add( ASN1RefValue((valmod, valref)) )
        else:
            # 2.3) valnum is a straight integer
            val = int(valnum)
        text = text[m.end():].strip()
        # 3) get TAG mode
        m = re.match('(IMPLICIT|EXPLICIT)(?:\s)', text)
        if m:
            self._tag = [val, cla, m.group(1)]
            text = text[m.end():].strip()
        else:
            # get the mode from the module-wide options
            if GLOBAL.COMP['NS']['tag'] == TAG_AUTO:
                mode = TAG_IMPLICIT
            else:
                mode = GLOBAL.COMP['NS']['tag']
            self._tag = [val, cla, mode]
        #
        return text
    
    #--------------------------------------------------------------------------#
    # ASN.1 syntactic parser for type / typeref
    #--------------------------------------------------------------------------#
    
    def _parse_type(self, text):
        """
        parses the text corresponding to the ASN.1 type (native or user-defined)
        
        if a native type is used, sets it in self._type
        if a reference to a user-defined type is used, sets the corresponding 
            reference in self._typeref and copy its _type into self._type
        if the type refers to a parameter, the parameter ref is updated with 
            the referrer's path
        
        for SEQUENCE OF and SET OF native types, parse the SIZE and other 
            constraints early with _parse_const() 
        
        returns the rest of the text
        """
        # An ASN.1 type can be noted as a:
        # 1) ASN.1 native type -> 1
        #    in case of INSTANCE OF declaration, another type follows 
        #    (TYPE-IDENTIFIER or subtype of it)
        # 2) reference to a user-defined ASN.1 type: 
        #    Typeref -> 2.2.2
        #    Typeref can reference a formal parameter too -> 2.2.1
        # 3) reference to a user-defined ASN.1 class: 
        #    CLASSREF -> 2.2.2
        #    CLASSREF can reference a formal parameter too -> 2.2.1
        # 4) reference to a user-defined type field within a user-defined ASN.1 class: 
        #    CLASSREF.&[fF]ield -> 2.1.2
        #    CLASSREF can reference a formal parameter too -> 2.1.1
        # 5) reference to an open-type field within a user-defined ASN.1 class value: 
        #    classvalref.&Type -> 5.2
        #    classvalref can reference a formal paramater too -> 5.1
        # 6) reference to a type within a user-defined CHOICE object:
        #    cho1 < ChoiceObj -> 4.2
        #    ChoiceObj can reference a formal parameter too -> 4.1
        # 7) when inside a native CLASS type, reference to an internal open-type field: 
        #    &Type -> 3
        
        # 1) reference to an ASN.1 native type
        rest, const = self._parse_type_native(text)
        if rest is not None:
            # parse constraint for SEQUENCE OF / SET OF
            if const is not None:
                assert(self._type in (TYPE_SEQ_OF, TYPE_SET_OF))
                for text_const in const:
                    void = self._parse_const(text_const)
            return rest
        #
        #
        param = GLOBAL.COMP['NS']['par']
        #
        #
        # 2) reference to a user-defined Typeref or CLASSREF
        m = match_typeref(text)
        if m:
            typeref = m.group(1)
            text = text[len(typeref):].strip()
            #
            if typeref.isupper() and text[0:2] == '.&':
                # 2.1) typeref is actually a CLASSREF, with (chained) class 
                # field(s) reference: CLASSREF(.&[fF]ield){1,}
                classpath = []
                while text[0:2] == '.&':
                    m = SYNT_RE_CLASSFIELDIDENT.match(text[1:])
                    try:
                        classpath.append(m.group(1))
                        text = text[1+m.end():].strip()
                    except AttributeError:
                        raise(ASN1ProcTextErr('{0}: invalid CLASS field reference, {1}'\
                              .format(self.fullname(), text)))
                if param and typeref in param:
                    # 2.1.1) CLASSREF is a reference to a local formal parameter
                    # type may not be known until CLASSREF gets its actual parameter
                    # hence it will be resolved at parameterization
                    self._typeref = ASN1RefClassField(ASN1RefParam(typeref), classpath)
                    param[typeref]['ref'].append( _path_root() + ['typeref'] )
                    self._type = TYPE_OPEN
                else:
                    # 2.1.2) CLASSREF is a global reference
                    try:
                        refmod = GLOBAL.COMP['NS']['obj'][typeref]
                    except KeyError:
                        raise(ASN1ProcTextErr('{0}: ASN1RefClassField into {1}, undefined'\
                              .format(self.fullname(), typeref))) 
                    self._typeref = ASN1RefClassField((refmod, typeref), classpath)
                    tr = self.get_typeref()
                    self._type =  tr._type
                    #
                    if tr.get_param():
                        raise(ASN1NotSuppErr('{0}: parameterized CLASS field {1!r}'\
                              .format(self.fullname(), self._typeref)))
                    #
                    # keep track of the type reference and return
                    self._ref.add( self._typeref )
            #
            elif text[0:1] == '.':    
                # 2.2) typeref is actually a reference to an imported module, 
                # and the subsequent token should be a typeref within this module
                refmod = typeref
                text = text[1:].strip()
                m = match_typeref(text)
                if not m:
                    raise(ASN1ProcTextErr('{0}: ASN1RefType to {1}., missing typeref'\
                          .format(self.fullname(), refmod)))
                typeref = m.group(1)
                text = text[len(typeref):].strip()
                self._typeref = ASN1RefType((refmod, typeref))
                tr = self.get_typeref()
                self._type = tr._type
                #
                # keep track of the type reference and return
                self._ref.add( self._typeref )
            #
            else:
                # 2.3) local type / class reference only
                if param and typeref in param:
                    # 2.3.1) typeref is a reference to a local formal parameter
                    # if the formal parameter is MODE_TYPE: it is an OPEN_TYPE or TYPE_CLASS
                    # if the formal parameter is MODE_SET: it can be any defined type
                    self._typeref = ASN1RefType(ASN1RefParam(typeref))
                    param[typeref]['ref'].append( _path_root() + ['typeref'] )
                    self._type = param[typeref]['gov']._type
                else:
                    # 2.3.2) typeref is a global reference
                    try:
                        refmod = GLOBAL.COMP['NS']['obj'][typeref]
                    except KeyError:
                        raise(ASN1ProcTextErr('{0}: ASN1RefType to {1}, undefined'\
                              .format(self.fullname(), typeref)))
                    self._typeref = ASN1RefType((refmod, typeref))
                    tr = self.get_typeref()
                    self._type = tr._type
                    #
                    # keep track of the type reference and return
                    self._ref.add( self._typeref )
            #
            return text
        #
        #
        # 3) internal reference to another user-defined field within a CLASS 
        # &ClassField
        # or worse: &ClassField.&ClassSubField.&...
        if self._parent and self._parent._type == TYPE_CLASS:
            m = SYNT_RE_CLASSFIELDREFINT.match(text)
            if m:
                classpath = [m.group(1)]
                text = text[m.end():].strip()
                while text[0:2] == '.&':
                    m = SYNT_RE_CLASSFIELDIDENT.match(text[1:])
                    try:
                        classpath.append(m.group(1))
                        text = text[1+m.end():].strip()
                    except AttributeError:
                        raise(ASN1ProcTextErr('{0}: invalid CLASS field reference, {1}'\
                              .format(self.fullname(), text)))
                self._typeref = ASN1RefClassIntern(None, classpath)
                # ensure the last field name is upper case (MODE_TYPE or MODE_SET)
                if classpath and classpath[-1][0].islower():
                    raise(ASN1ProcTextErr('{0}: invalid mode for CLASS field reference, {1!r}'\
                          .format(self.fullname(), self._typeref)))
                tr = self.get_typeref()
                self._type = tr._type
                #
                if tr.get_param():
                    raise(ASN1NotSuppErr('{0}: parameterized CLASS field {1!r}'\
                          .format(self.fullname(), self._typeref)))
                #
                # keep track of the type reference and return
                self._ref.add( self._typeref )
                return text
        #
        #
        # 4) reference to a CHOICE alternative
        # e.g. cho251 < cho25 < cho2 < ChoiceType
        m = SYNT_RE_CHOICEALT.match(text)
        if m:
            choicepath = list(reversed(list(map(strip, m.group().split('<')))))
            #
            if param and choicepath[0] in param:
                # 4.1) ChoiceType is a reference to a local formal parameter
                # set to OPEN_TYPE,
                # type resolution will happen in parameterized objects only
                if param[choicepath[0]]['gov']._type != TYPE_OPEN:
                    # it could actually be a TYPE_CLASS
                    raise(ASN1ProcTextErr('{0}: invalid type for parameter {1}'\
                          .format(self.fullname(), choicepath[0])))
                self._typeref = ASN1RefChoiceComp(ASN1RefParam(choicepath[0]), choicepath[1:])
                param[choicepath[0]]['ref'].append( _path_root() + ['typeref'] )
                self._type = TYPE_OPEN
            #
            else:
                # 4.2) ChoiceType is a global reference
                try:
                    choicemod = GLOBAL.COMP['NS']['obj'][choicepath[0]]
                except KeyError:
                    raise(ASN1ProcTextErr('{0}: ASN1RefChoiceComp into {1}, undefined'\
                          .format(self.fullname(), choicepath[0])))
                self._typeref = ASN1RefChoiceComp((choicemod, choicepath[0]), choicepath[1:])
                tr = self.get_typeref()
                self._type = tr._type
                #
                # keep track of the type reference and return
                self._ref.add( self._typeref )
            #
            return text[m.end():].strip()
        #
        #
        # 5) reference to a field within a CLASS value
        # e.g. myClassValue.&MyType
        m = SYNT_RE_IDENT.match(text)
        if m:
            classvalref = m.group(1)
            classpath = []
            text = text[m.end():].strip()
            while text[:2] == '.&':
                m = SYNT_RE_CLASSFIELDIDENT.match(text[1:])
                try:
                    classpath.append(m.group(1))
                    text = text[1+m.end():].strip()
                except AttributeError:
                    raise(ASN1ProcTextErr('{0}: invalid CLASS value field reference, {1}'\
                          .format(self.fullname(), text)))
            #
            if param and classvalref in param:
                # 5.1) myClassValue is a reference to a local formal parameter
                # type may not be known until myClassValue gets its actual parameter
                # hence it will be resolved at parameterization
                self._typeref = ASN1RefClassValField(ASN1RefParam(classvalref), classpath)
                # ensure the last field name is upper case (MODE_TYPE or MODE_SET)
                if classpath and classpath[-1][0].islower():
                    raise(ASN1ProcTextErr('{0}: invalid mode for CLASS value field reference, {1!r}'\
                          .format(self.fullname(), self._typeref)))
                param[classvalref]['ref'].append( _path_root() + ['typeref'] )
                self._type = TYPE_OPEN
            #
            else:
                # 5.2) myClassValue is a global reference
                try:
                    classvalmod = GLOBAL.COMP['NS']['obj'][classvalref]
                except KeyError:
                    raise(ASN1ProcTextErr('{0}: ASN1ClassValField into {1}, undefined'\
                          .format(self.fullname(), classvalref)))
                self._typeref = ASN1RefClassValField((classvalmod, classvalref), classpath)
                # ensure the last field name is upper case (MODE_TYPE or MODE_SET)
                if classpath and classpath[-1][0].islower():
                    raise(ASN1ProcTextErr('{0}: invalid mode for CLASS value field reference, {1!r}'\
                          .format(self.fullname(), self._typeref)))
                tr = self.get_typeref()
                self._type =  tr._type
                #
                if tr.get_param():
                    raise(ASN1NotSuppErr('{0}: parameterized CLASS value field {1!r}'\
                          .format(self.fullname(), self._typeref)))
                #
                # keep track of the type reference and return
                self._ref.add( self._typeref )
            #
            return text
        #
        raise(ASN1ProcTextErr('{0}: invalid ASN.1 type definition, {1}'\
              .format(self.fullname(), text)))
    
    def _parse_type_native(self, text):
        m = SYNT_RE_TYPE.match(text)
        if m:
            self._type = m.group(1)
            text = text[len(self._type):].strip()
            const = None
            #
            if self._type in (TYPE_SEQ, TYPE_SET):
                # SEQUENCE OF / SET OF: get potential SIZE constraint and OF keyword
                m = SYNT_RE_SIZEOF.match(text)
                if m and m.group(1) is not None:
                    # get SIZE constraint
                    text, const = self.__extract_const_seqof(text)
                    if text[:2] != 'OF':
                        # SIZE constraint only for SEQ OF / SET OF
                        raise(ASN1ProcTextErr('{0}: invalid use of SIZE keyword: {1}'\
                              .format(self.fullname(), text)))
                    # add OF to the native type
                    self._type = '%s OF' % self._type
                    text = text[2:].strip()
                elif m and m.group(2):
                    # no SIZE constraint, just OF keyword
                    self._type = '%s OF' % self._type
                    text = text[2:].strip()
            #
            elif self._type == TYPE_ANY:
                # ANY type can have a reference to another component of a SEQUENCE
                # with the DEFINED BY declaration
                if text[:10] == 'DEFINED BY':
                    text = text[10:].strip()
                    m = SYNT_RE_IDENT.match(text)
                    if not m:
                        raise(ASN1ProcTextErr('{0}: no identifier for ANY DEFINED BY, {1}'\
                              .format(self.fullname(), text)))
                    if self._flag is None:
                        self._flag = {FLAG_DEFBY: m.group(1)}
                    else:
                        self._flag[FLAG_DEFBY] = m.group(1)
                    text = text[m.end():].strip()
            #
            elif self._type == TYPE_INSTOF:
                # in case of INSTANCE OF declaration, another type follows 
                # (TYPE-IDENTIFIER or subtype of it)
                # get the ObjectClass reference following
                m = match_typeref(text)
                try:
                    classref = m.group(1)
                except AttributeError:
                    raise(ASN1ProcTextErr('{0}: no ObjectClass found, {1}'\
                          .format(self.fullname(), text)))
                try:
                    classmod = GLOBAL.COMP['NS']['obj'][classref]
                except KeyError:
                    raise(ASN1ProcTextErr('{0}: ASN1RefInstOf to {1}, undefined'\
                          .format(self.fullname(), classref)))
                self._typeref = ASN1RefInstOf((classmod, classref))
                text = text[len(classref):].strip()
            #
            elif self._type in (TYPE_TYPEIDENT, TYPE_ABSSYNT):
                # TYPE-IDENTIFIER and ABSTRACT-SYNTAX are actually standard CLASS
                if text[0:2] == '.&':
                    # an inner field can follow
                    m = SYNT_RE_CLASSFIELDIDENT.match(text[1:])
                    try:
                        self._typeref = ASN1RefClassField(('_IMPL_', self._type), [m.group(1)])
                        text = text[1+m.end():].strip()
                    except AttributeError:
                        raise(ASN1ProcTextErr('{0}: invalid {1} field reference, {2}'\
                              .format(self.fullname(), self._type, text)))
                else:
                    self._typeref = ASN1RefType(('_IMPL_', self._type))
                # overwrite the original type of the object
                self._type = self.get_typeref()._type
            #
            elif self._type in GLOBAL.MOD['_IMPL_']:
                # WNG: those types in _IMPL_ module are defined as SEQUENCE, 
                # but native type must be kept
                # REAL, EXTERNAL, EMBEDDED PDV, CHARACTER STRING
                self._typeref = ASN1RefType(('_IMPL_', self._type))
            #
            return text, const
        else:
            return None, None
    
    def __extract_const_seqof(self, text):
        if text[:4] == 'SIZE':
            # no outer parenthesis: e.g. SEQUENCE SIZE (2) OF
            text = text[4:].strip()
            text, text_const = extract_parenth(text)
            if not text_const:
                # no size specification
                raise(ASN1ProcTextErr('{0}: invalid SIZE constraint, {1}'\
                      .format(self.fullname(), text)))
            return text, ['(SIZE (%s))' % text_const]
        else:
            # any kind of constraint can happen otherwise
            const = []
            while text[0:1] == '(':
                text, text_const = extract_parenth(text)
                const.append('(%s)' % text_const)
            return text, const
        
    #--------------------------------------------------------------------------#
    # ASN.1 syntactic parser for content
    #--------------------------------------------------------------------------#
    
    def _parse_cont(self, text):
        """
        parses the text corresponding to any native content of an ASN.1 object
        
        calls special handler for ASN.1 native objects,
        in case of typeref referencement, process arguments as actual parameters
        
        returns the rest of the text
        """
        if self._typeref and self._type != TYPE_INSTOF:
            tr = self.get_typeref()
            params_form = tr.get_param()
            if params_form:
                #
                # 1) handle parameterized standard ASN.1 types
                if isinstance(self._typeref, ASN1RefType):
                    #
                    # 1.1) keep track locally of the formal parameters from typeref
                    self._params_form = list(params_form.values())
                    #
                    # 1.2) bind the content of typeref into self
                    if self._tag is None:
                        self._tag   = tr._tag
                    self._cont  = tr._cont
                    self._root  = tr._root
                    self._ext   = tr._ext
                    self._const = tr._const
                    #self._const = tr.get_const()
                    self._val   = tr._val
                    #
                    # 1.3) duplicate the parameterized pathes
                    for param in self._params_form:
                        for path in param['ref']:
                            #if path[-2:] == ['tag', 0]:
                                # the tag is parameterized, but the list storing it
                                # should not exist yet, 
                            #    self.select_set(path[0:-1], [])
                            #
                            if path[0] == 'param':
                                # a subsequent formal parameter governor is itself
                                # parameterized by this one
                                assert( len(path) > 3 )
                                p_ind = params_form.index(path[1])
                                # decorrelate the local governor
                                self._params_form[p_ind]['gov'] = \
                                    self._params_form[p_ind]['gov'].copy()
                                # keep track of the parameter index
                                if hasattr(param['gov'], '_p_ind'):
                                    param['gov']._p_ind[path[1]] = p_ind
                                else:
                                    param['gov']._p_ind = {path[1]: p_ind}
                            else:
                                self.select_set(path[0:1],
                                                _get_path_copy(self, path))
                #
                # 2) handle parameterized CHOICE component
                elif isinstance(self._typeref, ASN1RefChoiceComp):
                    #
                    # 2.1) make a local copy of the original formal parameters,
                    # and truncate the beggining of all referrers
                    parpath = tr.get_parent_path()
                    parpath_len = len(parpath)
                    self._params_form = []
                    for param in params_form.values():
                        self._params_form.append( {'gov': param['gov'],
                                                   'ref': []} )
                        for path in param['ref']:
                            assert( path[0] != 'param' )
                            if path[:parpath_len] == parpath:
                                # the formal parameter impacts the CHOICE alternative
                                # and requires processing
                                self._params_form[-1]['ref'].append(path[parpath_len:])
                    #
                    # 2.2) bind the content of typeref into self
                    if self._tag is None:
                        self._tag   = tr._tag
                    self._cont  = tr._cont
                    self._root  = tr._root
                    self._ext   = tr._ext
                    self._const = tr._const
                    #self._const = tr.get_const()
                    self._val   = tr._val
                    #
                    # 2.3) duplicate the parameterized pathes
                    for param in self._params_form:
                        for path in param['ref']:
                            if path[-2:] == ['tag', 0]:
                                # the tag is parameterized, but the list storing it
                                # should not exist yet
                                self.select_set(path[0:-1], [])
                            #
                            self.select_set(path[0:1],
                                            _get_path_copy(self, path))
                #
                else:
                    assert()
                #
                text = self._parameterize(text)
                del self._params_form
        #
        # 3) handle native content for specific ASN.1 types
        elif self._type in self._PARSE_CONT_DISPATCH:
            text = getattr(self, self._PARSE_CONT_DISPATCH[self._type])(text)
        #
        return text
    
    def _parameterize(self, text):
        """
        parses the text corresponding to the actual parameters of an ASN.1 
        object
        
        sets the actual parameters at all referrers path(es) for each formal 
        parameter
        
        returns the rest of the text
        """
        #
        # 0) extact actual parameters and verifies them against the number of 
        # formal parameters
        text, params_act = extract_multi(text)
        if not params_act:
            raise(ASN1ProcTextErr('{0}: missing actual parameters'\
                  .format(self.fullname())))
            #asnlog('WNG: {0}.{1}, missing actual parameters'\
            #       .format(GLOBAL.COMP['NS']['mod'], self.fullname()))
            #return text
        #
        if len(params_act) != len(self._params_form):
            raise(ASN1ProcTextErr('{0}: invalid number of parameters, {1} instead of {2}'\
                  .format(self.fullname(), len(params_act), len(self._params_form))))
        #
        # 1) get potential local formal parameters to be passed-through
        self._params_loc = GLOBAL.COMP['NS']['par']
        #
        # create an empty list for keeping track of parameters pass-through
        # for set of values
        # this will be re-initialized at the end of parse_set()
        GLOBAL.COMP['NS']['setpar'] = []
        #
        # 2) iterate over each actual parameter to set them properly in self
        for i in range(len(params_act)):
            #
            # 2.1) get formal param governor and referrers' path
            self._Gov = self._params_form[i]['gov']
            self._pathes = self._params_form[i]['ref']
            param_act = params_act[i]
            #
            # 2.2) extract MODE_SET parameter
            if param_act[0:1] == '{' and param_act[-1:] == '}' and \
            self._Gov._mode == MODE_SET:
                # param_act is a set object
                # WNG: any SEQUENCE / SET / OID value would have curlybrackets, too
                param_act = param_act[1:-1].strip()
                self.__parameterize_set(extract_set(param_act))
            #
            # 2.3) extract MODE_SET parameter reference
            elif self._Gov._mode == MODE_SET:
                self.__parameterize_set_comp(param_act)
            #
            # 2.4) extract MODE_VALUE parameter
            elif self._Gov._mode == MODE_VALUE:
                self.__parameterize_val(param_act)
            #
            # 2.5) extract MODE_TYPE / OPEN_TYPE parameter
            else:
                self.__parameterize_type(param_act)
            #
            if _DEBUG_PARAM:
                asnlog('[DBG] _parameterize({0}): {1}.{2}'.format(
                       text,
                       GLOBAL.COMP['NS']['mod'],
                       GLOBAL.COMP['NS']['name']))
                asnlog('    param_act: {0}'.format(param_act))
                asnlog('    NS path  : {0!r}'.format(GLOBAL.COMP['NS']['path']))
                asnlog('    NS set   : setdisp {0!r}, setpar {1!r}'.format(
                       GLOBAL.COMP['NS']['setdisp'],
                       GLOBAL.COMP['NS']['setpar']))
                asnlog('    governor : name {0}, type {1}, typeref {2!r}, mode {3}'\
                       .format(self._Gov._name, self._Gov._type,
                               self._Gov._typeref, self._Gov._mode))    
                asnlog('    referrers: {0!r}'.format(self._pathes))
            #
            # 2.6) clean-up temporary attributes
            del self._Gov
            del self._pathes
        #
        # 3) clean-up temporary attributes
        del self._params_loc
        #
        # 4) return the rest of the textual object definition
        return text
    
    def __parameterize_set(self, valset):
        # dispatch valset, which is a root / ext dict, to the parameterization
        # applying to each component of the set
        if valset == {'root': [], 'ext': None}:
            self.__parameterize_set_comp_empty(ext=False)
        elif valset == {'root': [], 'ext': []}:
            self.__parameterize_set_comp_empty(ext=True)
        else:
            for comp in valset['root']:
                self.__parameterize_set_comp(comp)
            if valset['ext']:
                for comp in valset['ext']:
                    self.__parameterize_set_comp(comp, dom='ext')
        if hasattr(self, '_ced_path'):
            del self._ced_path
    
    def __parameterize_set_comp_empty(self, ext=False):
        for path in self._pathes:
            #
            if path[0] == 'param':
                raise(ASN1NotSuppErr('{0}: formal parameter set parameterization, {1}'\
                      .format(self.fullname(), path)))
            #
            # 1) ensure the last part of path is the domain (root / ext)
            # and the index in the list of root / ext values
            assert( len(path)>=3 )
            assert( path[-2] in ('root', 'ext') )
            dom = path[-2]
            ind = path[-1]
            assert( isinstance(ind, integer_types) and ind >= 0 )
            #
            # 2) select the root / ext dict containing the set of values
            val = self.select(path[:-2])
            #
            # 3) keep track of the ASN1RefSet when __parameterize_set_comp()
            # is called for the 1st time from __parameterize_set()
            # and remove it from self
            ref = val[path[-2]][path[-1]]
            if isinstance(ref, ASN1RefSet):
                assert( isinstance(ref.called, ASN1RefParam) )
                del val[path[-2]][path[-1]]
            #
            if ext and val['ext'] is None:
                val['ext'] = []
    
    def __parameterize_set_comp(self, comp, dom='root'):
        # in case Gov is a CLASS, comp can be a field selected within
        # this class, e.g. Set{CLA:ClaSet} ::= {AnotherSet{{ClaSet.&Field}}}
        # hence, it is needed to split comp
        m = SYNT_RE_CLASSINSTFIELDREF.match(comp)
        if m and m.group(2):
            comp_spl = list(map(strip, comp[:m.end()].split('.&')))
            if m.end() < len(comp):
                comp_spl.append( comp[m.end():] )
        else:
            comp_spl = [comp]
        #
        # 1) parameter pass-through
        if self._params_loc and comp_spl[0] in self._params_loc:
            self.__parameterize_pt(comp_spl)
            return
        #
        _objval = []
        #
        # 2) set of values parameter resolution
        # use the governor to parse the set of values for each given path
        # take care of the root / ext domains for values
        for path in self._pathes:
            #
            if path[0] == 'param':
                raise(ASN1NotSuppErr('{0}: formal parameter set parameterization, {1}'\
                      .format(self.fullname(), path)))
            #
            # 2.1) ensure the last part of path is the domain (root / ext)
            # and the index in the list of root / ext values
            assert( len(path)>=3 )
            assert( path[-2] in ('root', 'ext') )
            if dom == 'root':
                dom = path[-2]
            ind = path[-1]
            assert( isinstance(ind, integer_types) and ind >= 0 )
            #
            # 2.2) select the root / ext dict containing the set of values
            val = self.select(path[:-2])
            #
            # 2.3) keep track of the ASN1RefSet when __parameterize_set_comp()
            # is called for the 1st time from __parameterize_set()
            # and remove it from self
            ref = val[path[-2]][path[-1]]
            if isinstance(ref, ASN1RefSet):
                assert( isinstance(ref.called, ASN1RefParam) )
                if ref.ced_path:
                    # it will be required to select internal field inside the 
                    # actual parameter, which is a set of values of CLASS
                    self._ced_path = ref.ced_path[:]
                else:
                    self._ced_path = []
                del val[path[-2]][path[-1]]
            #
            # 2.4) create a proxy object that will parse the textual set component 
            # of values
            ObjProxy = self._Gov.copy()
            ObjProxy._ref = set()
            #
            # 2.5) set the global path to the root / ext dict and parse the set 
            # of values
            _path_ext(path[:-2])
            _path_stack(['val'])
            ObjProxy.parse_set(comp, dom=dom)
            _path_pop()
            _path_trunc(len(path)-2)
            #
            # 2.6) this creates a root / ext dict of values to dispatch into self
            objval = ObjProxy._val
            assert( isinstance(objval, dict) )
            #
            for v in objval['root']:
                if self._ced_path:
                    # need to select an internal field within the value
                    if isinstance(v, ASN1RefSet) and isinstance(v.called, ASN1RefParam):
                        # this is easy to handle
                        val[dom].append( ASN1RefSet(ASN1RefParam(v.called.name),
                                                    v.ced_path + self._ced_path) )
                    else:
                        # try to select subfield into the value
                        o = ObjProxy
                        for cp in self._ced_path:
                            try:
                                o = o.get_cont()[cp]
                            except KeyError:
                                raise(ASN1ProcTextErr('{0}: invalid subfield from {1!r}'\
                                      .format(self.fullname(), ref)))
                            if cp not in v:
                                if not o.is_opt():
                                    raise(ASN1ProcTextErr(
                                          '{0}: missing value for mandatory field from {1!r}'\
                                          .format(self.fullname(), ref)))
                                else:
                                    v = None
                                    break
                            else:
                                v = v[cp]
                        if v is not None:
                            if o._mode == MODE_SET:
                                assert( 'root' in v and 'ext' in v )
                                for vr in v['root']:
                                    if vr not in val[dom]:
                                        val[dom].append(vr)
                                if v['ext']:
                                    if val['ext'] is None:
                                        val['ext'] = []
                                    for ve in v['ext']:
                                        val['ext'] = ve
                            elif o._mode == MODE_VALUE:
                                if v not in val[dom]:
                                    val[dom].append(v)
                            else:
                                assert()
                else:
                    # just append the value as is
                    if v not in val[dom]:
                        val[dom].append(v)
            #
            if objval['ext']:
                if val['ext'] is None:
                    val['ext'] = []
                for v in objval['ext']:
                    if self._ced_path:
                        # need to select an internal field within the value
                        if isinstance(v, ASN1RefSet) and isinstance(v.called, ASN1RefParam):
                            # this is easy to handle
                            val['ext'].append( ASN1RefSet(ASN1RefParam(v.called.name),
                                                          c.ced_path + self._ced_path) )
                        else:
                            # try to select subfield into the value
                            o = ObjProxy
                            for cp in self._ced_path:
                                try:
                                    o = o.get_cont()[cp]
                                except KeyError:
                                    raise(ASN1ProcTextErr('{0}: invalid subfield from {1!r}'\
                                          .format(self.fullname(), ref)))
                                if cp not in v:
                                    if not o.is_opt():
                                        raise(ASN1ProcTextErr(
                                              '{0}: missing value for mandatory field from {1!r}'\
                                              .format(self.fullname(), ref)))
                                    else:
                                        v = None
                                        break
                                else:
                                    v = v[cp]
                            if v is not None:
                                if o._mode == MODE_SET:
                                    assert( 'root' in v and 'ext' in v )
                                    if val['ext'] is None:
                                        val['ext'] = []
                                    for vr in v['root']:
                                        if vr not in val['ext']:
                                            val['ext'].append(vr)
                                    if v['ext']:
                                        for ve in v['ext']:
                                            if ve not in val['ext']:
                                                val['ext'].append(ve)
                                elif o._mode == MODE_VALUE:
                                    if v not in val['ext']:
                                        val['ext'].append(v)
                                else:
                                    assert()
                    else:
                        # just append the value as is
                        if v not in val['ext']:
                            val['ext'].append(v)
            #
            # 2.7) transfer references from ObjProxy to self
            if ObjProxy._ref:
                self._ref.update( ObjProxy._ref )
            _objval.append(objval)
        #
        if _DEBUG_PARAM_SET:
            asnlog('DBG: __parameterize_set_comp({0!r}, {1}), {2}.{3}'.format(
                   comp, dom,
                   GLOBAL.COMP['NS']['mod'],
                   GLOBAL.COMP['NS']['name']))
            asnlog('    NS path  : {0!r}'.format(GLOBAL.COMP['NS']['path']))
            asnlog('    NS set   : setdisp {0!r}, setpar {1!r}'.format(
                   GLOBAL.COMP['NS']['setdisp'],
                   GLOBAL.COMP['NS']['setpar']))
            asnlog('    referrers: {0!r}'.format(self._pathes))
            asnlog('    _objval  : {0!r}'.format(_objval))
    
    def __parameterize_pt(self, comp_spl):
        #
        # 1) select the local formal parameter that corresponds to comp
        param_loc = self._params_loc[comp_spl[0]]
        Gov_loc = param_loc['gov']
        #
        # 2) in case the actual parameter is actually a field selected within 
        # the local governor, and not directly the local governor itself
        classpath = comp_spl[1:]
        while classpath:
            try:
                Gov_loc = Gov_loc.get_cont()[classpath[0]]
            except KeyError:
                raise(ASN1ProcTextErr('{0}: invalid field in parameter pass-through, {1}'\
                      .format(self.fullname(), classpath[0])))
            else:
                del classpath[0]
        #
        # 3) ensure the local governor and typeref governor are compatible
        if Gov_loc._type != self._Gov._type or \
        (self._Gov._mode in (MODE_TYPE, MODE_VALUE) and Gov_loc._mode != self._Gov._mode):
        #if Gov_loc._type != self._Gov._type or Gov_loc._mode != self._Gov._mode:
            raise(ASN1ProcTextErr('{0}: incompatible parameter pass-through, {1!r}'\
                  .format(self.fullname(), comp_spl)))
        if Gov_loc._typeref is not None:
            if self._Gov._typeref is None or \
            Gov_loc._typeref.__hash__() != self._Gov._typeref.__hash__():
                asnlog('WNG: {0}.{1}, parameter pass-through may be incompatible, {1!r}'\
                       .format(GLOBAL.COMP['NS']['mod'], self.fullname(), comp_spl))
        #
        path_root = _path_root()
        path_cur = _path_cur()
        #
        # 4) build the local referrers
        for path in self._pathes:
            #
            if path[0] == 'param':
                raise(ASN1NotSuppErr('{0}: formal parameter pass-through parameterization, {1}'\
                      .format(self.fullname(), path)))
            #
            # 4.1) take potential current path into account (especially when
            # we handle ASN.1 value)
            if path_cur:
                #asnlog('{0}.{1}, path_cur: {2!r}, path: {3!r}'.format(
                #       GLOBAL.COMP['NS']['mod'], GLOBAL.COMP['NS']['name'],
                #       GLOBAL.COMP['NS']['path'], path))
                assert( path_cur[0] == 'val' )
                path = path_cur + path[1:]
            #
            # 4.2) keep track locally of the ASN1RefSet and rename it according 
            # to the local formal parameter
            ref = self.select(path)
            assert( isinstance(ref, (ASN1RefSet, ASN1RefValue, ASN1RefClassValField)) )
            assert( isinstance(ref.called, ASN1RefParam) )
            if isinstance(ref, ASN1RefSet) and Gov_loc._mode == MODE_VALUE and \
            not ref.ced_path:
                # casting the set of values to a single value
                newref = ASN1RefValue(called=ASN1RefParam(comp_spl[0]))
            else:
                newref = ref.__class__(called=ASN1RefParam(comp_spl[0]))
            if comp_spl[1:]:
                if ref.ced_path:
                    newref.ced_path = comp_spl[1:] + ref.ced_path
                else:
                    newref.ced_path = comp_spl[1:]
            elif ref.ced_path:
                newref.ced_path = ref.ced_path[:]
            self.select_set(path, newref)
            #
            # 4.3) extend the referrer from the local param to the object 
            # pointed by path, taking potential current path into account
            # WNG: in case of nested parse_set() calls, the path needs to be 
            # flattened (understand who can...)
            #
            if path[0] == 'val':
                path = path[1:]
            if path[0] in ('root', 'ext') and GLOBAL.COMP['NS']['setdisp']:
                assert( len(path) >= 2 )
                if path_cur:
                    path_full = path_root[:1-len(path_cur)] + path[2:]
                else:
                    path_full = path_root + path[2:]
                GLOBAL.COMP['NS']['setpar'].append(path_full)
            else:
                if path_cur:
                    path_full = path_root[:1-len(path_cur)] + path
                else:
                    path_full = path_root + path
            param_loc['ref'].append( path_full )
        # 
        if _DEBUG_PARAM_PT:
            asnlog('[DBG] __parameterize_pt({0!r}), {1}.{2}'.format(
                   comp_spl,
                   GLOBAL.COMP['NS']['mod'],
                   GLOBAL.COMP['NS']['name']))
            asnlog('    NS path         : {0!r}'.format(GLOBAL.COMP['NS']['path']))
            asnlog('    NS set          : setdisp {0!r}, setpar {1!r}'.format(
                   GLOBAL.COMP['NS']['setdisp'],
                   GLOBAL.COMP['NS']['setpar']))
            asnlog('    formal referrers: {0!r}'.format(self._pathes))
            asnlog('    local referrers : {0!r}'.format(param_loc['ref']))
    
    def __parameterize_val(self, val):
        # in case Gov is a CLASS, comp can be a field selected within
        # this class, e.g. val{CLA:claVal} ::= anotherVal{{claVal.&Field}}
        # hence, it is needed to split val
        m = SYNT_RE_CLASSINSTFIELDREF.match(val)
        if m and m.group(2):
            val_spl = list(map(strip, val[:m.end()].split('.&')))
            if m.end() < len(val):
                val_spl.append( val[m.end():] )
        else:
            val_spl = [val]
        #
        # 1) parameter pass-through
        if self._params_loc and val_spl[0] in self._params_loc:
            self.__parameterize_pt(val_spl)
            return
        # 
        # 2) create a proxy object that will parse the textual value
        ObjProxy = self._Gov.copy()
        ObjProxy._ref = set()
        _objval = []
        #
        path_root = _path_root()
        path_cur = _path_cur()
        #
        # 3) go over each path
        for path in self._pathes:
            #
            if path[0] == 'param':
                raise(ASN1NotSuppErr('{0}: formal parameter value parameterization, {1}'\
                      .format(self.fullname(), path)))
            #
            # 3.1) take potential current path into account (especially when
            # we handle ASN.1 value)
            if path_cur:
                #asnlog('{0}.{1}, path_cur: {2!r}, path: {3!r}'.format(
                #       GLOBAL.COMP['NS']['mod'], GLOBAL.COMP['NS']['name'],
                #       GLOBAL.COMP['NS']['path'], path))
                assert( path_cur[0] == 'val' )
                path = path_cur + path[1:]
            #
            # 3.2) select the ASN1Ref that needs to be replaced by the actual 
            # parameter and remove it from self
            ref = self.select(path)
            assert( isinstance(ref, ASN1Ref) )
            assert( isinstance(ref.called, ASN1RefParam) )
            if ref.ced_path:
                # we will need to select internal field inside the actual
                # parameter
                ced_path = ref.ced_path[:]
            else:
                ced_path = []
            #
            # 3.3) set the global path and parse the value
            _path_ext(path)
            _path_stack(['val'])
            rest = ObjProxy.parse_value(val)
            _path_pop()
            _path_trunc(len(path))
            #
            if rest:
                raise(ASN1ProcTextErr('{0}: remaining textual value definition, {1}'\
                      .format(self.fullname(), rest)))
            #
            objval = ObjProxy._val
            assert( objval is not None )
            # 
            # 3.4) select internal field inside the ObjProxy value if required
            o = ObjProxy
            if ced_path:
                for cp in ced_path:
                    try:
                        o = o.get_cont()[cp]
                    except KeyError:
                        raise(ASN1ProcTextErr('{0}: invalid subfield from {1!r}'\
                              .format(self.fullname(), ref)))
                    if cp not in objval:
                        if not o.is_opt():
                            raise(ASN1ProcTextErr(
                                  '{0}: missing value for mandatory subfield from {1!r}'\
                                  .format(self.fullname(), ref)))
                        else:
                            objval = None
                            break
                    else:
                        objval = objval[cp]
            #
            # 3.5) transfer the parsed value from ObjProxy to self
            if o._mode == MODE_SET:
                assert( path[-2] in ('root', 'ext') )
                dom, ind = path[-2], path[-1]
                # delete the potential ASN1Ref and dispatch the content of objval
                # into the dict at path[:-2]
                dest = self.select(path[:-2])
                assert( isinstance(dest, dict) )
                del dest[dom][ind]
                if objval is not None:
                    assert( 'root' in objval and 'ext' in objval )
                    for vr in objval['root']:
                        dest[dom].append( vr )
                    if objval['ext']:
                        if dest['ext'] is None:
                            dest['ext'] = []
                        for ve in objval['ext']:
                            dest['ext'].append(ve)
            elif o._mode == MODE_TYPE:
                assert( path[-1] == 'typeref' )
                # decorrelate objval from the original object
                OldObj = self.select(path[:-1])
                objval = self.__parameterize_transfer_obj(OldObj, objval, 
                                                          clone=True, ClassRef=None)
                self.select_set(path[:-1], objval)
            else:
                # o._mode == MODE_VALUE
                self.select_set(path, objval)
            #
            # 3.6) transfer references from ObjProxy to self
            if ObjProxy._ref:
                self._ref.update( ObjProxy._ref )
                # cleanup ObjProxy references
                ObjProxy._ref = set()
            #
            # cleanup ObjProxy value
            ObjProxy._val = None
            _objval.append(objval)
        # 
        if _DEBUG_PARAM_VAL:
            asnlog('DBG: __parameterize_val({0}), {2}.{3}'.format(
                   val,
                   GLOBAL.COMP['NS']['mod'],
                   GLOBAL.COMP['NS']['name']))
            asnlog('    NS path  : {0!r}'.format(GLOBAL.COMP['NS']['path']))
            asnlog('    NS set   : setdisp {0!r}, setpar {1!r}'.format(
                   GLOBAL.COMP['NS']['setdisp'],
                   GLOBAL.COMP['NS']['setpar']))
            asnlog('    referrers: {0!r}'.format(self._pathes))
            asnlog('    _objval  : {0!r}'.format(_objval))
    
    def __parameterize_type(self, typedef):
        # Gov is a MODE_TYPE / TYPE_OPEN ASN1Obj
        objects = []
        for path in self._pathes:
            #
            # 1) ensure the last part of the path is a typeref
            assert( path[-1] == 'typeref' )
            #
            if path[0] == 'param':
                # 2.1) in case a subsequent formal parameter gets parameterized
                if len(path) != 4 or path[2:4] != ['gov', 'typeref']:
                    raise(ASN1NotSuppErr('{0}: formal parameter type parameterization, {1}'\
                          .format(self.fullname(), path)))
                #
                # 2.2) update the governor in the local record of the formal parameters
                p_ind = self._Gov._p_ind[path[1]]
                ObjOpen = self._params_form[p_ind]['gov']
                assert( ObjOpen._type in (TYPE_OPEN, TYPE_CLASS) )
                #
            else:
                # 3) in case a standard part of the current object is to be parameterized
                # just select it
                ObjOpen = self.select(path[:-1])
                assert( isinstance(ObjOpen, ASN1Obj) )
                assert( ObjOpen._type == TYPE_OPEN )
            #
            # 4) parse the new object
            Obj = ASN1Obj(name=ObjOpen._name, mode=ObjOpen._mode)
            Obj._text_def = typedef
            #
            _path_ext(path[:-1])
            _path_stack([])
            rest = Obj.parse_def(typedef)
            _path_pop()
            _path_trunc(len(path)-1)
            #
            if rest:
                raise(ASN1ProcTextErr('{0}: remaining textual definition, {1}'\
                      .format(self.fullname(), rest)))
            #
            ClassRef = None
            # 5) select internal part of Obj if required
            if isinstance(Obj._typeref, ASN1RefType) and Obj._type == TYPE_CLASS and \
            isinstance(ObjOpen._typeref, ASN1RefClassField):
                Obj._typeref = ASN1RefClassField(Obj._typeref.called, ObjOpen._typeref.ced_path)
                # clean-up CLASS specifics attributes from Obj
                Obj._type = None
                del Obj._syntax
                # track the CLASS reference for potential table constraint
                ClassRef = Obj.get_classref()
            elif not isinstance(ObjOpen._typeref, ASN1RefType):
                raise(ASN1NotSuppErr('{0}: type parameterization with {1!r}'\
                      .format(self.fullname(), ObjOpen._typeref)))
            #
            # 6) transfer existing flags, constraints and tag to the new object
            Obj = self.__parameterize_transfer_obj(ObjOpen, Obj,
                                                   clone=False, ClassRef=ClassRef)
            #
            if path[0] == 'param':
                # 7) replace the local governor by the new object, by rewriting 
                # the gov / ref dict
                self._params_form[p_ind] = {'gov': Obj.resolve(),
                                            'ref': self._params_form[p_ind]['ref']} 
            #
            else:
                # 8) replace ObjOpen by Obj in self
                # e.g. MyType {CustomType} ::= CustomType
                if len(path) > 1:
                    self.select_set(path[:-1], Obj.resolve())
                else:
                    # this is a special case, were the new object will be assigned
                    # during the proc.asnobj_compile() function
                    self._new = Obj.resolve()
                Obj._parent = ObjOpen._parent
            #
            # 9) transfer references from Obj to self
            if Obj._ref:
                self._ref.update( Obj._ref )
            objects.append( Obj )
        #
        if _DEBUG_PARAM_TYPE:
            asnlog('DBG: __parameterize_type({0}), {1}.{2}'.format(
                   typedef,
                   GLOBAL.COMP['NS']['mod'],
                   GLOBAL.COMP['NS']['name']))
            asnlog('    NS path  : {0!r}'.format(GLOBAL.COMP['NS']['path']))
            asnlog('    NS set   : setdisp {0!r}, setpar {1!r}'.format(
                   GLOBAL.COMP['NS']['setdisp'],
                   GLOBAL.COMP['NS']['setpar']))
            asnlog('    referrers: {0!r}'.format(self._pathes))
            asnlog('    objects  : {0!r}'.format(objects))
    
    def __parameterize_transfer_obj(self, OldObj, NewObj, clone=False, ClassRef=None):
        # transfer existing flags, constraints and tag from OldObj to NewObj
        cloned = False
        if OldObj._flag is not None:
            assert(NewObj._flag is None)
            if clone:
                NewObj = NewObj.copy()
                cloned = True
            NewObj._flag = OldObj._flag
        #
        if OldObj._tag:
            assert(NewObj._tag is None)
            if clone and not cloned:
                NewObj = NewObj.copy()
                cloned = True
            NewObj._tag = OldObj._tag
        #
        if OldObj._const:
            if clone:
                if not cloned:
                    NewObj = NewObj.copy()
                    cloned = True
                NewObj._const = NewObj._const[:]
            for const in reversed(OldObj._const):
                # in case of table constraint, need to regenerate ClassRef
                if ClassRef is not None and const['type'] == CONST_TABLE:
                    TabSetOpen = const['tab']
                    # new TabSet according to the parameterized CLASS ref
                    if hasattr(ClassRef, '_mod') and ClassRef._mod:
                        _TabSet = ASN1Obj(name='_tab_{0}'.format(ClassRef._name),
                                          mode=MODE_SET,
                                          type=TYPE_CLASS)
                        _TabSet._typeref = ASN1RefType((ClassRef._mod, ClassRef._name))
                        _TabSet._text_def = ClassRef._text_def
                        TabSet = CLASS(_TabSet)
                    else:
                        # WNG: ClassRef._mod is not always defined, 
                        # e.g. when ClassRef is a parameter
                        TabSet = ClassRef.copy()
                        TabSet._mode = MODE_SET
                        TabSet._ref = set()
                    # transfer set values from TabSetOpen to TabSet
                    TabSet._val = {'root': [], 'ext': None}
                    for val in TabSetOpen._val['root']:
                        if isinstance(val, ASN1RefSet) and \
                        isinstance(val.called, ASN1RefParam):
                            # only supporting the transfer of parameterized set
                            TabSet._val['root'].append(val)
                        else:
                            raise(ASN1NotSuppErr(
                                  '{0}: type parameterization with table constraint, {1!r}'\
                                  .format(self.fullname(), val)))
                    # recreate a new const dict
                    const_new = dict(const)
                    const_new['tab'] = TabSet.resolve()
                    NewObj._const.insert(0, const_new)
                else:
                    NewObj._const.insert(0, const)
        #
        return NewObj
    
    def _parse_cont_int(self, text):
        """
        parses the text corresponding to the content of an ASN.1 INTEGER (named
        values) or BIT STRING (named offsets) object
        
        sets an ASN1Dict with names and named values / offsets in self._cont
        
        returns the rest of the text
        """
        # list of name (value / offset), coma-separated
        # eg: alpha(1), beta (deux), trois(dreI-3), four( 4 ), five ( fifthVal)
        rest, text = extract_curlybrack(text)
        if not text:
            return rest
        named_val = map(strip, text.split(','))
        self._cont = ASN1Dict()
        for nv in named_val:
            m = SYNT_RE_INT_ID.match(nv)
            if not m:
                raise(ASN1ProcTextErr('{0}: invalid named value in {1}, {2}'\
                      .format(self.fullname(), self._type, nv)))
            name = m.group(1)
            if name in self._cont:
                # duplicated identifier
                raise(ASN1ProcTextErr('{0}: duplicated named value in {1}, {2}'\
                      .format(self.fullname(), self._type, name)))
            elif m.group(4):
                # named offset is a reference to an INTEGER
                self._cont[name] = None
                _path_ext(['cont', name])
                self._parse_value_ref(m.group(4),
                                      type_expected=TYPE_INT)
                _path_trunc(2)
            else:
                # named offset is an integer value
                self._cont[name] = int(m.group(3))
        return rest
    
    def _parse_cont_enum(self, text):
        """
        parses the text corresponding to the content of an ASN.1 ENUMERATED
        object
        
        sets an ASN1Dict with names and provided indexes in self._cont, sets
        also self._ext if the content is extended
        
        returns the rest of the text
        """
        # list of enumeration strings and integer values, coma-separated
        # eg: butter (-1), cheese (1), cake, apple (three), ..., orange (4)
        rest, text = extract_curlybrack(text)
        if not text:
            raise(ASN1ProcTextErr('{0}: empty ENUMERATED'\
                  .format(self.fullname())))
        enums = map(strip, text.split(','))
        self._cont = ASN1Dict()
        self._ext  = None
        for enum in enums:
            m = SYNT_RE_ENUM.match(enum)
            if not m:
                raise(ASN1ProcTextErr('{0}: invalid identifier in ENUMERATED, {1}'\
                      .format(self.fullname(), enum)))
            name = m.group(1)
            if name == '...':
                # extension marker
                if self._ext is not None:
                    raise(ASN1ProcTextErr('{0}: invalid extension marker in ENUMERATED, {1}'\
                          .format(self.fullname(), text)))
                self._ext = []
            elif name in self._cont:
                # duplicated identifier
                raise(ASN1ProcTextErr('{0}: duplicated identifier in ENUMERATED, {1}'\
                      .format(self.fullname(), name)))
            elif m.group(3):
                # enum value is an integer
                self._cont[name] = int(m.group(3))
            elif m.group(4):
                # enum value is a reference to an integer
                self._cont[name] = None
                _path_ext(['cont', name])
                self._parse_value_ref(m.group(4),
                                      type_expected=TYPE_INT)
                _path_trunc(2)
            elif m.group(2) is None:
                # no explicit value for the enum
                self._cont[name] = None
            #
            if name != '...':
                if self._ext is not None:
                    # identifier in the extension list
                    self._ext.append(name)
        #
        if not self._cont:
            # empty ENUM are invalid
            raise(ASN1ProcTextErr('{0}: empty ENUMERATED'.format(self.fullname())))
            
        self.__parse_cont_gen_root()
        self.__parse_cont_gen_ext()
        self.__parse_cont_enum_autonum()
        self.__parse_cont_enum_reorder()
        return rest
    
    def __parse_cont_gen_root(self):
        self._root = []
        if self._ext is None:
            ext = []
        else:
            ext = self._ext
        for ident in self._cont.keys():
            if ident in ext:
                break
            else:
                self._root.append(ident)
        # for SEQUENCE, SET and CLASS (and also REAL, EXTERNAL and EMBEDDED PDV
        # which have hidden content), build the list of optional content in 
        # the root part
        if self._type in (TYPE_SEQ, TYPE_SET, TYPE_CLASS, TYPE_EXT, TYPE_EMB_PDV, TYPE_CHAR_STR):
            self._root_mand = []
            self._root_opt = []
            for ident in self._root:
                Cont = self._cont[ident]
                if Cont.is_opt():
                    self._root_opt.append(ident)
                else:
                    self._root_mand.append(ident)
    
    def __parse_cont_gen_ext(self):
        # in case the module forces extensibility globally
        if self._ext is None and GLOBAL.COMP['NS']['ext']:
            self._ext = []
        # for CHOICE, SEQUENCE and SET, build 2 dicts for grouped extension
        if self._type in (TYPE_CHOICE, TYPE_SEQ, TYPE_SET):
            self._ext_ident,self._ext_group = {}, {}
            if self._ext:
                for comp_name in self._ext:
                    Comp = self._cont[comp_name]
                    self._ext_ident[comp_name] = Comp._group
                    if Comp._group in self._ext_group:
                        self._ext_group[Comp._group].append(comp_name)
                    else:
                        self._ext_group[Comp._group] = [comp_name]
    
    def __parse_cont_enum_autonum(self):
        # applies automatic numbering
        # 1) on the root part
        indused = [self._cont[ident] for ident in self._root if \
                   self._cont[ident] is not None]
        ind = 0
        while ind in indused:
            ind += 1
        for ident in self._root:
            if self._cont[ident] is None:
                self._cont[ident] = ind
                indused.append(ind)
                ind += 1
                while ind in indused:
                    ind += 1
        # 2) on the ext part
        if self._ext:
            ind = 0
            while ind in indused:
                ind += 1
            for ident in self._ext:
                if self._cont[ident] is None:
                    self._cont[ident] = ind
                    indused.append(ind)
                    ind += 1
                    while ind in indused:
                        ind += 1
                elif self._cont[ident] in indused:
                    raise(ASN1ProcTextErr(
                          '{0}: invalid numbering of extension {1}, {2}'\
                          .format(self.fullname(), ident, self._cont[ident])))
    
    def __parse_cont_enum_reorder(self):
        # reorder the _cont ASN1Dict according to the enum numbering
        ind = list(self._cont.values())
        Cont = ASN1Dict()
        while ind:
            for (ident, val) in self._cont.items():
                if not ind:
                    break
                if val == min(ind):
                    Cont[ident] = val
                    ind.remove(val)
        self._cont = Cont
        # reorder the _ext list similarly
        if self._ext:
            ext = []
            for ident in self._cont:
                if ident in self._ext:
                    ext.append(ident)
            self._ext = ext
    
    def _parse_cont_seqof(self, text):
        """
        parses the text corresponding to the content of an ASN.1 SEQUENCE OF
        or SET OF object
        
        sets an ASN1Obj directly in self._cont
        
        returns the rest of the text
        """
        m = SYNT_RE_IDENT.match(text)
        if m:
            name = m.group(1)
            text = text[m.end():].strip()
        else:
            name = '_item_'
        #
        Comp = ASN1Obj(name=name, mode=MODE_TYPE, parent=self)
        Comp._text_def = text
        #
        _path_ext(['cont'])
        _path_stack([])
        text = Comp.parse_def(text)
        _path_pop()
        _path_trunc(1)
        #
        self._cont = Comp.resolve()
        self._cont.__comp_chk()
        #
        # transfer ref from component to self
        self._ref.update( Comp._ref )
        #
        return text
    
    def _parse_cont_choice(self, text):
        """
        parses the text corresponding to the content of an ASN.1 CHOICE object
        
        sets an ASN1Dict with components in self._cont
            each self._cont item has the following format:
            component_name (str): ASN1Obj
        sets a (nested) list of extended component_name in self._ext 
        
        returns the rest of the text
        """
        rest, text_comps = extract_multi(text)
        if not text_comps:
            raise(ASN1ProcTextErr('{0}: empty CHOICE'\
                  .format(self.fullname())))
        # initialize content and parse components
        self._cont = ASN1Dict()
        self._ext  = None
        self.__parse_cont_comps(text_comps, self._type, False)
        #
        if not self._cont:
            # empty CHOICE are invalid
            raise(ASN1ProcTextErr('{0}: empty CHOICE'.format(self.fullname())))
        #
        # transfer ref from components to self
        for Comp in self._cont.values():
            self._ref.update( Comp._ref )
        #
        self.__parse_cont_gen_root()
        self.__parse_cont_gen_ext()
        self.__parse_cont_gen_tag()
        #
        return rest
    
    def __parse_cont_gen_tag(self):
        #
        # (try to) apply automatic tagging first
        if GLOBAL.COMP['NS']['tag'] == TAG_AUTO:
            # if self is a SEQUENCE / SET / CHOICE
            # and at least 1 of the 3 first components is manually tagged,
            # then automatic tag does not apply...
            not_auto = False
            if self._type in (TYPE_SEQ, TYPE_SET, TYPE_CHOICE):
                for Comp in list(self._cont.values())[:3]:
                    if Comp._tag is not None:
                        not_auto = True
                        break
            #
            if not not_auto:
                # automatic tagging from 0
                t = 0
                t_used = []
                for Comp in self._cont.values():
                    if Comp._tag is not None:
                        # manually tagged
                        t_used.append(Comp._tag[0])
                        while t in t_used:
                            t += 1
                    else:
                        if Comp._type in (TYPE_CHOICE, TYPE_OPEN):
                            Comp._tag = [t, TAG_CONTEXT_SPEC, TAG_EXPLICIT]
                        else:
                            Comp._tag = [t, TAG_CONTEXT_SPEC, TAG_IMPLICIT]
                        t += 1
        #
        # then check tag canonicity
        if self._type in (TYPE_CHOICE, TYPE_SET):
            # for CHOICE and SET, verifies that all components have distinct tags
            tag_db = set()
            for ident in self._cont:
                Comp = self._cont[ident]
                tag = Comp.get_tag()
                if tag is None:
                    tag = Comp.get_tag_univ()
                #
                if tag is None:
                    # untagged CHOICE / OPEN / ANY
                    if Comp._type == TYPE_CHOICE:
                        cho_tag_db = Comp.__choice_expand_tags()
                        inter = tag_db.intersection( cho_tag_db )
                        if inter:
                            raise(ASN1ProcTextErr('{0}: duplicate tags in CHOICE / SET with {1}, {2!r}'\
                                  .format(self.fullname(), ident, inter)))
                    else:
                        asnlog('WNG: {0}.{1}, untagged OPEN / ANY in CHOICE / SET with {2}'\
                               .format(GLOBAL.COMP['NS']['mod'], self.fullname(), ident))
                else:
                    tag = tuple(tag)
                    if tag in tag_db:
                        raise(ASN1ProcTextErr('{0}: duplicate tag in CHOICE / SET with {1}, {2!r}'\
                              .format(self.fullname(), ident, tag)))
                    else:
                        tag_db.add( tag )
        #
        elif self._type == TYPE_SEQ:
            # for SEQUENCE, verifies that all optional successive root components 
            # have distinct tags
            prev_tag = None
            for ident in self._cont:
                Comp, err = self._cont[ident], False
                if Comp.is_opt() or prev_tag is not None:
                    tag = Comp.get_tag()
                    if tag is None:
                        tag = Comp.get_tag_univ()
                    if tag is None:
                        # untagged CHOICE / OPEN / ANY
                        if Comp._type == TYPE_CHOICE:
                            tag = Comp.__choice_expand_tags()
                        else:
                            asnlog('WNG: {0}.{1}, untagged OPEN / ANY in SEQUENCE with {2}'\
                                   .format(GLOBAL.COMP['NS']['mod'], self.fullname(), ident))
                    #
                    if prev_tag is not None:
                        if isinstance(prev_tag, set):
                            if isinstance(tag, set):
                                inter = prev_tag.intersection(tag)
                                if inter:
                                    err = True
                            elif isinstance(tag, list):
                                if tuple(tag) in prev_tag:
                                    err = True
                        elif isinstance(prev_tag, list):
                            if isinstance(tag, set):
                                inter = tag.intersection(tuple(prev_tag))
                                if inter:
                                    err = True
                            elif isinstance(tag, list):
                                if tag == prev_tag:
                                    err = True 
                        if err:
                            raise(ASN1ProcTextErr('{0}: duplicate tag in SEQUENCE with {1}, {2!r}'\
                                  .format(self.fullname(), ident, tag)))
                        else:
                            prev_tag = tag
                    else:
                        prev_tag = tag
                #
                if not Comp.is_opt():
                    prev_tag = None
    
    def __choice_expand_tags(self):
        tag_db = set()
        cho_cont = self.get_cont()
        for ident in cho_cont:
            Cho = cho_cont[ident]
            tag = Cho.get_tag()
            if tag is None:
                tag = Cho.get_tag_univ()
            if tag is None:
                # untagged CHOICE / OPEN / ANY
                if Cho._type == TYPE_CHOICE:
                    tag_db.update( Cho.__choice_expand_tags() )
                else:
                    asnlog('WNG: {0}.{1}, untagged OPEN / ANY component in {2}'\
                           .format(GLOBAL.COMP['NS']['mod'], self.fullname(), ident))
            else:
                tag_db.add( tuple(tag) )
        return tag_db
    
    def _parse_cont_seq(self, text):
        """
        parses the text corresponding to the content of an ASN.1 SEQUENCE object
        
        sets an ASN1Dict with components in self._cont
            each self._cont item has the following format:
            component_name (str): ASN1Obj
        sets a (nested) list of extended component_name in self._ext 
        
        returns the rest of the text
        """
        rest, text_comps = extract_multi(text)
        if text_comps is None:
            raise(ASN1ProcTextErr('{0}: no {1} content found'\
                  .format(self.fullname(), self._type)))
        # initialize content and parse components
        self._cont = ASN1Dict()
        self._ext  = None
        self.__parse_cont_comps(text_comps, self._type, False)
        #
        # transfer ref from components to self
        for Comp in self._cont.values():
            self._ref.update( Comp._ref )
        #
        self.__parse_cont_gen_root()
        self.__parse_cont_gen_ext()
        self.__parse_cont_gen_tag()
        #
        return rest
    
    def __parse_cont_comps(self, comps, parent_type, extgroup=False):
        if not hasattr(self, '_compof_id'):
            self._compof_id = 0
        groupid = 0
        for comp in comps:
            # 1) get standard ASN.1 component name
            m = SYNT_RE_IDENT.match(comp)
            if m:
                name = m.group(1)
                if name in self._cont:
                    raise(ASN1ProcTextErr('{0}: duplicated component name, {1}'\
                          .format(self.fullname(), name)))
                comp_t = comp[m.end():].strip()
                Comp = ASN1Obj(name=name, mode=MODE_TYPE, parent=self)
                Comp._text_def = comp_t
                self._cont[name] = Comp
                #
                _path_ext(['cont', name])
                _path_stack([])
                comp_t = Comp.parse_def(comp_t)
                comp_t = Comp._parse_cont_comp_flag(comp_t)
                _path_pop()
                _path_trunc(2)
                #
                self._cont[name] = Comp.resolve()
                if self._ext is not None:
                    # extended component
                    self._ext.append(name)
            #
            # 2) get COMPONENTS OF construction within SEQUENCE / SET
            elif parent_type != TYPE_CHOICE and comp[:13] == 'COMPONENTS OF':
                # lookup typeref and copy its components into C
                cont_len = len(self._cont)
                comp_t = self.__parse_cont_expand_compof(comp[13:].strip())
                if self._ext is not None:
                    self._ext.extend(\
                        [name for name in list(self._cont.keys())[cont_len:]])
            #
            # 3) get extension marker
            elif not extgroup and comp[:3] == '...':
                name = '...'
                if self._ext is None:
                    self._ext = []
                else:
                    # this multiple extension markers actually exist in some
                    # ASN.1 spec (e.g. in ITU-T X series specs)
                    #raise(ASN1ProcTextErr('{0}: duplicated extension marker'\
                    #      .format(self.fullname())))
                    #asnlog('WNG: {0}.{1}, multiple extension markers'\
                    #       .format(GLOBAL.COMP['NS']['mod'], self.fullname()))
                    pass
                comp_t = comp[3:].strip()
            #
            # 4) get group of options
            elif not extgroup and self._ext is not None and \
            comp[:2] == '[[' and comp[-2:] == ']]':
                og_text = comp[2:-2]
                # some specs have a dummy integer to identify the spec version
                # in the beginning of the group, we just remove it if we find one
                m = SYNT_RE_GROUPVERS.match(og_text)
                if m:
                    #group_vers = int(m.group().split(':')[0])
                    og_text = og_text[m.end():].strip()
                # split optional components
                og_coma_off = [-1] + search_top_lvl_sep(og_text, ',') + \
                              [len(og_text)]
                og_comps = map(strip,
                               [og_text[og_coma_off[i]+1:og_coma_off[i+1]] \
                                for i in range(len(og_coma_off)-1)])
                # re-parse it
                cont_len = len(self._cont)
                self.__parse_cont_comps(og_comps, self._type, True)
                for (comp_name, Comp) in list(self._cont.items())[cont_len:]:
                    Comp._group = groupid
                groupid += 1
                comp_t = ''
            #
            else:
                raise(ASN1ProcTextErr(
                      '{0}: no valid component identifier found, {1}'\
                      .format(self.fullname(), comp)))
            #
            # 5) ensure all the text has been processed
            if comp_t:
                raise(ASN1ProcTextErr(
                      '{0}, component {1}: remaining textual definition, {2}'\
                      .format(self.fullname(), name, comp_t)))
        #
        if not extgroup:
            del self._compof_id
    
    def __parse_cont_expand_compof(self, text):
        #
        # 1) create a new object, even if we generally only get a typeref here
        CompOf = ASN1Obj(name='_compof_{0}'.format(self._compof_id),
                         mode=MODE_TYPE,
                         parent=self)
        CompOf._text_def = text
        self._compof_id += 1
        self._cont[CompOf._name] = CompOf
        #
        # 2) ensure the SEQUENCE / SET to be expanded is not referencing a 
        # formal parameter
        if GLOBAL.COMP['NS']['par']:
            parrefnum = sum([len(par['ref']) for \
                             par in GLOBAL.COMP['NS']['par'].values()])
        #
        _path_ext(['cont', CompOf._name])
        _path_stack([])
        text = CompOf.parse_def(text)
        _path_pop()
        _path_trunc(2)
        #
        if GLOBAL.COMP['NS']['par'] and \
        parrefnum != sum([len(par['ref']) for \
                          par in GLOBAL.COMP['NS']['par'].values()]):
            raise(ASN1NotSuppErr('{0}: COMPONENT OF with parameterization'\
                  .format(self.fullname())))
        #
        del self._cont[CompOf._name]
        #
        # 3) ensure the SEQUENCE / SET to be expanded has the correct type and mode
        if CompOf._type != self._type or CompOf._mode != MODE_TYPE:
            raise(ASN1ProcTextErr('{0}: invalid COMPONENT OF definition, {1}'\
                  .format(self.fullname(), Comp._text_def)))
        #
        # 4) insert copies of components of CompOf into the content
        for (compof_name, CompOfObj) in CompOf.get_cont().items():
            if compof_name in self._cont:
                raise(ASN1ProcTextErr('{0}: duplicated component name, {1}'\
                      .format(self.fullname(), compof_name)))
            assert( CompOfObj._type is not None )
            self._cont[compof_name] = CompOfObj.copy()
            if GLOBAL.COMP['NS']['tag'] == TAG_AUTO and \
            self._cont[compof_name]._tag is not None and \
            self._cont[compof_name]._tag[1] == TAG_CONTEXT_SPEC:
                # delete context-specific tags of the components,
                # as they will be retagged automatically with this class in self
                self._cont[compof_name]._tag = None
            self._cont[compof_name]._parent = self
            # delete all subtype constraints
            self._cont[compof_name]._const = []
        #
        return text
    
    def _parse_cont_comp_flag(self, text):
        """
        parses the text corresponding to the potential specific behaviour of the
        ASN.1 constructed component: OPTIONAL or DEFAULT $abcd_gros_merdier.
        
        sets one item in self._flag
            the item has one of the following format:
            FLAG_OPT: None for OPTIONAL behaviour
            FLAG_DEF_STR: str for DEFAULT value (value unparsed)
        
        returns the rest of the text
        """
        if text[:8] == 'OPTIONAL':
            if self._flag is None:
                self._flag = {FLAG_OPT: None}
            else:
                self._flag[FLAG_OPT] = None
            text = text[8:].strip()
            return text
        #
        elif text[:7] == 'DEFAULT':
            if self._flag is None:
                self._flag = {FLAG_DEF: None}
            else:
                self._flag[FLAG_DEF] = None
            _path_ext(['flag', FLAG_DEF])
            text = self.parse_value(text[7:].strip())
            _path_trunc(2)
            return text
        #
        else:
            return text
    
    def __comp_chk(self):
        # verify there is no CLASS object defined / referenced within ASN.1
        # standard constructed types
        assert( self._parent is not None )
        if self._parent._type in (TYPE_SEQ, TYPE_SET, TYPE_SEQ_OF, TYPE_SET_OF, 
        TYPE_CHOICE): 
            if self._type in (TYPE_CLASS, TYPE_TYPEIDENT, TYPE_ABSSYNT):
                raise(ASN1ProcTextErr('{0}: CLASS object within ASN.1 constructed object'\
                      .format(self.fullname())))
            elif self._mode != MODE_TYPE:
                raise(ASN1ProcTextErr('{0}: mode {1} object within ASN.1 constructed object'\
                      .format(self.fullname())))
    
    
    def _parse_cont_set(self, text):
        """
        parses the text corresponding to the content of an ASN.1 SET object
        
        sets an ASN1Dict with components in self._cont
            each self._cont item has the following format:
            component_name (str): ASN1Obj
            all components are put in their canonical tag order
        sets a (nested) list of extended component_name in self._ext 
        
        returns the rest of the text
        """
        rest, text_comps = extract_multi(text)
        if text_comps is None:
            raise(ASN1ProcTextErr('{0}: no {1} content found'\
                  .format(self.fullname(), self._type)))
        # initialize content and parse components
        self._cont = ASN1Dict()
        self._ext  = None
        self.__parse_cont_comps(text_comps, self._type, False)
        #
        # transfer ref from components to self
        for Comp in self._cont.values():
            self._ref.update( Comp._ref )
        #
        self.__parse_cont_gen_root()
        self.__parse_cont_gen_ext()
        self.__parse_cont_gen_tag()
        #
        return rest
    
    
    def _parse_cont_class(self, text):
        """
        parses the text corresponding to the content of an ASN.1 CLASS object
        
        sets an ASN1Dict with CLASS fields in self._cont
            each self._cont item has the following format:
            field_name (str): ASN1Obj
        
        returns the rest of the text
        """
        rest, fields = extract_multi(text)
        if not fields:
            raise(ASN1ProcTextErr('{0}: CLASS content cannot be empty'\
                  .format(self.fullname())))
        #
        self._cont = ASN1Dict()
        self._ext  = None
        ref_class_intern = []
        #
        # 1) do a 1st iteration to compile each field properly, except for those
        # referring to another local field (ASN1RefClassIntern) to be placed
        # in ref_class_intern
        for field in fields:
            # 1.1) get name
            m = SYNT_RE_CLASSFIELDIDENT.match(field)
            if not m:
                raise(ASN1ProcTextErr('{0}: invalid CLASS field name, {1}'\
                      .format(self.fullname(), field)))
            name = m.group(1)
            field = field[m.end():].strip()
            #
            # 1.2) create an empty ASN1Obj instance and place it in the content
            # with the current CLASS object `self' as parent
            Field = ASN1Obj(name=name, parent=self)
            Field._text_def = field
            self._cont[name] = Field
            #
            # 1.3) set the path in the namespace for processing Field
            _path_ext(['cont', name])
            # we need to stack a new path, because the following processing is a 
            # variant of the standard parse_def() method
            _path_stack([])
            #
            # 1.4) get potential tag (a priori useless for CLASS object)
            field = Field._parse_tag(Field._text_def)
            #
            # 1.5) filter out ASN1RefClassIntern and ASN1RefClassField into the
            # same CLASS
            m1 = SYNT_RE_CLASSFIELDREFINT.match(field)
            m2 = SYNT_RE_CLASSFIELDREF.match(field)
            if m1 or (m2 and m2.group(2) == self._name):
                ref_class_intern.append( (name, Field, field) )
            else:
                # 1.6) get potential type or typeref
                if name[0].isupper() and (not field or \
                re.match('(UNIQUE|OPTIONAL|DEFAULT)(\s{1,}|$)', field)):
                    # no type is provided, so this is must be an OPEN TYPE
                    Field._mode = MODE_TYPE
                    Field._type = TYPE_OPEN
                else:
                    field = Field._parse_type(field)
                    # 1.7) mode and type determination for defined fields
                    if name[0].isupper():
                        Field._mode = MODE_SET
                    elif isinstance(Field._typeref, ASN1RefType) and \
                    str(Field._typeref.called).isupper():
                        # some ASN.1 inconsistency here (not the single one)
                        #Field._type = TYPE_CLASS # will be resolved afterwards
                        Field._mode = MODE_TYPE
                    else:
                        Field._mode = MODE_VALUE
                    #
                    # 1.8) continue processing the content, constraints, flags
                    field = Field._parse_cont(field)
                    while field and field[0:1] == '(':
                        # mutliple constraints can be specified
                        field = Field._parse_const(field)
                #
                # 1.9) overwrite the content with the compiled Field
                self._cont[name] = Field.resolve()
                #
                # 1.10) finally process the potential flag
                field = self._cont[name]._parse_cont_field_flag(field)
                if field:
                    raise(ASN1ProcTextErr('{0}.&{1}: unprocessed definition, {2}'\
                          .format(self.fullname(), name, field)))
            #
            # 1.11) restore the path in the namespace
            _path_pop()
            _path_trunc(2)
        #
        # 2) do a 2nd iteration over fields referring to another local one
        for (name, Field, field) in ref_class_intern:
            #
            # 2.1) set the path in the namespace
            _path_ext(['cont', name])
            _path_stack([])
            #
            # 2.2) get potential type or typeref
            field = Field._parse_type(field)
            #
            # 2.3) mode and type determination
            if name[0].isupper():
                Field._mode = MODE_SET
            else:
                Field._mode = MODE_VALUE
            #
            # 2.4) continue processing the content, constraints, flags
            field = Field._parse_cont(field)
            while field and field[0:1] == '(':
                # mutliple constraints can be specified
                field = Field._parse_const(field)
            #
            # 2.5) overwrite the content with the compiled Field
            self._cont[name] = Field.resolve()
            #
            # 2.6) process the potential flag
            field = self._cont[name]._parse_cont_field_flag(field)
            if field:
                raise(ASN1ProcTextErr('{0}.&{1}: unprocessed definition, {2}'\
                      .format(self.fullname(), name, field)))
            #
            # 2.7) restore the path in the namespace
            _path_pop()
            _path_trunc(2)
        #
        # 3) transfer ref from components to self
        for Comp in self._cont.values():
            self._ref.update( Comp._ref )
        #
        # 4) generate the root mandatory / optional lists
        self.__parse_cont_gen_root()
        #
        return rest
    
    def _parse_cont_field_flag(self, text):
        """
        parses the text corresponding to the potential specific behaviour of the
        ASN.1 CLASS field: OPTIONAL, DEFAULT $gros_merdier_degueu or UNIQUE.
        
        sets one or two item(s) from the following in self._flag
            each item has the following format:
            FLAG_UNIQ: None for UNIQUE
            FLAG_OPT: None for OPTIONAL
            FLAG_DEF_STR: str for DEFAULT value (value unparsed)
        
        returns the rest of the text
        """
        if text[:6] == 'UNIQUE':
            if self._flag is None:
                self._flag = {FLAG_UNIQ: None}
            else:
                self._flag[FLAG_UNIQ] = None
            text = text[6:].strip()
            if text[:8] == 'OPTIONAL':
                self._flag[FLAG_OPT] = None
                text = text[8:].strip()
                return text
            else:
                return text
        #
        elif text[:8] == 'OPTIONAL':
            if self._flag is None:
                self._flag = {FLAG_OPT: None}
            else:
                self._flag[FLAG_OPT] = None
            text = text[8:].strip()
            if text[:6] == 'UNIQUE':
                self._flag[FLAG_UNIQ] = None
            else:
                return text
        #
        elif text[:7] == 'DEFAULT':
            if self._flag is None:
                self._flag = {FLAG_DEF: None}
            else:
                self._flag[FLAG_DEF] = None
            _path_ext(['flag', FLAG_DEF])
            #
            if self._mode == MODE_VALUE:
                text = self.parse_value(text[7:].strip())
            #
            elif self._mode == MODE_SET:
                text, settext = extract_curlybrack(text[7:].strip())
                if settext is None:
                    raise(ASN1ProcTextErr('{0}: invalid set, {1}'\
                          .format(self.fullname(), text[7:].strip())))
                self.parse_set(settext)
            #
            else:
                # MODE_TYPE object definition
                Obj = ASN1Obj(name=self._name, mode=MODE_TYPE)
                Obj._text_def = text[7:].strip()
                self._flag[FLAG_DEF] = Obj
                _path_stack([])
                text = Obj.parse_def(Obj._text_def)
                _path_pop()
                self._flag[FLAG_DEF] = Obj.resolve()
            #
            _path_trunc(2)
            return text
        #
        else:
            return text
    
    
    #--------------------------------------------------------------------------#
    # ASN.1 syntactic parser for CLASS syntax
    #--------------------------------------------------------------------------#
    
    def _parse_class_syntax(self, text):
        if text[:11] != 'WITH SYNTAX':
            return text
        text = text[11:].strip()
        rest, text = extract_curlybrack(text)
        if not text:
            raise(ASN1ProcTextErr('{0}: WITH SYNTAX without actual content'\
                  .format(self.fullname())))
        # remove comas, as they are just here for beauty !
        text = text.replace(',', '')
        # replace any kind of space(s) with single white space
        text = re.subn('\s{1,}', ' ', text)[0]
        #
        self._syntax = []
        #
        self._synt_text  = text
        self._synt_off   = 0
        self._synt_cur   = self._syntax
        self._synt_depth = 0
        self._synt_fn    = []
        #
        self.__parse_class_syntax_grp()
        #
        if any([fn not in self._synt_fn for fn in self._root_mand]):
            #raise(ASN1ProcTextErr('{0}: some mandatory field(s) not in SYNTAX'\
            #      .format(self.fullname())))
            pass
        #
        del self._synt_text, self._synt_off, self._synt_cur, self._synt_depth, self._synt_fn
        #
        return rest
    
    def __parse_class_syntax_grp(self):
        #
        cap = []
        #
        while self._synt_off < len(self._synt_text):
            m = SYNT_RE_CLASSSYNTAX.match(self._synt_text[self._synt_off:])
            if not m or not m.group(1):
                raise(ASN1ProcTextErr('{0}: invalid WITH SYNTAX expression, {1}'\
                      .format(self.fullname(), self._synt_text[self._synt_off:])))
            #
            elif m.group(2):
                # [ : opt_open
                self._synt_off += m.end()
                if cap:
                    self._synt_cur.append(' '.join(cap))
                    cap = []
                synt_cur = self._synt_cur
                self._synt_cur.append([])
                self._synt_cur = self._synt_cur[-1]
                self._synt_depth += 1
                self.__parse_class_syntax_grp()
                self._synt_depth -= 1
                self._synt_cur = synt_cur
            #
            elif m.group(3):
                # ] : opt_close
                self._synt_off += m.end()
                if cap:
                    self._synt_cur.append(' '.join(cap))
                    cap = []
                return
            #
            elif m.group(4):
                # capital word
                self._synt_off += m.end()
                cap.append(m.group(4))
            #
            elif m.group(6):
                # &[fF]ieldName
                self._synt_off += m.end()
                if cap:
                    self._synt_cur.append(' '.join(cap))
                    cap = []
                elif self._synt_depth:
                    asnlog('WNG: {0}.{1}, no starting SYNTAX keyword for optional field {1}'\
                           .format(GLOBAL.COMP['NS']['mod'], self.fullname(), m.group(6)))
                # do some control on the corresponding field
                fn = m.group(6)
                if fn not in self._cont:
                    raise(ASN1ProcTextErr('{0}: SYNTAX field name not in content, {1}'\
                          .format(self.fullname(), fn)))
                    #pass
                elif self._synt_depth > 0 and fn not in self._root_opt:
                    raise(ASN1ProcTextErr('{0}: field {1}, optional in SYNTAX but not in content'\
                          .format(self.fullname(), fn)))
                    #pass
                elif self._synt_depth == 0 and fn in self._root_opt:
                    asnlog('WNG: {0}.{1}, field {1}, optional in content but not in SYNTAX'\
                           .format(GLOBAL.COMP['NS']['mod'], self.fullname(), fn))
                    #pass
                self._synt_fn.append(fn)
                #
                self._synt_cur.append('&' +fn)
            #
            else:
                assert()
        #
        if cap:
            self._synt_cur.append(' '.join(cap))
    
    #--------------------------------------------------------------------------#
    # ASN.1 syntactic parser for constraints
    #--------------------------------------------------------------------------#
    
    def _parse_const(self, text):
        """
        parses the next ASN.1 object constraint in text, between parenthesis
        
        appends a dict in self._const with at least the following keywords:
            text, type, keys
        
        returns the rest of the text
        """
        text, text_const = extract_parenth(text)
        if text_const is None:
            return text
        const = {'text': text_const}
        m = SYNT_RE_CONST_DISPATCH.match(text_const)
        if m is None:
            if not text_const:
                raise(ASN1ProcTextErr('{0}: invalid empty constraint'\
                     .format(self.fullname())))
            elif self._typeref and \
            isinstance(self._typeref, ASN1RefClassField) and \
            const['text'][0:1] == '{':
                # table constraint for CLASS.&field
                self._parse_const_table(const)
            else:
                # (set of) value(s)
                self._parse_const_val(const)
        elif m.group(1):
            # INCLUDES: (set of) value(s)
            self._parse_const_val(const)
        elif m.group(2):
            # SIZE: (set of) INTEGER value(s)
            self._parse_const_size(const)
        elif m.group(3):
            # FROM
            self._parse_const_alphabet(const)
        elif m.group(4):
            # WITH COMPONENTS
            self._parse_const_withcomps(const)
        elif m.group(5):
            # WITH COMPONENT
            self._parse_const_withcomp(const)
        elif m.group(6):
            # PATTERN
            self._parse_const_regexp(const)
        elif m.group(7):
            # SETTINGS
            # TODO: check which ASN.1 type can get such a constraint
            self._parse_const_property(const)
        elif m.group(8):
            # CONTAINING
            self._parse_const_containing(const)
        elif m.group(9):
            # ENCODED BY
            self._parse_const_encodedby(const)
        elif m.group(10):
            # CONSTRAINED BY
            self._parse_const_userconst(const)
        else:
            assert()
        return text
    
    def _parse_const_val(self, const):
        # single value and type inclusion constraints can be mixed together
        # within a single constraint syntactic definition
        # multiple single value(s) and/or type inclusion(s) are separated 
        # with "|"
        const_index = len(self._const)
        self._const.append(const)
        const['type'] = CONST_VAL
        const['keys'] = ['root', 'ext', 'excl']
        const['root'] = []
        const['ext']  = None
        const['excl'] = False
        #
        # simply use parse_set() to parse the textual values
        _path_ext(['const', const_index])
        if const['text'][:10] == 'ALL EXCEPT':
            # for the ALL EXCEPT case, 2 variants (like with the SIZE constraint)
            # the value can be between parenthesis or not...
            const['excl'] = True
            text = const['text'][10:].strip()
            if text[0] == '(':
                rest, text = extract_parenth(const['text'][10:])
                if text:
                    self.parse_set(text)
                else:
                    raise(ASN1ProcTextErr('{0}: invalid ALL EXCEPT syntax, {1}'\
                          .format(self.fullname(), const['text'])))
                if rest:
                    raise(ASN1ProcTextErr('{0}: invalid ALL EXCEPT syntax, {1}'\
                          .format(self.fullname(), const['text'])))
            else:
                self.parse_set(text)
        else:
            self.parse_set(const['text'])
        _path_trunc(2)
    
    def _parse_const_table(self, const):
        const_index = len(self._const)
        self._const.append(const)
        const['type'] = CONST_TABLE
        const['keys'] = ['tab', 'at', 'exc']
        const['tab']  = None
        const['at']   = None
        const['exc']  = None
        # the 1st part of the constraint is a (serie of) set(s) defined in curlybrackets,
        # the 2nd optional part is after "@", an identifier defined in curlybrackets again, 
        # the 3rd optional part is after "!", the exception part
        # e.g.: {ValSet1|ValSet2, ..., ValSet3|Val4}{@identifier}!exceptionCase
        #
        # we create a generic ASN1Obj instance of type classref, which will 
        # get all values from value(s) and set(s) of values thanks to parse_set()
        #
        # 1) get the CLASS object set(s)
        text, text_set = extract_curlybrack(const['text'])
        if not text_set:
            raise(ASN1ProcTextErr(
                  '{0}: invalid table constraint, no set defined, {1}'\
                  .format(self.fullname(), const['text'])))
        #
        # 2) create a new CLASS object, to host a set of CLASS values to be looked-up in,
        # and referencing the ClassRef
        ClassRef = self.get_classref()
        assert( ClassRef is not None )
        # use the the ClassRef CLASS as a typeref for an new CLASS set object
        if hasattr(ClassRef, '_mod') and ClassRef._mod:
            _TabSet = ASN1Obj(name='_tab_{0}'.format(ClassRef._name),
                              mode=MODE_SET,
                              type=TYPE_CLASS)
            _TabSet._typeref = ASN1RefType((ClassRef._mod, ClassRef._name))
            _TabSet._text_def = ClassRef._text_def
            TabSet = CLASS(_TabSet)
        else:
            # WNG: ClassRef._mod is not always defined, e.g. when ClassRef is a parameter
            TabSet = ClassRef.copy()
            TabSet._mode = MODE_SET
            TabSet._ref = set()
        const['tab'] = TabSet
        #
        _path_ext(['const', const_index, 'tab', 'val'])
        _path_stack(['val'])
        TabSet.parse_set(text_set)
        _path_pop()
        _path_trunc(4)
        #
        # 3) transfer any reference(s) from TabSet to self
        if TabSet._ref:
            self._ref.update( TabSet._ref )
        #
        # 4) get at "@" optionally
        text, at_name = extract_curlybrack(text)
        if at_name and at_name[0:1] == '@':
            at_name = at_name[1:].split('.')
            # ensure the chain of at_name items matches with the content
            if at_name[0] == '':
                # path starting with . is relative
                const['at'] = ['..'] + at_name[1:]
                parent = self._parent
                at_name = at_name[1:]
            else:
                # complete path starting from the root object:
                # count the number of parent until the root object
                lvl = 0
                obj = self
                while obj._parent is not None:
                    lvl += 1
                    obj = obj._parent
                const['at'] = ['..'] * lvl + at_name
                parent = obj
            for atn in at_name:
                if parent is None or parent._cont is None or atn not in parent._cont:
                    raise(ASN1ProcTextErr(
                          '{0}: undefined field reference for table constraint, {1}'\
                          .format(self.fullname(), at_name)))
                else:
                    parent = parent._cont[atn]
        #
        # 5) get exception case "!" optionally
        if text[0:1] == '!':
            # TODO: parse exception case
            const['exc'] = text[1:].strip()
            asnlog('INF: {0}.{1}, unprocessed table constraint exception'\
                   .format(GLOBAL.COMP['NS']['mod'], self.fullname()))
        elif text:
            raise(ASN1ProcTextErr('{0}: remaining text for table constraint, {1}'\
                  .format(self.fullname(), text)))
    
    def _parse_const_size(self, const):
        const_index = len(self._const)
        self._const.append(const)
        const['type'] = CONST_SIZE
        const['keys'] = ['root', 'ext']
        const['root'] = []
        const['ext']  = None 
        # 
        # 1) remove the SIZE identifier
        text = const['text'][4:].strip()
        rest, text = extract_parenth(text)
        if not text:
            raise(ASN1ProcTextErr('{0}: invalid SIZE constraint, no size defined, {1}'\
                  .format(self.fullname(), const['text'])))
        # 
        # 2) create a proxy INTEGER object that will parse the textual value(s)
        ObjProxy = ASN1Obj(name='_size_{0}'.format(self._name),
                           mode=MODE_SET,
                           type=TYPE_INT)
        #
        _path_ext(['const', const_index])
        _path_stack(['val'])
        ObjProxy.parse_set(text)
        assert( isinstance(ObjProxy._val, dict) )
        _path_pop()
        _path_trunc(2)
        #
        # 3) transfer the parsed set of values from ObjProxy to self
        if ObjProxy._val['root']:
            self.select_set(['const', const_index, 'root'], ObjProxy._val['root'])
        if ObjProxy._val['ext'] is not None:
            self.select_set(['const', const_index, 'ext'], ObjProxy._val['ext'])
        #
        # 4) transfer references from ObjProxy to self
        if ObjProxy._ref:
            self._ref.update( ObjProxy._ref )
        #
        # 5) check for some more funny constraint
        m = SYNT_RE_CONST_EXT.match(rest)
        if m:
            # previous constraint must be considered extensible
            const = self.select(['const', const_index])
            if const['ext'] is None:
                const['ext'] = []
            rest = rest[m.end():].lstrip()
        elif rest[0:1] == '^':
            # intersection with a 2nd constraint
            self._parse_const('(%s)' % rest[1:].lstrip())
            # this is a hack, and this is bad
            rest = ''
        if rest:
            raise(ASN1ProcTextErr('{0}: remaining text for SIZE constraint, {1}'\
                 .format(self.fullname(), rest)))
    
    def _parse_const_alphabet(self, const):
        const_index = len(self._const)
        self._const.append(const)
        const['type'] = CONST_ALPHABET
        const['keys'] = ['root', 'ext']
        const['root'] = []
        const['ext'] = None
        # 
        # 1) remove the FROM identifier
        text = const['text'][4:].strip()
        rest, text = extract_parenth(text)
        if not text:
            raise(ASN1ProcTextErr('{0}: invalid ALPHABET constraint, {1}'\
                  .format(self.fullname(), const['text'])))
        #
        # 2) create a proxy object that will parse the textual value(s)
        ObjProxy = ASN1Obj(name='_alpha_{0}'.format(self._name),
                           mode=MODE_SET,
                           type=self._type)
        #
        _path_ext(['const', const_index])
        _path_stack(['val'])
        ObjProxy.parse_set(text)
        assert( isinstance(ObjProxy._val, dict) )
        _path_pop()
        _path_trunc(2)
        #
        # WNG: some specs use FROM ("abcd"), some other FROM ("a"|"b"|"c"|"d")...
        # 3) transfer the parsed set of values from ObjProxy to self
        if ObjProxy._val['root']:
            rv = []
            for v in ObjProxy._val['root']:
                if isinstance(v, ASN1Range) or len(v) == 1:
                    rv.append(v)
                else:
                    # decompose the string into single char if needed
                    [rv.append(c) for c in v]
            self.select_set(['const', const_index, 'root'], rv)
        if ObjProxy._val['ext'] is not None:
            ev = []
            for v in ObjProxy._val['ext']:
                if isinstance(v, ASN1Range) or len(v) == 1:
                    ev.append(v)
                else:
                    # decompose the string into single char if needed
                    [ev.append(c) for c in v]
            self.select_set(['const', const_index, 'ext'], ev)
        #
        # 4) transfer references from ObjProxy to self
        if ObjProxy._ref:
            self._ref.update( ObjProxy._ref )
        #
        # 5) check for some more funny constraint
        m = SYNT_RE_CONST_EXT.match(rest)
        if m:
            # previous constraint must be considered extensible
            const = self.select(['const', const_index])
            if const['ext'] is None:
                const['ext'] = []
            rest = rest[m.end():].lstrip()
        elif rest[0:1] == '^':
            # intersection with a 2nd constraint
            self._parse_const('(%s)' % rest[1:].lstrip())
            # this is a hack, and this is bad
            rest = ''
        if rest:
            raise(ASN1ProcTextErr('{0}: remaining text for SIZE constraint, {1}'\
                 .format(self.fullname(), rest)))
    
    def _parse_const_withcomp(self, const):
        const_index = len(self._const)
        self._const.append(const)
        const['type'] = CONST_COMP
        const['keys'] = []
        # TODO
        asnlog('INF: {0}.{1}, unprocessed WITH COMPONENT constraint'\
               .format(GLOBAL.COMP['NS']['mod'], self.fullname()))
    
    def _parse_const_withcomps(self, const):
        const_index = len(self._const)
        self._const.append(const)
        const['type']  = CONST_COMPS
        const['keys']  = ['root', 'ext']
        const['root']  = []
        const['ext']   = None
        #
        # 1) split potential mutliple WITH COMPONENTS constraints,
        # OR-ed and / or extended
        # sometimes, the 2nd, 3rd, ... comes within additional parenthesis
        try:
            text_comps = extract_set(const['text'])
        except Exception as err:
            raise(ASN1ProcTextErr('{0}: {1}'.format(self.fullname(), err)))
        #
        # 2) collect comps in the root domain
        for rc in text_comps['root']:
            if rc[0:1] == '(' and rc[-1:] == ')':
                rc = rc[1:-1].strip()
            # initialize the container to store constraint present / absent list 
            # of identifier, and identifier with additional constraints
            const_comp = {'_pre': [], '_abs': []}
            const['root'].append(const_comp)
            # parse each component
            _path_ext( ['const', const_index, 'root', len(const['root'])-1] )
            self.__parse_const_withcomps_comp(rc, const_comp)
            _path_trunc(4)
        #
        # 3) collect comps in the ext domain
        if text_comps['ext'] == []:
            const['ext'] = []
        elif text_comps['ext']:
            const['ext'] = []
            for ec in text_comps['ext']:
                if ec[0:1] == '(' and ec[-1:] == ')':
                    ec = ec[1:-1].strip()
                # initialize the container to store constraint present / absent list 
                # of identifier, and identifier with additional constraints
                const_comp = {'_pre': [], '_abs': []}
                const['ext'].append(const_comp)
                # parse each extended component
                _path_ext( ['const', const_index, 'ext', len(const['ext'])-1] )
                self.__parse_const_withcomps_comp(ec, const_comp)
                _path_trunc(4)
    
    def __parse_const_withcomps_comp(self, text, const):
        # 1) check the WITH COMPONENTS identifier
        if text[:15] != 'WITH COMPONENTS':
            raise(ASN1ProcTextErr('{0}: invalid WITH COMPONENTS constraint, {1}'\
                  .format(self.fullname(), text)))
        text = text[15:].strip()
        #
        # 2) extract the components' parts
        rest, comps = extract_multi(text)
        if not comps:
            raise(ASN1ProcTextErr('{0}: empty WITH COMPONENTS constraint'\
                  .format(self.fullname())))
        #
        # 3) get the content of the original constructed object
        cont = self.get_cont()
        if cont is None:
            # warning: it seems there is this quite bad practice of using WITH COMPONENTS
            # constraint applied to formal parameters, which are undefined by nature.
            # so we do our best here to manage the constraint definition when there is
            # no available content defined
            # TODO: the constraint should be parsed after parameterization has happened
            asnlog('INF: {0}.{1}, unprocessed WITH COMPONENTS constraint on formal parameter'\
               .format(GLOBAL.COMP['NS']['mod'], self.fullname()))
            return
        #
        # 4) check for partial components
        if comps[0] == '...':
            partial = True
            comps = comps[1:]
        else:
            partial = False
        #
        # 5) initialize presence lists
        present = []
        potent  = []
        absent  = []
        opt     = []
        done    = []
        #
        # 6) check all components
        for comp in comps:
            ident = comp.split(' ', 1)[0]
            if ident not in cont:
                ident = comp.split('(', 1)[0]
                if ident not in cont:
                    raise(ASN1ProcTextErr(
                          '{0}: invalid ident in WITH COMPONENTS constraint, {1}'\
                          .format(self.fullname(), ident)))
            if ident in done:
                raise(ASN1ProcTextErr(
                      '{0}: duplicated ident in WITH COMPONENTS constraint, {1}'\
                      .format(self.fullname(), ident)))
            comp = comp[len(ident):].strip()
            if not comp:
                # 6.1) presence-only format
                potent.append(ident)
            else:
                # 6.2) use the constructed Component object to parse additional
                # constraint(s)
                Comp = cont[ident]
                #
                # remove already existing constraints and references from the Component
                CompConst = Comp._const
                CompRef = Comp._ref
                Comp._const = []
                Comp._ref = set()
                #
                _path_ext([ident])
                const_ind = 0
                while comp[:1] == '(':
                    _path_stack([])
                    try:
                        comp = Comp._parse_const(comp)
                    except ASN1ProcLinkErr as err:
                        Comp._const = CompConst
                        Comp._ref = CompRef
                        raise(err)
                    _path_pop()
                    const_ind += 1
                _path_trunc(1)
                #
                # 6.3) transfer any additional constraint(s) to the local const dict
                if Comp._const:
                    # The is needed to transfer the additional constraints
                    # into a dict with a single key 'const', in order to comply
                    # with the way pathes are handled into _parse_const() methods
                    const[ident] = {}
                    const[ident]['const'] = Comp._const
                # 
                # 6.4) transfer any new reference(s) from Comp to the local object
                if Comp._ref:
                    self._ref.update( Comp._ref )
                #
                # 6.5) restore original constraints and references from the Component
                Comp._const = CompConst
                Comp._ref = CompRef
                #
                # 6.6) handle PRESENT / ABSENT / OPTIONAL keyword
                if not comp:
                    potent.append(ident)
                elif comp[:7] == 'PRESENT':
                    present.append(ident)
                    comp = comp[7:].strip()
                elif comp[:6] == 'ABSENT':
                    absent.append(ident)
                    comp = comp[6:].strip()
                elif comp[:8] == 'OPTIONAL':
                    opt.append(ident)
                    comp = comp[8:].strip()
                if comp:
                    raise(ASN1ProcTextErr(
                          '{0}: invalid text in WITH COMPONENTS constraint, {1}'\
                          .format(self.fullname(), comp)))
            done.append(ident)
        #
        # 7) determine the PRESENCE / ABSENCE context depending of the 
        # constructed type
        if self._type == TYPE_CHOICE:
            if opt:
                raise(ASN1ProcTextErr(
                      '{0}: invalid OPTIONAL marker for components, {1}'\
                      .format(self.fullname(), opt))) 
            self.__parse_const_withcomps_choice(const,
                                                present, potent, absent)
        else:
            # SEQUENCE, SET
            self.__parse_const_withcomps_seq(const, partial,
                                             present, potent, absent, done)
        #
        # 8) ensure no more text exists
        if rest:
            raise(ASN1ProcTextErr('{0}: remaining text for WITH COMPONENTS constraint, {1}'\
              .format(self.fullname(), rest)))
    
    def __parse_const_withcomps_choice(self, const, present, potent, absent):
        if len(present) > 1:
            raise(ASN1ProcTextErr(
                  '{0}: invalid multiple PRESENT components, {1}'\
                  .format(self.fullname(), present)))
        elif len(present) == 1:
            const['_pre'].append(present[0])
            # all other components must be marked ABSENT
            for comp_name in self.get_cont():
                if comp_name != present[0]:
                    const['_abs'].append(comp_name)
        elif potent:
            # all other components must be marked ABSENT
            for comp_name in self.get_cont():
                if comp_name not in potent:
                    const['_abs'].append(comp_name)
        elif absent:
            for comp_name in self.get_cont():
                if comp_name in absent:
                    const['_abs'].append(comp_name)
    
    def __parse_const_withcomps_seq(self, const, partial,
                                          present, potent, absent, done):
        cont = self.get_cont()
        if self._type in (TYPE_SEQ, TYPE_REAL, TYPE_EXT, TYPE_EMB_PDV, TYPE_CHAR_STR):
            # ensure the correct order of components has been respected
            idents = list(cont.keys())
            ind_prev = -1
            for ident in done:
                ind = idents.index(ident)
                if ind < ind_prev:
                    raise(ASN1ProcTextErr(
                          '{0}: invalid order of components in WITH COMPONENTS'\
                          .format(self.fullname())))
                else:
                    ind_prev = ind
        if not partial:
            # ensure all mandatory components have been constrained
            if not all([ident in done for ident in self.get_root_mand()]):
                raise(ASN1ProcTextErr(
                      '{0}: missing mandatory components in WITH COMPONENTS'\
                      .format(self.fullname())))
            for ident in self.get_root_opt():
                # all OPTIONAL / DEFAULT components not listed in done are 
                # considered ABSENT
                Comp = cont[ident]
                if ident not in done:
                    const['_abs'].append(ident)
                # all OPTIONAL / DEFAULT components listed in potent are 
                # considered PRESENT
                if ident in potent:
                    const['_pre'].append(ident)
        for ident in present:
            if cont[ident].is_opt():
                const['_pre'].append(ident)
        for ident in absent:
            if cont[ident]._flag is not None and \
            (FLAG_OPT not in cont[ident]._flag or FLAG_DEF in cont[ident]._flag):
                raise(ASN1ProcTextErr('{0}: invalid ABSENT component, {1}'\
                      .format(self.fullname(), ident)))
            else:
                const['_abs'].append(ident)
    
    def _parse_const_regexp(self, const):
        const_index = len(self._const)
        self._const.append(const)
        const['type'] = CONST_REGEXP
        const['keys'] = []
        # TODO
        asnlog('INF: {0}.{1}, unprocessed PATTERN constraint'\
               .format(GLOBAL.COMP['NS']['mod'], self.fullname()))
    
    def _parse_const_property(self, const):
        const_index = len(self._const)
        self._const.append(const)
        const['type'] = CONST_PROPERTY
        const['keys'] = []
        # TODO
        asnlog('INF: {0}.{1}, unprocessed SETTINGS constraint'\
               .format(GLOBAL.COMP['NS']['mod'], self.fullname()))
    
    def _parse_const_containing(self, const):
        const_index = len(self._const)
        self._const.append(const)
        const['type'] = CONST_CONTAINING
        const['keys'] = ['obj', 'enc']
        const['obj'] = None
        const['enc'] = None
        # content of the constraint contain an unnamed ASN.1 object definition
        #
        # 1) extract potential encoding textual directive and object textual
        # description
        m = re.search('ENCODED BY', const['text'])
        if m:
            text_obj = const['text'][10:m.start()].strip()
            text_enc = const['text'][m.end():].strip()
            # 2) create a proxy OID object that will parse the encoding value
            ObjProxy = ASN1Obj(name='_enc_{0}'.format(self._name),
                               mode=MODE_VALUE,
                               type=TYPE_OID)
            #
            _path_ext(['const', const_index, 'enc'])
            _path_stack(['val'])
            ObjProxy.parse_value(text_enc)
            assert( ObjProxy._val is not None )
            _path_pop()
            _path_trunc(2)
            #
            # 3) transfer the parsed OID value from ObjProxy to self
            const['enc'] = ObjProxy._val
            #
            # 4) transfer references from ObjProxy to self
            if ObjProxy._ref:
                self._ref.update( ObjProxy._ref )
        else:
            text_obj = const['text'][10:].strip()
        #
        # 5) create an object and parse its textual definition
        # CONTAINING objects may need to reference the parent of self
        Obj = ASN1Obj(name='_cont_{0}'.format(self._name),
                      mode=MODE_TYPE,
                      parent=self._parent)
        Obj._text_def = text_obj
        const['obj'] = Obj
        #
        _path_ext(['const', const_index, 'obj'])
        _path_stack([])
        rest = Obj.parse_def(text_obj)
        _path_pop()
        _path_trunc(3)
        #
        if rest:
            raise(ASN1ProcTextErr(
                  '{0}, CONTAINING constraint: remaining textual definition, {1}'\
                  .format(self.fullname(), rest)))
        const['obj'] = Obj.resolve()
        #
        # 3) copy references from Obj in self
        if Obj._ref:
            self._ref.update( Obj._ref )
    
    def _parse_const_encodeby(self, const):
        const_index = len(self._const)
        self._const.append(const)
        const['type'] = CONST_ENCODEBY
        const['keys'] = ['enc']
        const['enc'] = None
        # TODO
        asnlog('INF: {0}.{1}, unprocessed ENCODE BY constraint'\
               .format(GLOBAL.COMP['NS']['mod'], self.fullname()))
    
    def _parse_const_userconst(self, const):
        const_index = len(self._const)
        self._const.append(const)
        const['type'] = CONST_CONSTRAIN_BY
        const['keys'] = ['user', 'exc']
        const['user'] = None
        const['exc'] = None
        # TODO
        asnlog('INF: {0}.{1}, unprocessed CONSTRAINED BY constraint'\
               .format(GLOBAL.COMP['NS']['mod'], self.fullname()))
    
    
    #--------------------------------------------------------------------------#
    # ASN.1 syntactic parser for values
    #--------------------------------------------------------------------------#
    
    def parse_value(self, text):
        """
        parses the text corresponding to an ASN.1 value for self and put the 
        result in the current last path (GLOBAL.COMP['NS']['path'][-1])
        """
        if self._type in self._PARSE_VALUE_DISPATCH:
            return getattr(self, self._PARSE_VALUE_DISPATCH[self._type])(text)
        else:
            raise(ASN1ObjErr('{0}: undefined type, {1}'\
                  .format(self.fullname(), self._type)))
    
    def _parse_value_ref(self, text, type_expected=None):
        # when text, the textual value, is a reference to a formal identifier or 
        # a global identifier
        # type_expected: None or TYPE_* or list of TYPE_*
        #
        # 0) get identifier
        m = SYNT_RE_IDENT.match(text)
        if not m:
            m = SYNT_RE_IDENTEXT.match(text)
            if not m:
                raise(ASN1ProcTextErr('{0}: invalid value reference for {1}, {2}'\
                      .format(self.fullname(), self._type, text)))
            else:
                # get the ref to the external module and identifier
                valmod = m.group(2)
                ident  = m.group(3)
        else:
            valmod = None
            ident  = m.group(1)
        #
        # 1) get remaining text and potential formal param
        text  = text[m.end():].strip()
        param = GLOBAL.COMP['NS']['par']
        #
        # 2) identifier is a reference to a local formal parameter
        if param and ident in param and valmod is None:
            Gov = param[ident]['gov']
            idents = [ident]
            #
            # 2.1) in case the formal param is a CLASS value, the text can reference
            # fields (iteratively) within this CLASS value
            # myParamValue {MYCLASS:myClass} ::= myClass.&myValue.&mySubValue
            while text[:2] == '.&':
                # ensure the parameter governor (and inner field, when iterating)
                # is a CLASS value
                self.__parse_value_ref_typechk(Gov,
                                               '.&'.join(idents),
                                               TYPE_CLASS)
                # get the field name to be selected within the param gov
                text = text[2:]
                m = SYNT_RE_WORD.match(text)
                if not m:
                    raise(ASN1ProcTextErr(
                          '{0}: invalid value field reference within parameter {1}, {2}'\
                          .format(self.fullname(), '.&'.join(idents), text)))
                idents.append( m.group(1) )
                text = text[m.end():].strip()
                try:
                    Gov = Gov.get_cont()[idents[-1]]
                except KeyError:
                    raise(ASN1ProcTextErr(
                          '{0}: undefined value field reference within parameter {1}, {2}'\
                          .format(self.fullname(), '.&'.join(idents[:-1]), idents[-1])))
            #
            # 2.2) ensure the parameter gov has the same type as self
            self.__parse_value_ref_typechk(Gov,
                                           '.&'.join(idents),
                                           type_expected)
            # 
            # 2.3) build the path selected in the called reference in case of 
            # CLASS internal field selection
            ced_path = []
            if len(idents) > 1:
                ced_path.extend(idents[1:])
            #
            # 2.4) create a reference for the value
            ref = ASN1RefValue(ASN1RefParam(ident), ced_path)
            #
            # 2.5) set the ref as the value
            self.select_set(_path_cur(), ref)
            #
            # 2.6) update the list of the parameter referrers with a copy of the
            # current path
            param[ident]['ref'].append( _path_root()[:] )
        #
        # 3) identifier is a reference to a global identifier
        else:
            # 3.1) get the module and value object from GLOBAL
            if valmod is None:
                try:
                    valmod = GLOBAL.COMP['NS']['obj'][ident]
                except KeyError:
                    raise(ASN1ProcTextErr('{0}: value {1}, undefined'\
                          .format(self.fullname(), ident)))
            try:
                valobj = get_asnobj(valmod, ident)
            except ASN1Err as Err:
                raise(ASN1ProcTextErr('{0}: {1}'\
                          .format(self.fullname(), Err)))
            if valobj._val is None:
                # value object not yet compiled
                raise(ASN1ProcLinkErr('{0}: value {1}'\
                      .format(self.fullname(), ident)))
            #
            # 3.2) check if valobj is a parameterized value
            if valobj._param:
                #
                # 3.2.1) rebuild the list of formal parameters
                self._params_form = list(valobj._param.values())
                #
                # 3.2.2) bind valobj into self
                # and duplicate the parameterized part of valobj
                path_cur = _path_cur()
                self.select_set(path_cur, valobj._val)
                for param in self._params_form:
                    for path in param['ref']:
                        assert( path[0] == 'val' )
                        path = path_cur + path[1:]
                        self.select_set(path[0:1],
                                        _get_path_copy(self, path))
                #
                # 3.2.3) do the parameterization
                text = self._parameterize(text)
                #
                # 3.2.4) some clean-up
                del self._params_form
            #
            # 3.3) valobj is just a referenced value
            else:
                val = valobj._val
                #
                # 3.3.1) in case the text is a CLASS value, the text can reference
                # fields (iteratively) within this CLASS value
                # myValue ::= myClass.&myValue.&mySubValue
                idents = [ident]
                while text[:2] == '.&':
                    # ensure the selected global object (and inner field, when iterating)
                    # is a CLASS value
                    self.__parse_value_ref_typechk(valobj,
                                                   '.&'.join(idents),
                                                   TYPE_CLASS)
                    # get the field name to be selected within valobj
                    text = text[2:]
                    m = SYNT_RE_WORD.match(text)
                    if not m:
                        raise(ASN1ProcTextErr(
                              '{0}: invalid value field reference within {2}, {3}'\
                              .format(self.fullname(), ident, text)))
                    idents.append( m.group(1) )
                    text = text[m.end():].strip()
                    try:
                        valobj = valobj.get_cont()[idents[-1]]
                        val = val[idents[-1]]
                    except KeyError:
                        raise(ASN1ProcTextErr(
                              '{0}: undefined value field reference within {2}, {3}'\
                              .format(self.fullname(), ident, ident_field)))
                #
                # 3.3.2) ensure valobj has the same type as self
                self.__parse_value_ref_typechk(valobj,
                                               '.&'.join(idents),
                                               type_expected)
                #
                self.select_set(_path_cur(), val)
                #
                # 3.3.3) keep track of the value reference
                if len(idents) > 1:
                    self._ref.add( ASN1RefValue((valmod, ident), idents[1:]) )
                else:
                    self._ref.add( ASN1RefValue((valmod, ident)) )
        #
        return text
    
    def __parse_value_ref_typechk(self, obj, ident, type_exp=None):
        if type_exp is None:
            type_exp = self._type
        if obj._mode != MODE_VALUE:
            raise(ASN1ProcTextErr(
                  '{0}: value identifier {1}, mode mismatch, {2} instead of VALUE'\
                  .format(self.fullname(), ident, obj._mode)))
        if type_exp == TYPE_ANY and obj._type != type_exp:
            # ASN.1 1988 old-school construction
            raise(ASN1NotSuppErr(
                  '{0}: ASN.1 1988 ANY type assigned with another type\'s value, '\
                  '{1} of type {2} and value {3}'\
                  .format(self.fullname(), ident, obj._type, obj._val)))
        elif (isinstance(type_exp, str_types) and obj._type != type_exp) or \
        (isinstance(type_exp, (tuple, list)) and obj._type not in type_exp):
            raise(ASN1ProcTextErr(
                  '{0}: value identifier {1}, type mismatch, {2} instead of {3}'\
                  .format(self.fullname(), ident, obj._type, type_exp)))
    
    def _parse_value_null(self, text):
        """
        parses the NULL value
        
        value is the integer 0
        """
        # test NULL ::= NULL
        m = re.match('(?:^|\s{1})(NULL)', text)
        if not m:
            # reference to a local formal parameter identifier 
            # or a global identifier
            return self._parse_value_ref(text)
        else:
            # raw NULL value
            self.select_set(_path_cur(), 0)
            return text[m.end():].strip()
    
    def _parse_value_bool(self, text):
        """
        parses the BOOLEAN value
        
        value is a boolean (Python bool)
        """
        # test BOOLEAN ::= TRUE (/ FALSE)
        m = re.match('(?:^|\s{1})(TRUE|FALSE)', text)
        if not m:
            # reference to a local formal parameter identifier 
            # or a global identifier
            return self._parse_value_ref(text)
        else:
            # raw BOOLEAN value
            self.select_set(_path_cur(),
                            self._VALUE_BOOL[m.group(1)])
            return text[m.end():].strip()
    
    def _parse_value_int(self, text):
        """
        parses the INTEGER value
        
        value is an integer (Python int)
        """
        # positive, null or negative integer
        # test INTEGER ::= -10 (or 0 or 100 or ...)
        m = SYNT_RE_INTVAL.match(text)
        if not m:
            m = SYNT_RE_CLASSVALREF.match(text)
            if m:
                # CLASS value field
                # reference to a local formal parameter identifier
                # or a global identifier
                return self._parse_value_ref(text)
            m = SYNT_RE_IDENTEXT.match(text)
            if m:
                # reference to an external module value
                return self._parse_value_ref(text)
            m = SYNT_RE_IDENT.match(text)
            if m:
                ref = m.group(1)
                # check if some content identifier are defined
                cont = self.get_cont()
                if cont is not None and ref in cont:
                    self.select_set(_path_cur(), cont[ref])
                    return text[m.end():].strip()
                else:
                    # reference to a local formal parameter identifier 
                    # or a global identifier
                    return self._parse_value_ref(text)
            else:
                raise(ASN1ProcTextErr('{0}: invalid value for INTEGER, {1}'\
                      .format(self.fullname(), text)))
        else:
            # raw INTEGER value
            self.select_set(_path_cur(), int(m.group(1)))
            return text[m.end():].strip()
    
    def _parse_value_real(self, text):
        """
        parses the REAL value
        
        value is a list of 3 integers, with the integral, decimal and exponent
        parts
        """
        m = SYNT_RE_REALNUM.match(text)
        if not m:
            m = SYNT_RE_REALSEQ.match(text)
            if not m:
                m = SYNT_RE_REALSPEC.match(text)
                if m:
                    # special value
                    self.select_set(_path_cur(),
                                         self._VALUE_REAL[m.group(1)])
                    return text[m.end():].strip()
                else:
                    # reference to a local formal parameter identifier 
                    # or a global identifier
                    return self._parse_value_ref(text)
            else:
                # sequence representation
                self.select_set(_path_cur(),
                                     list(map(int, m.groups())))
                return text[m.end():].strip()
        else:
            # real representation
            self.__parse_value_realsci(m.groups())
            return text[m.end():].strip()
    
    def __parse_value_realsci(self, val):
        # integral, decimal, base 10 exponent parts
        i, d, e = val
        if not d:
            if not e:
                ret = [int(i), 10, 0]
            else:
                ret = [int(i), 10, int(e)]
        else:
            # decimal part present
            # need to adjust the base 10 exponent
            if not e:
                e = 0
            else:
                e = int(e)
            e -= len(d)
            ret = [int(i+d), 10, e]
        self.select_set(_path_cur(), ret)
    
    def _parse_value_enum(self, text):
        """
        parses the ENUMERATED value
        
        value is a string (Python str)
        """
        m = SYNT_RE_IDENT.match(text)
        if not m:
            raise(ASN1ProcTextErr('{0}: invalid ENUMERATED value, {1}'\
                  .format(self.fullname(), text)))
        name = m.group(1)
        cont = self.get_cont()
        if name not in cont:
            raise(ASN1ProcTextErr('{0}: undefined ENUMERATED value, {1}'\
                  .format(self.fullname(), name)))
        self.select_set(_path_cur(), name)
        return text[m.end():].strip()
    
    def _parse_value_bitstr(self, text):
        """
        parses the BIT STRING value
        
        value is a list of 2 integers, with the integral value and length in bits
        """
        # bstring, hstring, set of named offsets between curly-brackets, or
        # reference to another BIT STRING value
        m = SYNT_RE_BSTRING.match(text)
        if m:
            # bstring
            bs = re.subn('\s{1,}', '', m.group(1))[0]
            if not bs:
                # null length bit string
                val = [0, 0]
            else:
                val = [int(bs, 2), len(bs)]
            self.select_set(_path_cur(), val)
            return text[m.end():].strip()
        #
        m = SYNT_RE_HSTRING.match(text)
        if m:
            # hstring
            hs = re.subn('\s{1,}', '', m.group(1))[0]
            if not hs:
                # null length bit string
                val = [0, 0]
            else:
                val = [int(hs, 16), 4*len(hs)]
            self.select_set(_path_cur(), val)
            return text[m.end():].strip()
        #
        m = SYNT_RE_IDENT.match(text)
        if m:
            # reference to a local formal parameter identifier 
            # or a global identifier
            return self._parse_value_ref(text)
        m = SYNT_RE_IDENTEXT.match(text)
        if m:
            # reference to an external module identifier
            return self._parse_value_ref(text)
        #
        if text[0] == '{':
            # set of named offsets
            rest, text = extract_curlybrack(text)
            if text is None:
                raise(ASN1ProcTextErr('{0}: invalid BIT STRING value, {1}'\
                      .format(self.fullname(), rest)))
            if not text:
                # empty set of offsets
                self.__parse_value_bitstr_offsets(None)
                return rest
            #
            named_offs = map(strip, text.split(','))
            # reference to local content identifiers
            cont = self.get_cont()
            # references to be put in a python set
            set_no = set()
            for no in named_offs:
                m = SYNT_RE_IDENT.match(no)
                if not m:
                    raise(ASN1ProcTextErr(
                          '{0}: invalid BIT STRING named offset, {1}'\
                          .format(self.fullname(), no)))
                ref = m.group(1)
                if cont is None or ref not in cont:
                    raise(ASN1ProcTextErr(
                          '{0}: undefined BIT STRING named offset, {1}'\
                          .format(self.fullname(), ref)))
                off = cont[ref]
                set_no.add( off )
                rest_no = no[m.end():].strip()
                if rest_no:
                    raise(ASN1ProcTextErr(
                          '{0}: remaining named offset text, {1}'\
                          .format(self.fullname(), rest_no)))
            self.__parse_value_bitstr_offsets(set_no)
            return rest
        #
        raise(ASN1ProcTextErr(
              '{0}: invalid BIT STRING value, {1}'\
              .format(self.fullname(), text)))
        
    def __parse_value_bitstr_offsets(self, val):
        # val: set of offsets
        # returns the integral value and the minimum number of bits 
        # for the set of offsets
        if val is None:
            # null length bit string
            val = [0, 0]
        else:
            moff = max(val)
            val  = [sum([1<<(moff-i) for i in val]), 1+moff]
        # take potential SIZE constraint into account
        Consts_sz = [C for C in self.get_const() if C['type'] == CONST_SIZE]
        if Consts_sz:
            # size is a set of INTEGER values
            Const_sz = reduce_setdicts(Consts_sz)
            # check if there is a root lower bound, without defined extension
            if Const_sz.root and Const_sz.ext is None:
                lb = Const_sz.root[0]
                # lb can be a single int value or an ASN1RangeInt
                if hasattr(lb, 'lb'):
                    lb = lb.lb
                if lb is None:
                    lb = 0
                assert( isinstance(lb, integer_types) and lb >= 0 )
                if val[1] < lb:
                    diff = lb - val[1]
                    val = [val[0] << diff, val[1] + diff]
        self.select_set(_path_cur(), val)
    
    def _parse_value_octstr(self, text):
        """
        parses the OCTET STRING value
        
        value is a bytestream (Python bytes)
        """
        m = SYNT_RE_BSTRING.match(text)
        if m:
            # bstring
            bs = re.subn('\s{1,}', '', m.group(1))[0]
            if not bs:
                # null length octet string
                val = b''
            else:
                val = uint_to_bytes(int(bs, 2), len(bs))
            self.select_set(_path_cur(), val)
            return text[m.end():].strip()
        else:
            m = SYNT_RE_HSTRING.match(text)
            if m:
                # hstring
                hs = re.subn('\s{1,}', '', m.group(1))[0]
                if len(hs)%2:
                    val = unhexlify(hs + '0')
                else:
                    val = unhexlify(hs)
                self.select_set(_path_cur(), val)
                return text[m.end():].strip()
            else:
                # reference to a local formal parameter identifier 
                # or a global identifier of another BIT STRING value
                return self._parse_value_ref(text)
    
    def _parse_value_oid(self, text):
        """
        parses the OBJECT IDENTIFIER or RELATIVE-OID value
        
        value is a list of integers
        """
        # id-dsa OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) 
        #                                x9-57(10040) x9algorithm(4) 1 }
        rest, text = extract_curlybrack(text)
        if text is None:
            # reference to a local formal parameter identifier 
            # or a global identifier for the whole OID
            return self._parse_value_ref(rest)
        elif text == '':
            raise(ASN1ProcTextErr('{0}: invalid empty OBJECT IDENTIFIER value'\
                  .format(self.fullname())))
        else:
            val = []
            self.select_set(_path_cur(), val)
            m = SYNT_RE_OID_COMP.match(text)
            while m:
                if m.group(1):
                    # NumberForm
                    val.append(int(m.group(1)))
                elif m.group(4):
                    # NameAndNumberForm
                    val.append(int(m.group(4)))
                elif m.group(3):
                    # NameForm
                    ident = tuple(val) + (m.group(3), )
                    if self._type == TYPE_OID and ident in ASN1_OID_ISO:
                        val.append(int(ASN1_OID_ISO[ident]))
                    else:
                        # reference to another OID or integer as component of
                        # our current OID value
                        self.__parse_value_oid_ref(m.group(3), val)
                text = text[m.end():].strip()
                m = SYNT_RE_OID_COMP.match(text)
            if text:
                raise(ASN1ProcTextErr('{0}: invalid remaining text in {1} value, {2}'\
                      .format(self.fullname(), self._type, text)))
        return rest
    
    def __parse_value_oid_ref(self, ident, val):
        # when ident is a reference to a local formal parameter identifier 
        # or a global identifier for a component of an OID
        param = GLOBAL.COMP['NS']['par']
        if param and ident in param:
            #
            # 1) reference to a local parameter
            # type verification
            self.__parse_value_ref_typechk(param[ident]['gov'],
                                           ident,
                                           [self._type, TYPE_INT])
            #
            # append a reference for the value
            val.append(ASN1RefValue(ASN1RefParam(ident)))
            # update the list of the parameter referrers
            param[ident]['ref'].append( _path_root() + [len(val)-1] )
        #
        else:
            #
            # 2) reference to a global identifier
            try:
                valmod = GLOBAL.COMP['NS']['obj'][ident]
            except KeyError:
                raise(ASN1ProcTextErr('{0}: OID reference {1}, undefined'\
                      .format(self.fullname(), ident)))
            try:
                valobj = get_asnobj(valmod, ident)
            except ASN1Err as Err:
                raise(ASN1ProcTextErr('{0}: {1}'\
                          .format(self.fullname(), Err)))
            if valobj._val is None:
                raise(ASN1ProcLinkErr('{0}: OID value {1}'\
                      .format(self.fullname(), ident)))
            self.__parse_value_ref_typechk(valobj,
                                           ident,
                                           [self._type, TYPE_INT])
            if valobj._type == TYPE_INT:
                val.append(valobj._val)
            else:
                val.extend(valobj._val)
            # 
            # 3) keep track of the reference
            self._ref.add( ASN1RefValue((valmod, ident)) )
    
    def _parse_value_str(self, text):
        """
        parses any *String object value
        
        value is a string (Python str)
        """
        m = SYNT_RE_IDENT.match(text)
        if m:
            return self._parse_value_ref(text)
            #return self._parse_value_ref(text, type_expected=TYPE_STRINGS)
        m = SYNT_RE_IDENTEXT.match(text)
        if m:
            # reference to an external module value
            return self._parse_value_ref(text)
            #return self._parse_value_ref(text, type_expected=TYPE_STRINGS)
        else:
            text, val = extract_charstr(text)
            if val is None:
                raise(ASN1ProcTextErr('{0}: invalid {1} value, {2}'\
                      .format(self.fullname(), self._type, text)))
            self.select_set(_path_cur(), val)
        return text
    
    def _parse_value_str_univ(self, text):
        """
        parses the UniversalString object value
        
        value is a string (Python str) or code-point (4 uint8 tuples)
        """
        try:
            text = self._parse_value_str(text)
        except ASN1ProcTextErr:
            # try with the code-point notation {W, X, Y, Z}
            m = SYNT_RE_UNIVSTR.match(text)
            if m:
                # convert to a std Python str
                try:
                    val = pack('>BBBB', *map(int, m.groups())).decode('utf-32-be')
                except Exception:
                    raise(ASN1ProcTextErr('{0}: invalid UniversalString value, {2}'\
                          .format(self.fullname(), text)))
                else:
                    self.select_set(_path_cur(), val)
                    return text[m.end():].strip()
            else:
                raise(ASN1ProcTextErr('{0}: invalid UniversalString value, {2}'\
                      .format(self.fullname(), text)))
        else:
            return text
    
    def _parse_value_timeutc(self, text):
        """
        parses the UTCTime value
        
        value is a tuple of length 7, with str (digits) or None
        """
        # (AA, MM, DD, HH, MM, [SS,] Z)
        m = SYNT_RE_TIMEUTC.match(text)
        if m:
            self.select_set(_path_cur(), m.groups())
            return text[m.end():].strip()
        else:
            # reference to a local formal parameter identifier 
            # or a global identifier of another UTCTime value
            return self._parse_value_ref(text)
    
    def _parse_value_timegen(self, text):
        """
        parses the GeneralizedTime value
        
        value is a tuple of length 8, with str (digits) or None
        """
        # (AAAA, MM, DD, HH, [MM, [SS,]] [{.,}F*,] [Z])
        m = SYNT_RE_TIMEGENE.match(text)
        if m:
            self.select_set(_path_cur(), m.groups())
            return text[m.end():].strip()
        else:
            # reference to a local formal parameter identifier 
            # or a global identifier of another GeneralizedTime value
            return self._parse_value_ref(text)
    
    def _parse_value_choice(self, text):
        """
        parses the CHOICE value
        
        value is a list of length 2, with the chosen component identifier and
        single value
        """
        # identifier: ASN1Obj single value
        #
        # 1) get the identifier and textual value
        m = SYNT_RE_IDENT.match(text)
        if not m:
            m = SYNT_RE_IDENTEXT.match(text)
            if m:
                # reference to an external module value
                return self._parse_value_ref(text)
            else:
                raise(ASN1ProcTextErr('{0}: invalid CHOICE value, {1}'\
                      .format(self.fullname(), text)))
        name = m.group(1)
        cont = self.get_cont()
        rest = text[m.end():].strip()
        if rest[0:1] != ':':
            # if we only have an identifier
            return self._parse_value_ref(text)
        elif name not in cont:
            raise(ASN1ProcTextErr('{0}: undefined CHOICE identifier, {1}'\
                  .format(self.fullname(), name)))
        text = rest[1:].strip()
        #
        # 2) prepare the container for receiving the value of the chosen object
        # with the ident of the chosen object in the 1st place
        val = [name, None]
        self.select_set(_path_cur(), val)
        #
        # 3) create a proxy object with the chosen one that will parse the textual value
        ObjProxy = cont[name].copy()
        ObjProxy._ref = set()
        #
        _path_ext([1])
        _path_stack(['val'])
        text = ObjProxy.parse_value(text)
        assert( ObjProxy._val is not None )
        _path_pop()
        _path_trunc(1)
        #
        # 4) transfer the parsed value from ObjProxy to self
        val[1] = ObjProxy._val
        #
        # 5) transfer references from ObjProxy to self
        if ObjProxy._ref:
            self._ref.update( ObjProxy._ref )
        #
        return text
    
    def _parse_value_seq(self, text):
        """
        parses the SEQUENCE value
        
        value is an ASN1Dict made of component identifier, single value
        """
        # 1) extract all identifiers / values between "{" and "}" 
        # and coma-separated
        rest, values = extract_multi(text)
        if values is None:
            return self._parse_value_ref(text)
        values = list(values)
        #
        # 2) get the SEQUENCE root / ext / optional content and identifiers
        cont = self.get_cont()
        root_opt = self.get_root_opt()
        ext = self.get_ext()
        ext_ident = self.get_ext_ident()
        ext_group = self.get_ext_group()
        idents = list(cont.keys())
        #
        # 3) prepare a container for receiving all values
        vals = ASN1Dict()
        self.select_set(_path_cur(), vals)
        #
        # 4) parse all values according to the root and extended content
        # iterate over all content identifiers and provided values
        ind_cont = 0
        ind_values = 0
        while ind_cont < len(cont) and ind_values < len(values):
            ident = idents[ind_cont]
            value = values[ind_values]
            m = re.match(ident, value)
            if not m:
                if ident in root_opt:
                    # 4.1) optional / default value component, value not present
                    ind_cont += 1
                elif ext and ident in ext:
                    # 4.2) extended component, value not present
                    # if ident is in a group of extended components,
                    # jump over all idents in the same group
                    if ident in ext_ident:
                        gid = ext_ident[ident]
                        ind_cont += len(ext_group[gid])
                    else:
                        ind_cont += 1
                else:
                    raise(ASN1ProcTextErr('{0}, component {1}: invalid SEQUENCE value, {2}'\
                          .format(self.fullname(), ident, value)))
            else:
                # 4.3) value present
                value = value[m.end():].strip()
                vals[ident] = None
                #
                # 4.4) create a proxy object with the selected field that will parse 
                # the textual value
                ObjProxy = cont[ident].copy()
                ObjProxy._ref = set()
                #
                _path_ext([ident])
                _path_stack(['val'])
                restval = ObjProxy.parse_value(value)
                assert( ObjProxy._val is not None )
                _path_pop()
                _path_trunc(1)
                #
                if restval:
                    raise(ASN1ProcTextErr(
                          '{0}, component {1}: remaining textual value definition, {2}'\
                          .format(self.fullname(), ident, restval)))
                #
                # 4.5) transfer the parsed value from ObjProxy to self
                vals[ident] = ObjProxy._val
                #
                # 4.6) transfer references from ObjProxy to self
                if ObjProxy._ref:
                    self._ref.update( ObjProxy._ref )
                #
                ind_cont += 1
                ind_values += 1
        #
        # 5) check if any value remains, that would be invalid
        if values[ind_values:]:
            raise(ASN1ProcTextErr('{0}: undefined SEQUENCE value, {1}'\
                  .format(self.fullname(), values[ind_values:])))
        # check if the provided value conforms to the optional and extended
        # part of the content
        if not self.is_value_ok(vals):
            raise(ASN1ProcTextErr(
                  '{0}: invalid SEQUENCE value, incorrect non-optional root or grouped extension, {1}'\
                  .format(self.fullname(), values)))
        #
        return rest
    
    def _parse_value_set(self, text):
        """
        parses the SET value
        
        value is an ASN1Dict made of component identifier, single value
        """
        # 1) extract all identifiers / values between "{" and "}" 
        # and coma-separated
        rest, values = extract_multi(text)
        if values is None:
            return self._parse_value_ref(text)
        values = list(values)
        #
        # 2) get the SET content
        cont = self.get_cont()
        #
        # 3) prepare a container for receiving all values
        vals = ASN1Dict()
        self.select_set(_path_cur(), vals)
        #
        # 4) parse all provided values
        for value in values:
            m = SYNT_RE_IDENT.match(value)
            if not m:
                raise(ASN1ProcTextErr('{0}: invalid SET value, {1}'\
                      .format(self.fullname(), value)))
            ident = m.group(1)
            if ident not in cont:
                raise(ASN1ProcTextErr('{0}: invalid SET value identifier, {1}'\
                      .format(self.fullname(), ident)))
            elif ident in vals:
                raise(ASN1ProcTextErr('{0}: duplicated SET value, {1}'\
                      .format(self.fullname(), ident)))
            #
            # 4.1) value present
            value = value[m.end():].strip()
            vals[ident] = None
            #
            # 4.2) create a proxy object with the selected field that will parse the 
            # textual value
            ObjProxy = cont[ident].copy()
            ObjProxy._ref = set()
            #
            _path_ext([ident])
            _path_stack(['val'])
            restval = ObjProxy.parse_value(value)
            assert( ObjProxy._val is not None )
            _path_pop()
            _path_trunc(1)
            #
            if restval:
                raise(ASN1ProcTextErr(
                      '{0}, component {1}: remaining textual value definition, {2}'\
                      .format(self.fullname(), ident, restval)))
            #
            # 4.3) transfer the parsed value from ObjProxy to self
            vals[ident] = ObjProxy._val
            #
            # 4.4) transfer references from ObjProxy to self
            if ObjProxy._ref:
                self._ref.update( ObjProxy._ref )
        #
        # 5) check if the provided value conforms to the optional and extended
        # part of the content
        if not self.is_value_ok(vals):
            raise(ASN1ProcTextErr('{0}: invalid SET value, '\
                  'incorrect non-optional root or grouped extension, {1}'\
                  .format(self.fullname(), values)))
        #
        return rest
    
    def _parse_value_seqof(self, text):
        """
        parses the SEQUENCE OF or SET OF value
        
        value is a list of single values
        """
        # TODO: verify the number of values against any SIZE constraint
        # 1) extract all identifiers / values between "{" and "}" 
        # and coma-separated
        rest, values = extract_multi(text)
        if values is None:
            return self._parse_value_ref(text)
        #
        # 2) create a proxy object with the SEQUENCE OF component that will parse 
        # the textual value
        ObjProxy = self.get_cont().copy()
        ObjProxy._ref = set()
        #
        # 3) prepare a container for receiving all values
        vals = []
        self.select_set(_path_cur(), vals)
        #
        # 4) parse all provided values 
        for value in values:
            #
            # 4.1) use ObjProxy to parse the textual value
            vals.append(None)
            #
            _path_ext([len(vals)-1])
            _path_stack(['val'])
            restval = ObjProxy.parse_value(value)
            assert( ObjProxy._val is not None )
            _path_pop()
            _path_trunc(1)
            #
            if restval:
                raise(ASN1ProcTextErr('{0}: remaining textual value definition, {1}'\
                      .format(self.fullname(), restval)))
            #
            # 4.2) transfer the parsed value from ObjProxy to self
            vals[-1] = ObjProxy._val
            #
            # 4.3) cleanup ObjProxy value
            ObjProxy._val = None
        # 
        # 5) transfer references from ObjProxy to self
        if ObjProxy._ref:
            self._ref.update( ObjProxy._ref )
        #
        return rest
    
    def _parse_value_open(self, text):
        """
        parses the OPEN TYPE value
        
        value is a list of length 2, with an ASN1Obj instance and the 
        corresponding single value
        """
        # ASN1Obj definition: ASN1Obj single value
        #
        # 1) extract the ASN.1 object definition and its value
        colon_offset = search_top_lvl_sep(text, ':')
        if len(colon_offset) == 0:
            return self._parse_value_ref(text)
        # 
        # WNG: in case the OPEN type is a CHOICE, we can have several colons, 
        # this checks is too strong, disabling it
        #elif len(colon_offset) > 1:
        #    raise(ASN1ProcTextErr('{0}: invalid OPEN value, {1}'\
        #          .format(self.fullname(), text)))
        #
        textobj, textval = text[:colon_offset[0]].strip(), \
                           text[1+colon_offset[0]:].strip()
        #
        # 2) setup the container that will receive the value
        val = [None, None]
        self.select_set(_path_cur(), val)
        #
        # 3) parse the object definition and put it in val
        Obj = ASN1Obj(name=self._name, mode=MODE_TYPE)
        Obj._text_def = textobj
        val[0] = Obj
        #
        _path_ext([0])
        _path_stack([])
        rest = Obj.parse_def(textobj)
        _path_pop()
        _path_trunc(1)
        #
        if rest:
            raise(ASN1ProcTextErr('{0}: remaining textual definition, {1}'\
                 .format(self.fullname(), rest)))
        val[0] = Obj.resolve()
        #
        # 5) parse the value according to the object definition and put it in val
        _path_ext([1])
        _path_stack(['val'])
        textval = Obj.parse_value(textval)
        assert( Obj._val is not None )
        _path_pop()
        _path_trunc(1)
        #
        # 6) transfer the parsed value from Obj to self
        val[1] = Obj._val
        Obj._val = None
        #
        # 7) transfer references from Obj to self
        if Obj._ref:
            self._ref.update( Obj._ref )
        #
        return textval
    
    def _parse_value_ext(self, text):
        # TODO
        # would parse an OID first
        # then call the corresponding object within GLOBAL.MOD
        # and finally call Obj.parse_def() on the value text
        raise(ASN1NotSuppErr('{0}: _parse_value_ext()'.format(self.fullname())))
    
    def _parse_value_class(self, text):
        """
        parses the CLASS object value, according to its syntax
        
        value is an ASN1Dict made of {field identifier: single value}
        """
        # 1) extract the value
        text, values = extract_curlybrack(text)
        if values is None:
            return self._parse_value_ref(text)
        #
        # 2) prepare a container for receiving all values
        vals = ASN1Dict()
        self.select_set(_path_cur(), vals)
        #
        # 3) parse the values according to the CLASS definition
        if not self.get_syntax():
            # extract all values according to the content identifiers
            self._parse_value_class_ident(vals, values)
        else:
            # extract all values according to the syntax
            self._parse_value_class_syntax(vals, values)
        #
        # 4) ensure all the required values were provided
        if not self.is_value_ok(vals):
            # ensure all mandatory fields are there
            raise(ASN1ProcTextErr(
                  '{0}: invalid CLASS value, missing non-optional field'\
                  .format(self.fullname(), values)))
        #
        return text
    
    def _parse_value_class_ident(self, vals, text):
        # 1) extract value syntax separated with identifiers and coma
        # split each coma-separated field
        coma_offsets = [-1] + search_top_lvl_sep(text, ',') + [len(text)]
        values = list(map(strip, [text[coma_offsets[i]+1:coma_offsets[i+1]] \
                                  for i in range(len(coma_offsets)-1)]))
        cont = self.get_cont()
        #
        # 2) iterate over each field and parse the associated 'value'
        # can be a value, a set of values, or an object definition
        ind = 0
        for field_name in cont:
            Field = cont[field_name]
            text = values[ind]
            m = re.match('&%s' % field_name, text)
            #
            if not m:
                # 2.1) value not there
                if not Field.is_opt():
                    # field is not optional
                    raise(ASN1ProcTextErr('{0}: missing mandatory value for {1}'\
                          .format(self.fullname(), field_name)))
            #
            else:
                # 2.2) value there
                text = text[m.end():].strip()
                text = self.__parse_value_class_field(Field, text, vals)
                if text:
                    raise(ASN1ProcTextErr(
                          '{0}, field {1}: remaining textual definition, {2}'\
                          .format(self.fullname(), field_name, text)))
            #  
            ind += 1 
            if ind > len(values):
                break
    
    def __parse_value_class_field(self, Field, text, vals):
        if Field._mode != MODE_TYPE:
            # 1) Field._mode in (MODE_VALUE, MODE_SET)
            # text is a true value or set of values
            # 1.1) create a proxy object with the selected field that will parse 
            # the textual value(s)
            if isinstance(Field._typeref, ASN1RefClassIntern):
                # Field type is a local reference to a MODE_TYPE object
                try:
                    ObjProxy = vals[Field._typeref.ced_path[-1]].copy()
                except KeyError:
                    raise(ASN1ProcTextErr(
                          '{0}, field {1}: requires OPEN type field {2}, not yet defined'\
                          .format(self.fullname(), Field._name, Field._typeref.ced_path[-1])))
            else:
                ObjProxy = Field.copy()
            ObjProxy._ref = set()
            #
            # 1.2) parse the value or set of values
            _path_ext([Field._name])
            _path_stack(['val'])
            #
            if Field._mode == MODE_VALUE:
                # 1.3) true value 
                text = ObjProxy.parse_value(text)
                assert( ObjProxy._val is not None )
            #
            else:
                # 1.4) set of values
                text, settext = extract_curlybrack(text)
                if settext is None:
                    raise(ASN1ProcTextErr('{0}, field {1}: invalid set, {2}'\
                          .format(self.fullname(), Field._name, text)))
                ObjProxy.parse_set(settext)
                assert( isinstance(ObjProxy._val, dict) )
            #
            _path_pop()
            _path_trunc(1)
            #
            # 1.5) transfer the parsed value from ObjProxy to self
            vals[Field._name] = ObjProxy._val
        #
        else:
            # 2) Field._mode == MODE_TYPE
            # 2.1) value present and is actually an object definition
            Obj = ASN1Obj(name=Field._name, mode=MODE_TYPE)
            Obj._text_def = text
            vals[Field._name] = Obj
            #
            # 2.2) parse object definition
            _path_ext([Field._name])
            _path_stack([])
            text = Obj.parse_def(text)
            _path_pop()
            _path_trunc(1)
            #
            # 2.3) truncate Obj._text_def, this is a bit dirty...
            off = Obj._text_def.find(text)
            assert( off >= 0 )
            Obj._text_def = Obj._text_def[:off].strip()
            #
            vals[Field._name] = Obj.resolve()
            # 
            # 2.4) transfer references from Obj to self
            if Obj._ref:
                self._ref.update( Obj._ref )
        #
        return text.strip()
    
    def _parse_value_class_syntax(self, vals, text):
        #
        # prepare temporary attributes
        self._text    = text
        self._synt    = self.get_syntax()
        self._synt_in = False
        self._depth   = 0
        #
        # this works recursively over SYNTAX groups in self._synt 
        self.__parse_value_class_syntax_grp(vals)
        #
        # clean-up temp attr
        text = self._text
        del self._text, self._synt, self._synt_in, self._depth
        #
        # ensure nothing remains
        if text:
            raise(ASN1ProcTextErr('{0}: remaining textual definition, {1}'\
                  .format(self.fullname(), text)))
    
    def __parse_value_class_syntax_grp(self, vals):
        for grp in self._synt:
            #
            # old-school ASN.1 notation made use of coma between groups...
            if self._text[0:1] == ',':
                self._text = self._text[1:].strip()
            #
            if isinstance(grp, str_types) and grp[0] == '&':
                # 1) field identifier: parse the associated value
                self._synt_in = True
                Field = self.get_cont()[grp[1:]]
                self._text = self.__parse_value_class_field(Field, self._text, vals)
            #
            elif isinstance(grp, str_types) and grp.isupper():
                # 2) SYNTAX word(s) group: check if we have it
                m = re.match(grp, self._text)
                if m:
                    self._synt_in = True
                    self._text = self._text[m.end():].strip()
                elif self._synt_in:
                    # we already started parsing some part of this group
                    raise(ASN1ProcTextErr('{0}: missing SYNTAX keyword, {1}'\
                          .format(self.fullname(), grp)))
                elif self._depth == 0:
                    # this group is a mandatory part of the SYNTAX
                    raise(ASN1ProcTextErr('{0}: missing mandatory SYNTAX keyword, {1}'\
                          .format(self.fullname(), grp)))
                else:
                    # this (optional) group is not present
                    return
            #
            elif isinstance(grp, list):
                # 3) optional inner group, do it recursively
                synt = self._synt
                synt_in = self._synt_in
                self._synt = grp
                self._synt_in = False
                self._depth += 1
                self.__parse_value_class_syntax_grp(vals)
                self._depth -= 1
                self._synt_in = synt_in
                self._synt = synt
            #
            else:
                assert()
    
    #--------------------------------------------------------------------------#
    # ASN.1 syntactic parser for set of values
    #--------------------------------------------------------------------------#
    
    def parse_set(self, text, dom='root'):
        # WNG: textual set of values must come extracted from curlybrackets already
        #
        # a set of values has the following format:
        # root_set, ext_marker , ext_set
        # where each group is optional
        # ext_marker: "...", it is the extension marker
        # root_set, ext_set: one or multiple value(s) and/or set(s) of value(s), 
        # each separated with "|"
        #
        # dom: if 'ext', indicates that every values will be put in the extension
        # domain, including values in the root component
        # 
        # 1) split the textual values
        try:
            text_val = extract_set(text)
        except ASN1Err as err:
            raise(ASN1ProcTextErr('{0}: {1}'.format(self.fullname(), err)))
        #
        # 2) initialize root / ext dict for storing values
        val = self.select(_path_cur())
        if val is None:
            val = {'root': [], 'ext': None}
            self.select_set(_path_cur(), val)
        else:
            # there is already a dict at the current path (e.g. in a const)
            assert( isinstance(val, dict) )
            assert( val['root'] == [] )
            assert( val['ext'] is None )
            pass
            #val['root'], val['ext'] = [], None
        #
        # 3) collect values in the root domain
        if dom == 'ext':
            val['ext'] = []
        for rv in text_val['root']:
            # configure the current path
            self.__parse_set_comp_path_config(val, dom)
            # parse each root component
            if self._type == TYPE_OPEN:
                rest = self.__parse_set_comp_open(rv, val, dom)
            else:
                len_val = len(val[dom])
                rest = self._parse_set_comp(rv, val, dom)
                # in case the set component just parsed is a single value,
                # we need to check for potential deduplication here,
                # because parse_value() is used and cannot implement such control
                if len(val[dom]) >= 2 and len(val[dom]) == len_val + 1 \
                and val[dom][-1] in val[dom][:-1]:
                    if _DEBUG_SET_VAL:
                        asnlog('DBG: {0}.{1}, duplicated value in {2} set: {3}'\
                               .format(GLOBAL.COMP['NS']['mod'], self.fullname(), dom,
                                       repr(val[dom][-1]).replace('\n', '')))
                    del val[dom][-1]
            # 
            self.__parse_set_comp_path_unconfig()
            val = self.__parse_set_track_val(val)
            #
            if rest[:6] == 'EXCEPT':
                asnlog('WNG: {0}.{1}, ignoring set exclusion, {2}'\
                       .format(GLOBAL.COMP['NS']['mod'], self.fullname(), rest))
                rest = ''
            elif rest:
                raise(ASN1ProcTextErr('{0}: remaining textual set definition, {1}'\
                      .format(self.fullname(), rest)))
        #
        # 4) collect values in the extension domain
        if text_val['ext'] is None:
            return
        dom = 'ext'
        if val['ext'] is None:
            val['ext'] = []
        for ev in text_val['ext']:
            # configure the current path
            self.__parse_set_comp_path_config(val, dom)
            # parse each extended component
            if self._type == TYPE_OPEN:
                rest = self.__parse_set_comp_open(ev, val, dom)
            else:
                len_val = len(val[dom])
                rest = self._parse_set_comp(ev, val, dom)
                # in case the set component just parsed is a single value,
                # we need to check for potential deduplication here,
                # because parse_value() is used and cannot implement such control
                if len(val[dom]) >= 2 and len(val[dom]) == len_val + 1 \
                and val[dom][-1] in val[dom][:-1]:
                    if _DEBUG_SET_VAL:
                        asnlog('DBG: {0}.{1}, duplicated value in {2} set: {3}'\
                               .format(GLOBAL.COMP['NS']['mod'], self.fullname(), dom,
                                       repr(val[dom][-1]).replace('\n', '')))
                    del val[dom][-1]
            #
            self.__parse_set_comp_path_unconfig()
            val = self.__parse_set_track_val(val)
            #
            if rest[:6] == 'EXCEPT':
                asnlog('WNG: {0}.{1}, ignoring set exclusion, {2}'\
                       .format(GLOBAL.COMP['NS']['mod'], self.fullname(), rest))
                rest = ''
            elif rest:
                raise(ASN1ProcTextErr('{0}: remaining textual set definition, {1}'\
                      .format(self.fullname(), rest)))
    
    def __parse_set_comp_path_config(self, val, dom):
        _path = [dom, len(val[dom])]
        if GLOBAL.COMP['NS']['setdisp']:
            # if setdisp is set, this means we need to dispatch a set of values
            # inside the current path which is already configured with the right depth,
            # only the domain (root / ext) and indexing needs to be updated
            _path_trunc(2)
            _path_ext(_path)
        else:
            _path_ext(_path)
    
    def __parse_set_comp_path_unconfig(self):
        if not GLOBAL.COMP['NS']['setdisp']:
            _path_trunc(2)
    
    def __parse_set_track_val(self, val):
        # in case of set component parameterization, it can happen that the 
        # root / ext val dict is overwritten with a new dict instance with the 
        # same content
        # here, we ensure that we keep track of the last current version of this
        # root / ext dict
        newval = self.select(_path_cur())
        if id(newval) == id(val):
            return val
        else:
            return newval
    
    def _parse_set_comp(self, text, val, dom):
        # text: textual definition of a single value (or reference to a single value)
        # or reference to a set of values
        # or ASN.1 object defined inline with specific constraints
        #
        # val: root / ext dict for receiving the result when parsing text
        # dom: root / ext domain
        #
        # 0) check if we are using the exclusion format
        if text[:10] == 'ALL EXCEPT':
            val['excl'] = True
            text = text[10:].strip()
        #
        # 1) check if we have an identifier + potential .&[fF]ield selection
        # must not be a ref to a value within an explicit module (ie Mod.value)
        m, n = SYNT_RE_CLASSINSTFIELDREF.match(text), SYNT_RE_IDENTEXT.match(text)
        if m and not n:
            ident_first = m.group(1)
            ident_last  = m.group(2)
            if ident_last is None:
                #
                # 1.1) NULL and BOOLEAN have single values which are 
                # uppercase text, hence need to be processed first
                if ident_first == 'NULL':
                    assert( self._type == TYPE_NULL )
                    return self.parse_value(text)
                elif ident_first in ('FALSE', 'TRUE'):
                    assert( self._type == TYPE_BOOL )
                    return self.parse_value(text)
                elif ident_first in ('MIN', 'MAX', 'MINUS-INFINITY', 'PLUS-INFINITY'):
                    assert( self._type in self._RANGE_TYPE )
                    return self._parse_value_or_range(text)
                else:
                    # continue processing below
                    ident_last = ident_first
            #
            if ident_last[0:1].isupper():
                #
                # 1.2) object textual description is uppercase:
                # this is an ASN.1 object which must define a set of values 
                # compatible with self
                # those values will be dispatched into val
                GLOBAL.COMP['NS']['setdisp'] += 1
                param = GLOBAL.COMP['NS']['par']
                #
                if param and ident_first in param:
                    #
                    # 3.3) reference to a local formal parameter
                    text = text[len(ident_first):].strip()
                    Gov = param[ident_first]['gov']
                    idents = [ident_first]
                    while text[:2] == '.&':
                        #
                        # 3.3.1) parameter can be a CLASS set, and the reference can 
                        # select fields (iteratively) within this CLASS set, e.g.
                        # MyParamSet {MYCLASS:MyClass} ::= MyClass.&MySet.&MySubSet
                        #
                        # ensure the parameter governor (and inner field, when iterating)
                        # is a CLASS set
                        self.__parse_set_ref_typechk(Gov,
                                                     '.&'.join(idents),
                                                     TYPE_CLASS,
                                                     (MODE_VALUE, MODE_SET))
                        # get the field name to be selected within the param gov
                        text = text[2:]
                        m = SYNT_RE_TYPEREF.match(text)
                        if not m:
                            raise(ASN1ProcTextErr(
                                  '{0}: invalid set field reference within parameter {1}, {2}'\
                                  .format(self.fullname(), '.&'.join(idents), text)))
                        idents.append( m.group(1) )
                        text = text[m.end():].strip()
                        try:
                            Gov = Gov.get_cont()[idents[-1]]
                        except KeyError:
                            raise(ASN1ProcTextErr(
                                  '{0}: undefined set field reference within parameter {1}, {2}'\
                                  .format(self.fullname(), '.&'.join(idents[:-1]), idents[-1])))
                    assert( idents[-1] == ident_last )
                    #
                    # 3.3.2) ensure the parameter gov has the same type as self
                    self.__parse_set_ref_typechk(Gov, '.&'.join(idents))
                    # 
                    # 3.3.3) build the path selected in the called reference in case of 
                    # MyClass.&MySet.&MySubSet
                    ced_path = []
                    if len(idents) > 1:
                        ced_path.extend(idents[1:])
                    # 
                    # 3.3.4) create a reference for the set
                    ref = ASN1RefSet(ASN1RefParam(ident_first), ced_path)
                    # set the ref in the val dict with all other values
                    val[dom].append(ref)
                    # 
                    # 3.3.5) add the current path to the referrers of the formal parameter
                    param[ident_first]['ref'].append( _path_root()[:] )
                #
                # 3.4) reference to a MODE_SET object or MODE_TYPE object with constraints
                # or MODE_TYPE object with constraints defined inline
                else:
                    #
                    # 3.4.1) we create an empty object that will parse the definition
                    # It can be a single identifier in case of a simple object reference
                    ObjProxy = ASN1Obj(name='_set_{0}'.format(self._name),
                                       mode=MODE_SET)
                    ObjProxy._text_def = text
                    #
                    # 3.4.2) parse the object definition
                    _path_stack([])
                    text = ObjProxy.parse_def(text)
                    _path_pop()
                    ObjProxy = ObjProxy.resolve()
                    #
                    # 3.4.3) extract its set of values
                    ObjProxy_val = ObjProxy.get_val()
                    if ObjProxy_val is None:
                        # in this case, the set of values is actually defined from 
                        # a value constraint, not from straight values
                        # WNG: this is currently only supported for non-parameterized 
                        # TYPE_INT object
                        objval = ObjProxy.__parse_set_from_const()
                    else:
                        objval = ObjProxy_val
                    #
                    # 3.4.4) dispatch the root / ext values from objval into self within val
                    if objval['root']:
                        self.__parse_set_insert(val[dom], objval['root'], dom)
                    if objval['ext']:
                        if val['ext'] is None:
                            val['ext'] = []
                        self.__parse_set_insert(val['ext'], objval['ext'], 'ext')
                    #
                    # 3.4.5) transfer references from ObjProxy to self
                    # WNG: in case the set is only a typeref, we don't want to
                    # get all ref made by the typeref
                    if ObjProxy_val is not None and ObjProxy._typeref is not None:
                        self._ref.add( ASN1RefSet(ObjProxy._typeref.called,
                                                  ObjProxy._typeref.ced_path) )
                    elif ObjProxy._ref:
                        self._ref.update( ObjProxy._ref )
                #
                GLOBAL.COMP['NS']['setdisp'] -= 1
                return text
        #
        # 4) object textual description is lower case or not an identifier at all:
        # in all remaining cases, this is a single value or a ref to a single value
        if self._type in self._RANGE_TYPE:
            return self._parse_value_or_range(text)
        else:
            return self.parse_value(text)
    
    def __parse_set_ref_typechk(self, obj, ident, type_exp=None, mode_exp=MODE_SET):
        if type_exp is None:
            type_exp = self._type
        if (isinstance(mode_exp, str_types) and obj._mode != mode_exp) or \
        (isinstance(mode_exp, (tuple, list)) and obj._mode not in mode_exp):
            raise(ASN1ProcTextErr(
                  '{0}: set identifier {1}, mode mismatch, {2} instead of {3!r}'\
                  .format(self.fullname(), ident, mode_exp)))
        elif (isinstance(type_exp, str_types) and obj._type != type_exp) or \
        (isinstance(type_exp, (tuple, list)) and obj._type not in type_exp):
            raise(ASN1ProcTextErr(
                  '{0}: set identifier {1}, type mismatch, {2} instead of {3!r}'\
                  .format(self.fullname(), ident, obj._type, type_exp)))
    
    def __parse_set_insert(self, val, objval, dom):
        # In case of parameter pass-through, referrers re-indexing may be required
        # 1) get all values that are an ASN1RefSet referring to a formal parameter
        ref = [v for v in objval if isinstance(v, ASN1RefSet) and \
                                    isinstance(v.called, ASN1RefParam)]
        assert( len(ref) == len(GLOBAL.COMP['NS']['setpar']) )
        #
        # 2) insert all values  1 by 1 from objval into val (self)
        # and rewrite the root / ext domain and indexing into the val set
        for v in objval:
            # deduplicate values within v
            if v not in val:
                val.append(v)
                if v in ref:
                    ind = ref.index(v)
                    GLOBAL.COMP['NS']['setpar'][ind][-2] = dom
                    GLOBAL.COMP['NS']['setpar'][ind][-1] = len(val)-1
        GLOBAL.COMP['NS']['setpar'] = []
    
    def _parse_value_or_range(self, text):
        # check for the range marker ".."
        m = re.search('[^.]\.\.[^.]', text)
        if m:
            if self._type == TYPE_INT:
                ra = ASN1RangeInt()
            elif self._type == TYPE_REAL:
                ra = ASN1RangeReal()
            else:
                assert( self._type in ASN1Range._TYPE_STR )
                ra = ASN1RangeStr()
            # parse the range
            text_lb = text[:1+m.start()].strip()
            text_ub = text[m.end()-1:].strip()
            if text_lb[-1:] == '<':
                lb_incl = False
                text_lb = text_lb[:-1]
            else:
                lb_incl = True
            if text_ub[:1] == '<':
                ub_incl = False
                text_ub = text_ub[1:]
            else:
                ub_incl = True
            self.select_set(_path_cur(), ra)
            # set value to boundaries
            if self._type != TYPE_INT or text_lb != 'MIN':
                # keeps None for lb for TYPE_INT
                _path_ext(['lb'])
                rest = self.parse_value(text_lb)
                _path_trunc(1)
                if rest:
                    raise(ASN1ProcTextErr('{0}: invalid range lower bound, {1}'\
                          .format(self.fullname(), text_lb)))
            if self._type != TYPE_INT or text_ub != 'MAX':
                # keeps None for ub for TYPE_INT
                _path_ext(['ub'])
                text = self.parse_value(text_ub)
                _path_trunc(1)
            elif text_ub == 'MAX':
                text = ''
            # handle boundary inclusion
            if self._type == TYPE_REAL:
                if not lb_incl:
                    ra.lb_incl = False
                if not ub_incl:
                    ra.ub_uncl = False
            else:
                if not lb_incl:
                    # increment lower bound
                    if ra.lb is not None:
                        ra.lb += 1
                if not ub_incl:
                    # decrement higher bound
                    if ra.ub is not None:
                        ra.ub -= 1
        else:
            text = self.parse_value(text)
        #
        return text
    
    def __parse_set_from_const(self):
        # extraction of set of values from constraints of MODE_TYPE object
        # 
        # 1) set extraction from INTEGER constraints
        if self._type == TYPE_INT:
            # we go over all constraints of the object and return a root / ext dict 
            # with integral values
            root, ext = set(), None
            set_int = ASN1Set(d={'root': [ASN1RangeInt(None, None)], 'ext': None})
            consts = self.get_const()
            for const in consts:
                if const['type'] != CONST_VAL:
                    raise(ASN1NotSuppErr('{0}: non value constraint for integer-based type, {1!r}'\
                          .format(self.fullname(), const)))
                elif const['excl']:
                    # need to exclude the given values
                    for v in const['root']:
                        if isinstance(v, ASN1RangeInt):
                            # unsupported
                            raise(ASN1NotSuppErr('{0}: unable to exclude range, {1}'\
                                  .format(self.fullname(), v)))
                        else:
                            set_int.excl_val(v)
                else:
                    set_loc = ASN1Set(d={'root': const['root'], 'ext': const['ext']})
                    set_int = set_int.intersect(set_loc)
            return {'root': set_int.root, 'ext': set_int.ext}
        #
        # 2) otherwise unsupported, but stays nice, do not raise...
        else:
            asnlog('WNG: {0}.{1}, unprocessed set of values from constraint, {1}'\
                   .format(GLOBAL.COMP['NS']['mod'], self.fullname(), self._text_def))
            return {'root': [], 'ext': None}
    
    def __parse_set_comp_open(self, text, val, dom):
        # specific case for OPEN TYPE: an ASN.1 set defined between { and }
        # is defined by a set of ASN.1 object types, and not a set of ASN.1 values
        # text: textual definition of an ASN1 object
        # val: root / ext dict for receiving the result when parsing text
        # ext: True when in the extension domain
        #
        # parse the new object
        Obj = ASN1Obj(name=self._name, mode=MODE_TYPE)
        Obj._text_def = text
        val[dom].append( Obj )
        #
        _path_stack([])
        text = Obj.parse_def(text)
        _path_pop()
        #
        val[dom][-1] = Obj.resolve()
        #
        # copy references from Obj to self
        if Obj._ref:
            self._ref.update( Obj._ref )
        #
        return text
    

#///////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\#
#------------------------------------------------------------------------------#
# Python classes for ASN.1 native basic objects
#------------------------------------------------------------------------------#
#\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\///////////////////////////////////////#

class NULL(ASN1Obj):
    __doc__ = """
    ASN.1 basic type NULL object
    
    single value: int 0
    
    %s
    """ % ASN1Obj_docstring
    
    TYPE  = TYPE_NULL
    TAG   = 5
    _type = TYPE
    
    CONST = [CONST_VAL]
    
    def __init__(self, Obj=None):
        self._init_from_obj(Obj)
    
    def _to_asn1(self, val):
        return 'NULL'

class BOOL(ASN1Obj):
    __doc__ = """
    ASN.1 basic type BOOLEAN object
    
    single value: Python bool
    
    %s
    """ % ASN1Obj_docstring
    
    TYPE  = TYPE_BOOL
    TAG   = 1
    _type = TYPE
    
    CONST = [CONST_VAL]
    
    def __init__(self, Obj=None):
        self._init_from_obj(Obj)
    
    def _to_asn1(self, val):
        return {True: 'TRUE', False: 'FALSE'}[val]

class INT(ASN1Obj):
    __doc__ = """
    ASN.1 basic type INTEGER object
    
    single value: Python int
    
    %s
    """ % ASN1Obj_docstring
    
    TYPE  = TYPE_INT
    TAG   = 2
    _type = TYPE
    
    CONST = [CONST_VAL]
    
    def __init__(self, Obj=None):
        self._init_from_obj(Obj)
    
    def _to_asn1(self, val):
        # to be applied to an internal single value `val' to get 
        # an ASN.1 compliant value
        return str(val)

class REAL(ASN1Obj):
    __doc__ = """
    ASN.1 basic type REAL object
    
    single value: Python list of 3 int
        1st int is the mantissa, 2nd is the base, 3rd is the exponent
        Special values are:
        [-1, None, None]: MINUS-INFINITY
        [1,  None, None]: PLUS-INFINITY
        [0,  None, None]: NOT-A-NUMBER
    
    %s
    """ % ASN1Obj_docstring
    
    REPR_VAL = b'S' # b'S': sequential repr, b'N': numeric repr if exp base 10
    
    #
    # SEQUENCE-like definition of REAL:
    #
    # REAL ::= SEQUENCE {
    #    mantissa INTEGER,
    #    base INTEGER (2|10),
    #    exponent INTEGER }
    #
    
    TYPE  = TYPE_REAL
    TAG   = 9
    _type = TYPE
    
    CONST = [CONST_VAL]
    
    def __init__(self, Obj=None):
        self._init_from_obj(Obj)
    
    def _to_asn1(self, val):
        # to be applied to an internal single value `val' to get 
        # an ASN.1 compliant value
        if val[1:3] == [None, None]:
            return {-1: 'MINUS-INFINITY',
                     1: 'PLUS-INFINITY',
                     0: 'NOT-A-NUMBER'}[val[0]]
        elif self.REPR_VAL == b'N' and val[1] == 10:
            return '%iE%i' % (val[0], val[2])
        else:
            return '{mantissa %i, base %i, exponent %i}'.format(*val)

class ENUM(ASN1Obj):
    __doc__ = """
    ASN.1 basic type ENUMERATED object
    
    single value: Python str, must be a key in _cont
    
    %s
    """ % ASN1Obj_docstring
    
    TYPE  = TYPE_ENUM
    TAG   = 10
    _type = TYPE
    
    CONST = [CONST_VAL]
    
    def __init__(self, Obj=None):
        self._init_from_obj(Obj)
    
    def _to_asn1(self, val):
        # to be applied to an internal single value `val' to get 
        # an ASN.1 compliant value
        return val

class OID(ASN1Obj):
    __doc__ = """
    ASN.1 basic type OBJECT IDENTIFIER object
    
    single value: Python list of int
    
    %s
    """ % ASN1Obj_docstring
    
    TYPE  = TYPE_OID
    TAG   = 6
    _type = TYPE
    
    CONST = [CONST_VAL]
    
    def __init__(self, Obj=None):
        self._init_from_obj(Obj)
    
    def _to_asn1(self, val):
        # to be applied to an internal single value `val' to get 
        # an ASN.1 compliant value
        return '{%s}' % ' '.join(map(str, val))

class REL_OID(ASN1Obj):
    __doc__ = """
    ASN.1 basic type RELATIVE-OID object
    
    single value: Python list of int
    
    %s
    """ % ASN1Obj_docstring
    
    TYPE  = TYPE_REL_OID
    TAG   = 13
    _type = TYPE
    
    CONST = [CONST_VAL]
    
    def __init__(self, Obj=None):
        self._init_from_obj(Obj)
    
    def _to_asn1(self, val):
        # to be applied to an internal single value `val' to get 
        # an ASN.1 compliant value
        return '{%s}' % ' '.join(map(str, val))

class BIT_STR(ASN1Obj):
    __doc__ = """
    ASN.1 basic type BIT STRING object
    
    single value: Python list of 2 int
        1st int is the unsigned integral value, 2nd is the length in bits
        
    when CONST_CONTAINING is set, a Python list of 3 items is used,
        the 1st and 2nd items are the original value (2 int),
        the 3rd item is a CHOICE-like single value, i.e. a list of 2 items with
        a global identifier string and an ASN1Obj single value
    
    %s
    """ % ASN1Obj_docstring
    
    REPR_VAL = b'B' # b'B': bstring, b'H': hstring if bit length mutliple of 4
    
    TYPE  = TYPE_BIT_STR
    TAG   = 3
    _type = TYPE
    
    CONST = [CONST_VAL,
             CONST_SIZE,
             CONST_CONTAINING,
             CONST_ENCODE_BY]
    
    def __init__(self, Obj=None):
        self._init_from_obj(Obj)
    
    def _to_asn1(self, val):
        # to be applied to an internal single value `val' to get 
        # an ASN.1 compliant value
        if self.REPR_VAL == b'H' and not val[1]%4:
            # hstr
            hstr = hex(val[0])[2:]
            if 4*len(hstr) < val[1]:
                hstr = (val[1]//4 - len(hstr))*'0' + hstr
            return '\'%s\'H' % hstr
        else:
            # bstr
            bstr = bin(val[0])[2:]
            if len(bstr) < val[1]:
                bstr = (val[1] - len(bstr))*'0' + bstr
            return '\'%s\'B' % bstr

class OCT_STR(ASN1Obj):
    __doc__ = """
    ASN.1 basic type OCTET STRING object
    
    single value: Python bytes
        
    when CONST_CONTAINING is set, a Python list of 2 items is used,
        the 1st item is the original value (bytes),
        the 2nd item is a CHOICE-like single value, i.e. a list of 2 items with
        a global identifier string and an ASN1Obj single value
    
    %s
    """ % ASN1Obj_docstring
    
    REPR_VAL = b'B' # b'B': bstring, b'H': hstring
    
    TYPE  = TYPE_OCT_STR
    TAG   = 4
    _type = TYPE
    
    CONST = [CONST_VAL,
             CONST_SIZE,
             CONST_CONTAINING,
             CONST_ENCODE_BY]
    
    def __init__(self, Obj=None):
        self._init_from_obj(Obj)
    
    def val_ok(self, val):
        """
        returns True if val complies to the content, against any size 
        constraint
        """
        # TODO
        return True
    
    def _to_asn1(self, val):
        # to be applied to an internal single value `val' to get 
        # an ASN.1 compliant value
        if isinstance(val, tuple):
            if self.REPR_VAL == b'H':
                return '\'%s\'H' % hexlify(val[0]).upper()
            else:
                bstr = bin(bytes_to_uint(val[0], len(val[0])))[2:]
                if len(bstr) < 8*len(val[0]):
                    bstr = (8*len(val[0]) - len(bstr))*'0' + bstr
                return '\'%s\'B' % bstr
        else:
            if self.REPR_VAL == b'H':
                return '\'%s\'H' % hexlify(val).upper()
            else:
                bstr = bin(bytes_to_uint(val, len(val)))[2:]
                if len(bstr) < 8*len(val):
                    bstr = (8*len(val) - len(bstr))*'0' + bstr
                return '\'%s\'B' % bstr


_String_docstring = """
single value: Python str

Attribute specific to *String:

_clen: None or int, indicates the number of bits for a character

%s
""" % ASN1Obj_docstring

class _String(ASN1Obj):
    __doc__ = """
    Virtual parent for any ASN.1 *String object
    
    %s
    """ % _String_docstring
    
    _clen = None
    
    CONST = [CONST_VAL,
             CONST_SIZE,
             CONST_ALPHABET,
             CONST_REGEXP]
    
    def __init__(self, Obj):
        self._init_from_obj(Obj)
    
    def _to_asn1(self, val):
        # to be applied to an internal single value `val' to get 
        # an ASN.1 compliant value
        return '"%s"' % val.replace('"', '""')
    

class OBJ_DESC(_String):
    __doc__ = """
    ASN.1 basic type OBJECT DESCRIPTOR object
    
    %s
    """ % _String_docstring
    
    TYPE  = TYPE_OBJ_DESC
    TAG   = 7
    _type = TYPE

class STR_UTF8(_String):
    __doc__ = """
    ASN.1 basic type UTF8String object
    
    %s
    """ % _String_docstring
    
    TYPE  = TYPE_STR_UTF8
    TAG   = 12
    _type = TYPE

class STR_NUM(_String):
    __doc__ = """
    ASN.1 basic type NumericString object
    
    %s
    """ % _String_docstring
    
    TYPE  = TYPE_STR_NUM
    TAG   = 18
    _type = TYPE

class STR_PRINT(_String):
    __doc__ = """
    ASN.1 basic type PrintableString object
    
    %s
    """ % _String_docstring
    
    TYPE  = TYPE_STR_PRINT
    TAG   = 19
    _type = TYPE

class STR_TELE(_String):
    __doc__ = """
    ASN.1 basic type TeletexString object
    
    %s
    """ % _String_docstring
    
    TYPE  = TYPE_STR_TELE
    TAG   = 20
    _type = TYPE

class STR_T61(_String):
    __doc__ = """
    ASN.1 basic type T61String object
    
    %s
    """ % _String_docstring
    
    TYPE  = TYPE_STR_T61
    TAG   = 20
    _type = TYPE

class STR_VID(_String):
    __doc__ = """
    ASN.1 basic type VideotexString object
    
    %s
    """ % _String_docstring
    
    TYPE  = TYPE_STR_VID
    TAG   = 21
    _type = TYPE

class STR_IA5(_String):
    __doc__ = """
    ASN.1 basic type IA5String object
    
    %s
    """ % _String_docstring
    
    TYPE  = TYPE_STR_IA5
    TAG   = 22
    _type = TYPE
    _clen = 7 # to be confirmed

class STR_GRAPH(_String):
    __doc__ = """
    ASN.1 basic type GraphicString object
    
    %s
    """ % _String_docstring
    
    TYPE  = TYPE_STR_GRAPH
    TAG   = 25
    _type = TYPE

class STR_VIS(_String):
    __doc__ = """
    ASN.1 basic type VisibleString object
    
    %s
    """ % _String_docstring
    
    TYPE  = TYPE_STR_VIS
    TAG   = 26
    _type = TYPE

class STR_ISO646(_String):
    __doc__ = """
    ASN.1 basic type ISO646String object
    
    %s
    """ % _String_docstring
    
    TYPE  = TYPE_STR_ISO646
    TAG   = 26
    _type = TYPE

class STR_GENE(_String):
    __doc__ = """
    ASN.1 basic type GenericString object
    
    %s
    """ % _String_docstring
    
    TYPE  = TYPE_STR_GENE
    TAG   = 27
    _type = TYPE

class STR_UNIV(_String):
    __doc__ = """
    ASN.1 basic type UniversalString object
    
    %s
    """ % _String_docstring
    
    TYPE  = TYPE_STR_UNIV
    TAG   = 28
    _type = TYPE
    _clen = 32

class STR_BMP(_String):
    __doc__ = """
    ASN.1 basic type BMPString object
    
    %s
    """ % _String_docstring
    
    TYPE  = TYPE_STR_BMP
    TAG   = 30
    _type = TYPE
    _clen = 16

class _Time(ASN1Obj):
    __doc__ = """Virtual parent for UTCTime and GeneralizedTime"""
    
    CONST = [CONST_VAL]
    
    def __init__(self, Obj):
        self._init_from_obj(Obj)


class TIME_UTC(_Time):
    __doc__ = """
    ASN.1 basic type UTCTime object
    
    single value: Python 7-tuple of int (AA, MM, DD, HH, MM, [SS,] Z),
        SS is optional, hence 6th element can be None
        Z corresponds to the UTC decay
    
    %s
    """ % ASN1Obj_docstring
    
    TYPE  = TYPE_TIME_UTC
    TAG   = 23
    _type = TYPE
    
    def _to_asn1(self, val):
        # to be applied to an internal single value `val' to get 
        # an ASN.1 compliant value
        ret = '%.2i%.2i%.2i%.2i%.2i' % val[:5]
        if val[5] is not None:
            ret += '%.2i' % val[5]
        if val[6] == 0:
            ret += 'Z'
        elif val[6] > 0:
            ret += '+%.4i' % val[6]
        else:
            ret += '%.4i' % val[6]
        return ret

class TIME_GEN(_Time):
    __doc__ = """
    ASN.1 basic type GeneralizedTime object
    
    single value: Python 8-tuple of int 
        (AAAA, MM, DD, HH, [MM, [SS, [FFFF,]]], Z),
        MM, SS and FFFF are optional, hence 5th, 6th and 7th element can be None
        Z corresponds to the UTC decay and is optional, hence 8th element 
        can be None too
    
    %s
    """ % ASN1Obj_docstring
    
    TYPE  = TYPE_TIME_GEN
    TAG   = 24 
    _type = TYPE
    
    def _to_asn1(self, val):
        # to be applied to an internal single value `val' to get 
        # an ASN.1 compliant value
        ret = '%.4i%.2i%.2i%.2i' % val[:4]
        if val[4] is not None:
            ret += '%.2i' % val[4]
            if val[5] is not None:
                ret += '%.2i' % val[5]
                if val[6] is not None:
                    ret += '.%.4i' % val[6]
        if val[7] == 0:
            ret += 'Z'
        elif val[7] > 0:
            ret += '+%.4i' % val[7]
        elif val[7] < 0:
            ret += '%.4i' % val[7]
        return ret

#///////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\#
#------------------------------------------------------------------------------#
# Python classes for ASN.1 native constructed objects
#------------------------------------------------------------------------------#
#\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\///////////////////////////////////////#

class CHOICE(ASN1Obj):
    __doc__ = """
    ASN.1 constructed type CHOICE object
    
    single value: Python list of 2 items
        1st item is the identifier of the choice (str),
        2nd item is the ASN1Obj single value specific to the chosen object
    
    %s
    """ % ASN1Obj_docstring
    
    TYPE  = TYPE_CHOICE
    TAG   = None
    _type = TYPE
    
    CONST = [CONST_VAL,
             CONST_COMPS]
    
    def __init__(self, Obj=None):
        self._init_from_obj(Obj)
    
    def _to_asn1(self, val):
        return '%s: %s' % (val[0],
                           self.get_cont()[val[0]]._to_asn1[val[1]])

class SEQ(ASN1Obj):
    __doc__ = """
    ASN.1 constructed type SEQUENCE object
    
    single value: Python ASN1Dict
        keys are components' identifier (str),
        values are ASN1Obj single value specific to components object
    
    %s
    """ % ASN1Obj_docstring
    
    TYPE  = TYPE_SEQ
    TAG   = 16
    _type = TYPE
    
    CONST = [CONST_VAL,
             CONST_COMPS]
    
    def __init__(self, Obj=None):
        self._init_from_obj(Obj)
    
    def init_cache(self):
        self._cache = {}
        if self._cont is not None:
            for Comp in self._cont.values():
                Comp.init_cache()
    
    def _to_asn1(self, val):
        cont = self.get_cont()
        values = ['%s %s' % (ident, cont[ident]._to_asn1(value)) for \
                  (ident, value) in val.items()]
        return '{ %s }' % ', '.join(values)


class SEQ_OF(ASN1Obj):
    __doc__ = """
    ASN.1 constructed type SEQUENCE OF object
    
    single value: Python list
        items are ASN1Obj single value specific to the component object
    
    %s
    """ % ASN1Obj_docstring
    
    TYPE  = TYPE_SEQ_OF
    TAG   = 16
    _type = TYPE
    
    CONST = [CONST_VAL,
             CONST_SIZE,
             CONST_COMP]
    
    def __init__(self, Obj):
        self._init_from_obj(Obj)
    
    def init_cache(self):
        self._cache = {}
        if self._cont is not None:
            self._cont.init_cache()
    
    def _to_asn1(self, val):
        cont = self.get_cont()
        return '{ %s }' % ', '.join([cont._to_asn1(value) for value in val])

class SET(ASN1Obj):
    __doc__ = """
    ASN.1 constructed type SET object
    
    single value: Python dict
        keys are components' identifier (str),
        values are ASN1Obj single value specific to components object
    
    %s
    """ % ASN1Obj_docstring
    
    TYPE  = TYPE_SET
    TAG   = 17
    _type = TYPE
    
    CONST = [CONST_VAL,
             CONST_COMPS]
    
    def __init__(self, Obj=None):
        self._init_from_obj(Obj)
    
    def init_cache(self):
        self._cache = {}
        if self._cont is not None:
            for Comp in self._cont.values():
                Comp.init_cache()
    
    def _to_asn1(self, val):
        cont = self.get_cont()
        values = ['%s %s' % (ident, cont[ident]._to_asn1(value)) for \
                  (ident, value) in val.items()]
        return '{ %s }' % ', '.join(values)

class SET_OF(ASN1Obj):
    __doc__ = """
    ASN.1 constructed type SET OF object
    
    single value: Python list
        items are ASN1Obj single value specific to the component object
    
    %s
    """ % ASN1Obj_docstring
    
    TYPE  = TYPE_SET_OF
    TAG   = 17
    _type = TYPE
    
    CONST = [CONST_VAL,
             CONST_SIZE,
             CONST_COMP]
    
    def __init__(self, Obj):
        self._init_from_obj(Obj)
    
    def init_cache(self):
        self._cache = {}
        if self._cont is not None:
            self._cont.init_cache()
    
    def _to_asn1(self, val):
        cont = self.get_cont()
        return '{ %s }' % ', '.join([cont._to_asn1(value) for value in val])

#///////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\#
#------------------------------------------------------------------------------#
# Python classes for ASN.1 native container objects
#------------------------------------------------------------------------------#
#\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\///////////////////////////////////////#

class OPEN(ASN1Obj):
    
    TYPE  = TYPE_OPEN
    TAG   = None
    _type = TYPE
    
    CONST = [CONST_VAL,
             CONST_CONTAINING]
    
    def __init__(self, Obj=None):
        self._init_from_obj(Obj)

class ANY(OPEN):
    
    TYPE  = TYPE_ANY
    TAG   = None
    _type = TYPE
    
    CONST = [CONST_VAL,
             CONST_CONTAINING]

class EXT(ASN1Obj):
    """
    ASN.1 context switching type EXPTERNAL object
    
    associated type:
        [UNIVERSAL 8] IMPLICIT SEQUENCE {
            identification [0] EXPLICIT CHOICE {
                syntaxes [0] SEQUENCE {
                    abstract [0] OBJECT IDENTIFIER,
                    transfer [1] OBJECT IDENTIFIER
                    },
                syntax [1] OBJECT IDENTIFIER,
                presentation-context-id [2] INTEGER,
                context-negotiation [3] SEQUENCE {
                    presentation-context-id [0] INTEGER,
                    transfer-syntax [1] OBJECT IDENTIFIER
                    },
                transfer-syntax [4] OBJECT IDENTIFIER,
                fixed [5] NULL
                },
            data-value-descriptor [1] ObjectDescriptor OPTIONAL,
            data-value [2] OCTET STRING
            } (WITH COMPONENTS {
                ...,
                identification (WITH COMPONENTS {
                    ...,
                    syntaxes ABSENT,
                    transfer-syntax ABSENT,
                    fixed ABSENT })
                })
    """
    TYPE  = TYPE_EXT
    TAG   = 8
    _type = TYPE
    
    CONST = [CONST_VAL,
             CONST_COMPS]
    
    def __init__(self, Obj=None):
        self._init_from_obj(Obj)

class EMB_PDV(ASN1Obj):
    """
    ASN.1 context switching type EMBEDDED PDV object
    
    associated type:
        [UNIVERSAL 8] IMPLICIT SEQUENCE {
            identification [0] EXPLICIT CHOICE {
                syntaxes [0] SEQUENCE {
                    abstract [0] OBJECT IDENTIFIER,
                    transfer [1] OBJECT IDENTIFIER
                    },
                syntax [1] OBJECT IDENTIFIER,
                presentation-context-id [2] INTEGER,
                context-negotiation [3] SEQUENCE {
                    presentation-context-id [0] INTEGER,
                    transfer-syntax [1] OBJECT IDENTIFIER
                    },
                transfer-syntax [4] OBJECT IDENTIFIER,
                fixed [5] NULL
                },
            data-value-descriptor [1] ObjectDescriptor OPTIONAL,
            data-value [2] OCTET STRING
            } (WITH COMPONENTS {
                ...,
                data-value-descriptor ABSENT
                })
    """
    TYPE  = TYPE_EMB_PDV
    TAG   = 11
    _type = TYPE
    
    CONST = [CONST_VAL,
             CONST_COMPS]
    
    def __init__(self, Obj=None):
        self._init_from_obj(Obj)

class CHAR_STR(ASN1Obj):
    
    TYPE  = TYPE_CHAR_STR
    TAG   = 29
    _type = TYPE
    
    CONST = [CONST_VAL,
             CONST_SIZE,
             CONST_COMPS]
    
    def __init__(self, Obj=None):
        self._init_from_obj(Obj)

#///////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\#
#------------------------------------------------------------------------------#
# Python classes for ASN.1 native CLASS objects
#------------------------------------------------------------------------------#
#\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\///////////////////////////////////////#

class CLASS(ASN1Obj):
    __doc__ = """
    ASN.1 CLASS object type
    
    single value: Python ASN1Dict
        keys are fields' identifier (str),
        values are ASN1Obj single value, values set or type, specific to each
        field
    
    %s
    """ % ASN1Obj_docstring
    
    KW = ('name', 'mode', 'param', 'tag', 'type', 'typeref',  'cont', 'ext',
          'const', 'val', 'ref', 'parent', 'flag', 'group', 'msg', 'syntax')
    
    TYPE  = TYPE_CLASS
    TAG   = None
    _type = TYPE
    
    CONST = [CONST_VAL]
    
    def __init__(self, Obj):
        self._init_from_obj(Obj)
    
    def init_cache(self):
        self._cache = {}
        if self._cont is not None:
            for Field in self._cont.values():
                Field.init_cache()
    
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
        if name not in self.get_cont():
            raise(ASN1ObjErr('{0}: invalid identifier, {1}'\
                  .format(self.fullname(), name)))
        #
        # TODO: enable caching all those values' lists
        #
        if self._mode == MODE_VALUE:
            if val is None:
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
                values = []
                # return all the values for the given identifier
                if self._val['root']:
                    values.extend([v[name] for v in self._val['root']])
                if self._val['ext']:
                    values.extend([v[name] for v in self._val['ext']])
                return values
            else:
                if self._val['root']:
                    for v in self._val['root']:
                        if v[name] == val:
                            return v
                if self._val['ext']:
                    for v in self._val['ext']:
                        if v[name] == val:
                            return v
                return None
    
    def _to_asn1(self, val):
        return None

#///////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\#
#------------------------------------------------------------------------------#
# Python classes for predefined ASN.1 objects
#------------------------------------------------------------------------------#
#\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\///////////////////////////////////////#

class INST_OF(SEQ):
    
    TYPE  = TYPE_INSTOF
    TAG   = 8
    _type = TYPE
    
    def __init__(self, Obj):
        self._init_from_obj(Obj)
        # TODO:
        # resolve _typeref
        # verifies it is a TYPE-IDENTIFIER
        # expand its content into sequential components
        assert( self._typeref is not None )
        #tr = self.get_typeref()
        #tr.get_refchain()

#///////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\#
#------------------------------------------------------------------------------#
# Python dict for ASN.1 object look-up
#------------------------------------------------------------------------------#
#\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\///////////////////////////////////////#

ASN1ObjLUT = {
    TYPE_NULL       : NULL,
    TYPE_BOOL       : BOOL,
    TYPE_INT        : INT,
    TYPE_REAL       : REAL,
    TYPE_ENUM       : ENUM,
    TYPE_BIT_STR    : BIT_STR,
    TYPE_OCT_STR    : OCT_STR,
    TYPE_OID        : OID,
    TYPE_REL_OID    : REL_OID,
    TYPE_STR_IA5    : STR_IA5,
    TYPE_STR_PRINT  : STR_PRINT,
    TYPE_STR_NUM    : STR_NUM,
    TYPE_STR_VIS    : STR_VIS,
    TYPE_STR_BMP    : STR_BMP,
    TYPE_STR_UTF8   : STR_UTF8,
    TYPE_STR_ISO646 : STR_ISO646,
    TYPE_STR_TELE   : STR_TELE,
    TYPE_STR_VID    : STR_VID,
    TYPE_STR_GRAPH  : STR_GRAPH,
    TYPE_STR_T61    : STR_T61,
    TYPE_STR_GENE   : STR_GENE,
    TYPE_STR_UNIV   : STR_UNIV,
    TYPE_OBJ_DESC   : OBJ_DESC,
    TYPE_TIME_GEN   : TIME_GEN,
    TYPE_TIME_UTC   : TIME_UTC,
    TYPE_CHOICE     : CHOICE,
    TYPE_SEQ        : SEQ,
    TYPE_SEQ_OF     : SEQ_OF,
    TYPE_SET        : SET,
    TYPE_SET_OF     : SET_OF,
    TYPE_OPEN       : OPEN,
    TYPE_ANY        : ANY,
    TYPE_EXT        : EXT,
    TYPE_EMB_PDV    : EMB_PDV,
    TYPE_CHAR_STR   : CHAR_STR,
    TYPE_CLASS      : CLASS,
    TYPE_TYPEIDENT  : CLASS,
    TYPE_ABSSYNT    : CLASS,
    TYPE_INSTOF     : INST_OF
    }

