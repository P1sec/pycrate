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
# * File Name : pycrate_asn1c/gen_pycrate_asn1rt.py
# * Created : 2016-12-21
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

import copy

from .utils  import *
from .glob   import *
from .setobj import *
from .refobj import *
from .asnobj import get_asnobj, ASN1Obj, INT, OID


class _Generator(object):
    
    def __init__(self, dest='/tmp/dst.txt'):
        self.dest = dest
        self.fd = open(self.dest, 'w')
        self.indent = 0
        self.gen()
        self.fd.close()
    
    def wrl(self, s):
        self.fd.write('{0}{1}\n'.format(self.indent * ' ', s))
    
    def gen(self):
        pass

#------------------------------------------------------------------------------#
# Python source code generator
#------------------------------------------------------------------------------#
# generate Python source code for the ASN1 runtime of pycrate
# (located in pycrate_asn1rt/ directory)

_mode_lut = {
    'TYPE'              : 'MODE_TYPE',
    'SET'               : 'MODE_SET',
    'VALUE'             : 'MODE_VALUE'
    }

_tag_lut = {
    'IMPLICIT'          : 'TAG_IMPLICIT',
    'EXPLICIT'          : 'TAG_EXPLICIT',
    'CONTEXT-SPECIFIC'  : 'TAG_CONTEXT_SPEC',
    'PRIVATE'           : 'TAG_PRIVATE',
    'APPLICATION'       : 'TAG_APPLICATION',
    'UNIVERSAL'         : 'TAG_UNIVERSAL',
    'AUTOMATIC'         : 'TAG_AUTOMATIC'
    }

_type_lut = {
    'NULL'              : 'TYPE_NULL',
    'BOOLEAN'           : 'TYPE_BOOL',
    'INTEGER'           : 'TYPE_INT',
    'REAL'              : 'TYPE_REAL',
    'ENUMERATED'        : 'TYPE_ENUM',
    'BIT STRING'        : 'TYPE_BIT_STR',
    'OCTET STRING'      : 'TYPE_OCT_STR',
    'OBJECT IDENTIFIER' : 'TYPE_OID',
    'REALTIVE-OID'      : 'TYPE_REL_OID',
    #
    'IA5String'         : 'TYPE_STR_IA5',
    'PrintableString'   : 'TYPE_STR_PRINT',
    'NumericString'     : 'TYPE_STR_NUM',
    'VisibleString'     : 'TYPE_STR_VIS',
    'BMPString'         : 'TYPE_STR_BMP',
    'UTF8String'        : 'TYPE_STR_UTF8',
    'ISO646String'      : 'TYPE_STR_ISO646',
    'TeletexString'     : 'TYPE_STR_TELE',
    'VideotexString'    : 'TYPE_STR_VID',
    'GraphicString'     : 'TYPE_STR_GRAPH',
    'T61String'         : 'TYPE_STR_T61',
    'GeneralString'     : 'TYPE_STR_GENE',
    'UniversalString'   : 'TYPE_STR_UNIV',
    'ObjectDescriptor'  : 'TYPE_OBJ_DESC',
    #
    'GeneralizedTime'   : 'TYPE_TIME_GEN',
    'UTCTime'           : 'TYPE_TIME_UTC',
    #
    'CHOICE'            : 'TYPE_CHOICE',
    'SEQUENCE'          : 'TYPE_SEQ',
    'SEQUENCE OF'       : 'TYPE_SEQ_OF',
    'SET'               : 'TYPE_SET',
    'SET OF'            : 'TYPE_SET_OF',
    #
    'OPEN_TYPE'         : 'TYPE_OPEN',
    'ANY'               : 'TYPE_OPEN',
    'EXTERNAL'          : 'TYPE_EXT',
    'EMBEDDED PDV'      : 'TYPE_EMB_PDV',
    'CHARACTER STRING'  : 'TYPE_CHAR_STR',
    #
    'CLASS'             : 'TYPE_CLASS',
    'INSTANCE OF'       : 'TYPE_INSTOF' 
    }

def value_to_defin(v, Obj=None, Gen=None, ind=None):
    if Obj.TYPE == TYPE_NULL:
        # '0'
        return '0'
    elif Obj.TYPE == TYPE_BOOL:
        # bool
        return repr(v)
    elif Obj.TYPE == TYPE_INT:
        # int (/long)
        rv = repr(v)
        if rv[-1] == 'L':
            # python2 useless long notation
            return rv[:-1]
        else:
            return rv
    elif Obj.TYPE == TYPE_REAL:
        # list of 3 int -> convert to 3-tuple
        mant, ex = repr(v[0]), repr(v[2])
        if mant[-1] == 'L':
            # again, python2 useless long notation
            mant = mant[:-1]
        if ex[-1] == 'L':
            ex = ex[:-1]
        return '(%s, %r, %s)' % (mant, v[1], ex)
    elif Obj.TYPE == TYPE_ENUM:
        # string
        return repr(v)
    elif Obj.TYPE == TYPE_BIT_STR:
        # list of 2 int -> convert to tuple
        vv, vl = repr(v[0]), repr(v[1])
        if vv[-1] == 'L':
            vv = vv[:-1]
        if vl[-1] == 'L':
            vl = vl[:-1]
        return '(%s, %s)' % (vv, vl)
    elif Obj.TYPE == TYPE_OCT_STR:
        # byte-string
        if python_version > 2:
            return repr(v)
        else:
            return 'b%s' % repr(v)
    elif Obj.TYPE == TYPE_OID:
        # list of int -> convert to tuple
        return repr(tuple(v))
    elif Obj.TYPE == TYPE_REL_OID:
        # list of int -> convert to tuple
        return repr(tuple(v))
    elif Obj.TYPE in TYPE_STRINGS:
        # char string
        return repr(v)
    elif Obj.TYPE in (TYPE_TIME_UTC, TYPE_TIME_GEN):
        # tuple of {int, None}
        return repr(v)
    elif Obj.TYPE == TYPE_CHOICE:
        # list of name and single value -> convert to tuple
        return '(' + repr(v[0]) + ', ' + value_to_defin(v[1], Obj.get_cont()[v[0]], Gen) + ')'
    elif Obj.TYPE in (TYPE_SEQ_OF, TYPE_SET_OF):
        # list of single value
        return '[' + ', '.join([value_to_defin(i, Obj.get_cont(), Gen) for i in v]) + ']'
    elif Obj.TYPE in (TYPE_SEQ, TYPE_SET):
        # Python dict of {name: single value}
        #return 'ASN1Dict([' + \
        return 'dict([' + \
               ', '.join(['({0}, {1})'.format(repr(name), value_to_defin(val, Obj.get_cont()[name], Gen)) \
                          for (name, val) in v.items()]) + \
               '])'
    elif Obj.TYPE == TYPE_CLASS:
        # Python dict of {name: single value or set of values or type object}
        r = []
        for (name, value) in v.items():
            ObjVal = Obj.get_cont()[name]
            if not hasattr(ObjVal, '_pyname'):
                ObjVal._pyname = '_{0}_{1}'.format(Obj._pyname, name_to_defin(ObjVal._name))
            if ObjVal._mode == MODE_VALUE:
                if ObjVal.TYPE == TYPE_OPEN and isinstance(ObjVal._typeref, ASN1RefClassIntern):
                    # get the typeref object defined in v, and use it to define the ObjVal value
                    ObjValTr = v[ObjVal._typeref.ced_path[0]]
                    for p in ObjVal._typeref.ced_path[1:]:
                        ObjValTr = ObjValTr.get_cont()[p]
                    r.append('({0}, {1})'.format(repr(name), value_to_defin(value, ObjValTr, Gen)))
                else:
                    r.append('({0}, {1})'.format(repr(name), value_to_defin(value, ObjVal, Gen)))
            elif ObjVal._mode == MODE_SET:
                if ObjVal.TYPE == TYPE_OPEN and isinstance(ObjVal._typeref, ASN1RefClassIntern):
                    # get the typeref object defined in v, and use it to define the ObjVal value
                    ObjValTr = v[ObjVal._typeref.ced_path[0]]
                    for p in ObjVal._typeref.ced_path[1:]:
                        ObjValTr = ObjValTr.get_cont()[p]
                    r.append('({0}, {1})'.format(repr(name), set_to_defin(value, ObjValTr, Gen)))
                else:
                    r.append('({0}, {1})'.format(repr(name), set_to_defin(ASN1Set(value), ObjVal, Gen)))
            else:
                #ObjVal._mode == MODE_TYPE
                # value is an ASN1 object, create it first
                # WNG: no name unicity for value, use ind for this purpose
                if ind is not None:
                    value._pyname = '_{0}_val_{1}_{2!r}'.format(Obj._pyname, name_to_defin(value._name), ind)
                else:
                    value._pyname = '_{0}_val_{1}'.format(Obj._pyname, name_to_defin(value._name))
                Gen.gen_type(value, compts=False)
                # object to be linked in the ASN1Dict value 
                r.append('({0}, {1})'.format(repr(name), value._pyname))
        #return 'ASN1Dict([' + ', '.join(r) + '])'
        return 'dict([' + ', '.join(r) + '])'
    elif Obj.TYPE in (TYPE_OPEN, TYPE_ANY):
        # list with [object definition, single value]
        # changing it to a 2-tuple
        v[0]._pyname = '_{0}_val'.format(name_to_defin(v[0]._name))
        Gen.gen_type(v[0], compts=False)
        return '({0}, {1})'.format(v[0]._pyname, value_to_defin(v[1], v[0], Gen))
    elif Obj.TYPE == TYPE_EXT:
        # TODO
        assert()
    elif Obj.TYPE == TYPE_EMB_PDV:
        # TODO
        assert()
    elif Obj.TYPE == TYPE_CHAR_STR:
        # TODO
        assert()
    else:
        assert()

def range_to_defin(r, Obj=None):
    # ASN1Range only applied to TYPE_INT, TYPE_REAL and TYPE_STR_*
    if Obj.TYPE == TYPE_INT:
        return 'ASN1RangeInt(lb={0}, ub={1})'\
               .format(value_to_defin(r.lb, Obj), value_to_defin(r.ub, Obj))
    elif Obj.TYPE == TYPE_REAL:
        return 'ASN1RangeReal(lb={0}, ub={1}, lb_incl={2!r}, ub_incl={3!r})'\
                .format(value_to_defin(r.lb, Obj), value_to_defin(r.ub, Obj), r.lb_incl, r.ub_incl)
    elif Obj.TYPE in ASN1Range._TYPE_STR:
        return 'ASN1RangeStr(lb={0!r}, ub={1!r})'.format(r.lb, r.ub)
    else:
        assert()

def set_to_defin(S, Obj=None, Gen=None):
    # ASN1Set(rv, rr, ev, er)
    # ind: value index, required especially for distinguishing sets of CLASS values
    ind = 0
    # root part
    rv, rr = [], []
    for v in S._rv:
        rv.append( value_to_defin(v, Obj, Gen, ind) )
        ind += 1
    rv = '[' + ', '.join(rv) + ']'
    for vr in S._rr:
        rr.append( range_to_defin(vr, Obj) )
    rr = '[' + ', '.join(rr) + ']'
    # extension part
    if S._ev is None:
        ev, er = 'None', '[]'
    else:
        ev, er = [], []
        for v in S._ev:
            ev.append( value_to_defin(v, Obj, Gen, ind) )
            ind += 1
        ev = '[' + ', '.join(ev) + ']'
        for vr in S._er:
            er.append( range_to_defin(vr, Obj) )
        er = '[' + ', '.join(er) + ']'
    #
    return 'ASN1Set(rv={0}, rr={1}, ev={2}, er={3})'.format(rv, rr, ev, er)

def tag_to_defin(t):
    return '({0!r}, {1}, {2})'.format(t[0], _tag_lut[t[1]], _tag_lut[t[2]])

def typeref_to_defin(Obj):
    if isinstance(Obj._typeref, ASN1RefClassIntern):
        return 'ASN1RefClassIntern(None, {0!r})'.format(Obj._typeref.ced_path)
    elif hasattr(Obj._typeref, 'called') and \
    Obj._typeref.called[1] in ('TYPE-IDENTIFIER', 'ABSTRACT-SYNTAX'):
        # special process for those types which are injected in all modules by proc.py
        return '{0}({1!r}, {2!r})'.format(Obj._typeref.__class__.__name__,
                                          Obj._typeref.called,
                                          Obj._typeref.ced_path)
    # otherwise, we ensure to provide the correct module name (and not the imported one,
    # which be misleading due to IMPORTS chain)
    else:
        (modname, objname) = Obj._typeref.called
        while objname in GLOBAL.MOD[modname]['_imp_']:
            modname = GLOBAL.MOD[modname]['_imp_'][objname]
        if isinstance(Obj._typeref, ASN1RefType):
            return 'ASN1RefType((\'{0}\', \'{1}\'))'.format(modname, objname)
        elif isinstance(Obj._typeref, ASN1RefClassField):
            return 'ASN1RefClassField((\'{0}\', \'{1}\'), {2!r})'\
                    .format(modname, objname, Obj._typeref.ced_path)
        elif isinstance(Obj._typeref, ASN1RefClassValField):
            return 'ASN1RefClassValField((\'{0}\', \'{1}\'), {2!r})'\
                    .format(modname, objname, Obj._typeref.ced_path)
        elif isinstance(Obj._typeref, ASN1RefChoiceComp):
            return 'ASN1RefChoiceComp((\'{0}\', \'{1}\'), {2!r})'\
                    .format(modname, objname, Obj._typeref.ced_path)
        elif isinstance(Obj._typeref, ASN1RefInstOf):
            return 'ASN1RefInstOf((\'{0}\', \'{1}\'))'.format(modname, objname)
        else:
            assert()


class PycrateGenerator(_Generator):
    """
    PycrateGenerator generates Python source code to be loaded into the pycrate
    ASN.1 runtime, located in pycrate_asn1rt
    """
    _impl = 0
    
    def gen(self):
        #
        self.wrl('# -*- coding: UTF-8 -*-')
        self.wrl('# Code automatically generated by pycrate_asn1c')
        self.wrl('')
        self.wrl('from pycrate_asn1rt.utils            import *')
        self.wrl('from pycrate_asn1rt.err              import *')
        self.wrl('from pycrate_asn1rt.glob             import make_GLOBAL, GLOBAL')   
        self.wrl('from pycrate_asn1rt.dictobj          import ASN1Dict')
        self.wrl('from pycrate_asn1rt.refobj           import *')
        self.wrl('from pycrate_asn1rt.setobj           import *')
        self.wrl('from pycrate_asn1rt.asnobj_basic     import *')
        self.wrl('from pycrate_asn1rt.asnobj_str       import *')
        self.wrl('from pycrate_asn1rt.asnobj_construct import *')
        self.wrl('from pycrate_asn1rt.asnobj_class     import *')
        self.wrl('from pycrate_asn1rt.asnobj_ext       import *')
        self.wrl('from pycrate_asn1rt.init             import init_modules')
        self.wrl('')
        #
        modlist = []
        #
        for mod_name in [mn for mn in GLOBAL.MOD if mn[:1] != '_']:
            self._mod_name = mod_name
            Mod = GLOBAL.MOD[mod_name]
            pymodname = name_to_defin(mod_name)
            #
            self.wrl('class {0}:\n'.format(pymodname))
            self.indent = 4
            #
            self.wrl('_name_  = {0!r}'.format(Mod['_name_']))
            self.wrl('_oid_   = {0!r}'.format(Mod['_oid_']))
            #self.wrl('_tag_   = {0}'.format(_tag_lut[Mod['_tag_']]))
            self.wrl('')
            for attr in ('_obj_', '_type_', '_set_', '_val_', '_class_', '_param_'):
                self.wrl('{0} = ['.format(attr))
                self.indent += 4
                for name in Mod[attr]:
                    self.wrl('{0},'.format(repr(name)))
                self.wrl(']')
                self.indent -= 4
            self.wrl('')
            #
            self._all_ = []
            self._allobj_ = {}
            self.gen_mod(GLOBAL.MOD[mod_name])
            self.wrl('_all_ = [')
            for pyobjname in self._all_:
                self.wrl('    {0},'.format(pyobjname))
            self.wrl(']')
            modlist.append(pymodname)
            #
            self.indent = 0
            self.wrl('')
        #
        # create the _IMPL_ class if required
        if self._impl:
            self.wrl('class _IMPL_:\n')
            self.indent = 4
            #
            self.wrl('_name_ = \'_IMPL_\'')
            self.wrl('_oid_  = []')
            self.wrl('_obj_  = {0!r}'.format(GLOBAL.MOD['_IMPL_']['_obj_']))
            self.wrl('')
            #
            self._all_ = []
            self._allobj_ = {}
            self.gen_mod(GLOBAL.MOD['_IMPL_'])
            self.wrl('_all_ = [')
            for pyobjname in self._all_:
                self.wrl('    {0},'.format(pyobjname))
            self.wrl(']')
            modlist.append('_IMPL_')
            #
            self.indent = 0
            self.wrl('')
        #
        self.wrl('init_modules(' + ', '.join(modlist) + ')')        
    
    def gen_mod(self, Mod):
        obj_names = [obj_name for obj_name in Mod.keys() if obj_name[0:1] != '_']
        for obj_name in obj_names:
            Obj = Mod[obj_name]
            self.wrl('#-----< {0} >-----#'.format(Obj._name))
            if Obj._mode == MODE_TYPE:
                self.gen_type(Obj)
            elif Obj._mode == MODE_SET:
                self.gen_set(Obj)
            elif Obj._mode == MODE_VALUE:
                self.gen_val(Obj)
            # delete potential table constraints caches
            if hasattr(self, '_const_tabs'):
                del self._const_tabs
            self.wrl('')
    
    def _handle_dup(self, Obj):
        if Obj._pyname in self._all_:
            # a similar object was already generated (this is mainly due to a 
            # certain usage of parameterization)
            ObjDef = self._allobj_[Obj._pyname]
            if Obj == ObjDef or \
            Obj._name == ObjDef._name and Obj._type == ObjDef._type and \
            Obj._mode == ObjDef._mode and Obj._typeref == ObjDef._typeref and \
            Obj._cont == ObjDef._cont and Obj._const == ObjDef._const and \
            Obj._tag == ObjDef._tag and Obj._flag == ObjDef._flag and \
            Obj._val == ObjDef._val:
                # new object seems broadly equal to the already defined one
                return True
            else:
                # change _pyname attribute, until an unused _pyname is found
                ext = 0
                Obj._pyname = Obj._pyname + '_{0!r}'.format(ext)
                while Obj._pyname in self._all_:
                    ObjDef = self._allobj_[Obj._pyname]
                    if Obj == ObjDef or \
                    Obj._name == ObjDef._name and Obj._type == ObjDef._type and \
                    Obj._mode == ObjDef._mode and Obj._typeref == ObjDef._typeref and \
                    Obj._cont == ObjDef._cont and Obj._const == ObjDef._const and \
                    Obj._tag == ObjDef._tag and Obj._flag == ObjDef._flag and \
                    Obj._val == ObjDef._val:
                        return True
                    else:
                        ext += 1
                        Obj._pyname = Obj._pyname[:-2] + '_{0!r}'.format(ext)
                return False
        else:
            return False
    
    def gen_type(self, Obj, compts=False):
        #
        # 1) create a python-compliant name if not already done
        if not hasattr(Obj, '_pyname'):
            Obj._pyname = name_to_defin(Obj._name)
        #
        # 2) check to not duplicate object
        if self._handle_dup(Obj):
            return
        #
        # 3) early process INSTANCE OF, as it translates to a special 
        # SEQUENCE object
        if Obj.TYPE == TYPE_INSTOF:
            InstSeq = Obj.get_typeref()
            if hasattr(Obj, '_pyname'):
                InstSeq._pyname = Obj._pyname
            self.gen_type(InstSeq)
            if Obj._const:
                # TODO
                assert()
            self.wrl('{0}.TAG = 8'.format(InstSeq._pyname))
            self._all_.append(InstSeq._pyname)
            self._allobj_[InstSeq._pyname] = InstSeq
            return
        #
        # 3bis) in case of parameterized object with no referrers
        # need to consider it as a standard object
        if Obj._param and \
        sum([len(param['ref']) for param in Obj._param.values()]) == 0:
            Obj._param = None
        #
        # 4) initialize the object Python instance
        self.wrl('{0} = {1}({2})'.format(Obj._pyname,
                                         Obj.__class__.__name__,
                                         self._gen_type_init_attr(Obj, compts)))
        #
        # 5) check if the _IMPL_ module is required
        if Obj._typeref and isinstance(Obj._typeref.called, tuple) and \
        Obj._typeref.called[0] == '_IMPL_': 
            self._impl += 1
        #
        # 6) in case this is a parameterized object, no need to defined 
        # anything more
        if Obj._param:
            return
        #
        # 7) generate the content and specific constraints
        if Obj.TYPE == TYPE_NULL                        : pass
        elif Obj.TYPE == TYPE_BOOL                      : self.gen_type_bool(Obj)
        elif Obj.TYPE == TYPE_INT                       : self.gen_type_int(Obj)
        elif Obj.TYPE == TYPE_REAL                      : self.gen_type_real(Obj)
        elif Obj.TYPE == TYPE_ENUM                      : self.gen_type_enum(Obj)
        elif Obj.TYPE == TYPE_BIT_STR                   : self.gen_type_bitstr(Obj)
        elif Obj.TYPE == TYPE_OCT_STR                   : self.gen_type_octstr(Obj)
        elif Obj.TYPE in (TYPE_OID, TYPE_REL_OID)       : self.gen_type_oid(Obj)
        elif Obj.TYPE in TYPE_STRINGS                   : self.gen_type_str(Obj)
        elif Obj.TYPE in (TYPE_TIME_UTC, TYPE_TIME_GEN) : self.gen_type_time(Obj)
        elif Obj.TYPE == TYPE_CHOICE                    : self.gen_type_choice(Obj)
        elif Obj.TYPE in (TYPE_SEQ_OF, TYPE_SET_OF)     : self.gen_type_seqof(Obj)
        elif Obj.TYPE in (TYPE_SEQ, TYPE_SET)           : self.gen_type_seq(Obj)
        elif Obj.TYPE == TYPE_CLASS                     : self.gen_type_class(Obj)
        elif Obj.TYPE in (TYPE_OPEN, TYPE_ANY)          : self.gen_type_open(Obj)
        elif Obj.TYPE == TYPE_EXT                       : self.gen_type_ext(Obj)
        elif Obj.TYPE == TYPE_EMB_PDV                   : self.gen_type_embpdv(Obj)
        elif Obj.TYPE == TYPE_CHAR_STR                  : self.gen_type_charstr(Obj)
        else:
            raise(ASN1Err('{0}.{1}: unknown ASN.1 type, {2}'\
                  .format(self._mod_name, Obj._name, Obj.TYPE)))
        #
        # 8) generate the table constraint
        self.gen_const_table(Obj)
        #
        # 9) keep track of the generated object
        self._all_.append(Obj._pyname)
        self._allobj_[Obj._pyname] = Obj
    
    def gen_set(self, Obj):
        #
        # generate the type first
        self.gen_type(Obj, compts=False)
        #
        # in case this is a parameterized object, no need to defined anything more
        if Obj._param:
            return
        #
        # now generate the set of values
        self.wrl('{0}._val = {1}'.format(Obj._pyname, set_to_defin(ASN1Set(Obj._val), Obj, self)))
    
    def gen_val(self, Obj):
        #
        # generate the type first
        self.gen_type(Obj, compts=False)
        #
        # in case this is a parameterized object, no need to defined anything more
        if Obj._param:
            return
        #
        # now generate the set of values
        self.wrl('{0}._val = {1}'.format(Obj._pyname, value_to_defin(Obj._val, Obj, self)))
    
    def _gen_type_init_attr(self, Obj, compts):
        attr = ['name={0}'.format(repr(Obj._name)),
                'mode={0}'.format(_mode_lut[Obj._mode])]
        # WNG: tag or typeref at the root of the object definition could be parameterized too
        if Obj._tag and isinstance(Obj._tag[0], integer_types):
            attr.append('tag={0}'.format(tag_to_defin(Obj._tag)))
        if Obj._typeref and isinstance(Obj._typeref.called, tuple):
            attr.append('typeref={0}'.format(typeref_to_defin(Obj)))
        if Obj._param:
            attr.append('param=True')
        if compts:
            # this is for constructed objects components only
            if Obj._flag and FLAG_OPT in Obj._flag:
                attr.append('opt=True')
            elif Obj._flag and FLAG_DEF in Obj._flag:
                if Obj._mode == MODE_SET:
                    # this can happen with CLASS fields
                    attr.append('default={0}'.format(set_to_defin(ASN1Set(Obj._flag[FLAG_DEF]), Obj, self)))
                else:
                    if Obj._mode == MODE_TYPE:
                        par = Obj._parent
                        while par is not None:
                            if par.TYPE == TYPE_CLASS:
                                assert()
                            par = par._parent
                    attr.append('default={0}'.format(value_to_defin(Obj._flag[FLAG_DEF], Obj, self)))
            if Obj.TYPE == TYPE_ANY and Obj._flag and FLAG_DEFBY in Obj._flag:
                attr.append('defby={0!r}'.format(Obj._flag[FLAG_DEFBY]))
            if Obj._flag and FLAG_UNIQ in Obj._flag:
                attr.append('uniq=True')
            if Obj._group is not None:
                attr.append('group={0!r}'.format(Obj._group))
        return ', '.join(attr)
    
    #--------------------------------------------------------------------------#
    # specific types
    #--------------------------------------------------------------------------#
    
    def gen_type_bool(self, Obj):
        # value constraint
        self.gen_const_val(Obj)
    
    def gen_type_int(self, Obj):
        # named integer values
        if Obj._cont:
            # Cont is an ASN1Dict with {str: int}
            self.wrl('{0}._cont = ASN1Dict({1!r})'.format(Obj._pyname, list(Obj._cont.items())))
        # value constraint
        self.gen_const_val(Obj)
    
    def gen_type_real(self, Obj):
        # components constraint
        self.gen_const_comps(Obj)
        # value constraint
        self.gen_const_val(Obj)
    
    def gen_type_enum(self, Obj):
        # enum content
        if Obj._cont:
            self.wrl('{0}._cont = ASN1Dict({1!r})'.format(Obj._pyname, list(Obj._cont.items())))
            if Obj._ext is None:
                self.wrl('{0}._ext = None'.format(Obj._pyname))
            else:
                self.wrl('{0}._ext = {1!r}'.format(Obj._pyname, Obj._ext))
        # value constraint
        self.gen_const_val(Obj)
    
    def gen_type_bitstr(self, Obj):
        # content: named bit offsets
        if Obj._cont:
            # Cont is an ASN1Dict with {str: int}
            self.wrl('{0}._cont = ASN1Dict({1!r})'.format(Obj._pyname, list(Obj._cont.items())))
        # value constraint
        self.gen_const_val(Obj)
        # size constraint
        self.gen_const_sz(Obj)
        # containing constraint
        self.gen_const_contain(Obj)
    
    def gen_type_octstr(self, Obj):
        # value constraint
        self.gen_const_val(Obj)
        # size constraint
        self.gen_const_sz(Obj)
        # containing constraint
        self.gen_const_contain(Obj)
    
    def gen_type_oid(self, Obj):
        # value constraint
        self.gen_const_val(Obj)
    
    def gen_type_str(self, Obj):
        # value constraint
        self.gen_const_val(Obj)
        # size constraint
        self.gen_const_sz(Obj)
        # alphabet constraint
        Consts_alpha = [C for C in Obj.get_const() if C['type'] == CONST_ALPHABET]
        if Consts_alpha:
            Salpha = reduce_setdicts(Consts_alpha)
            self.wrl('{0}._const_alpha = {1}'.format(Obj._pyname, set_to_defin(Salpha, Obj, self)))
    
    def gen_type_time(self, Obj):
        # value constraint
        self.gen_const_val(Obj)
    
    def gen_type_choice(self, Obj):
        # components constraint
        self.gen_const_comps(Obj)
        # content: ASN1Dict of {name: ASN1Obj}
        if Obj._cont is not None:
            # create all objects of the content first
            links = ASN1Dict()
            for name in Obj._cont:
                Cont = Obj._cont[name]
                Cont._pyname = '_{0}_{1}'.format(Obj._pyname, name_to_defin(Cont._name))
                self.gen_type(Cont, compts=True)
                links[name] = Cont._pyname
            # now link all of them in an ASN1Dict into the Obj content
            self.wrl('{0}._cont = ASN1Dict(['.format(Obj._pyname))
            for name in links:
                self.wrl('    ({0!r}, {1}),'.format(name, links[name]))
            self.wrl('    ])')
            # extension
            if Obj._ext is None:
                self.wrl('{0}._ext = None'.format(Obj._pyname))
            else:
                self.wrl('{0}._ext = {1!r}'.format(Obj._pyname, Obj._ext))
        # value constraint
        self.gen_const_val(Obj)
    
    def gen_type_seq(self, Obj):
        # components constraint
        self.gen_const_comps(Obj)
        # content: ASN1Dict of {name: ASN1Obj}
        if Obj._cont is not None:
            # create all objects of the content first
            links = ASN1Dict()
            for name in Obj._cont:
                Cont = Obj._cont[name]
                Cont._pyname = '_{0}_{1}'.format(Obj._pyname, name_to_defin(Cont._name))
                self.gen_type(Cont, compts=True)
                links[name] = Cont._pyname
            # now link all of them in an ASN1Dict into the Obj content
            self.wrl('{0}._cont = ASN1Dict(['.format(Obj._pyname))
            for name in links:
                self.wrl('    ({0!r}, {1}),'.format(name, links[name]))
            self.wrl('    ])')
            # extension
            if Obj._ext is None:
                self.wrl('{0}._ext = None'.format(Obj._pyname))
            else:
                self.wrl('{0}._ext = {1!r}'.format(Obj._pyname, Obj._ext))
        # value constraint
        self.gen_const_val(Obj)
    
    def gen_type_seqof(self, Obj):
        # component constraint
        self.gen_const_comp(Obj)
        # content: ASN1Obj
        if Obj._cont is not None:
            # create the object of the content first
            Cont = Obj._cont
            Cont._pyname = '_{0}_{1}'.format(Obj._pyname, name_to_defin(Cont._name))
            self.gen_type(Cont)
            # now link it to the Obj content
            self.wrl('{0}._cont = {1}'.format(Obj._pyname, Cont._pyname))
        # value constraint
        self.gen_const_val(Obj)
        # size constraint
        self.gen_const_sz(Obj)
    
    def gen_type_class(self, Obj):
        # content: ASN1Dict of {name: ASN1Obj}
        if Obj._cont is not None:
            # create all objects of the content first
            links = ASN1Dict()
            for name in Obj._cont:
                Cont = Obj._cont[name]
                Cont._pyname = '_{0}_{1}'.format(Obj._pyname, name_to_defin(Cont._name))
                self.gen_type(Cont, compts=True)
                links[name] = Cont._pyname
            # now link all of them in an ASN1Dict into the Obj content
            self.wrl('{0}._cont = ASN1Dict(['.format(Obj._pyname))
            for name in links:
                self.wrl('    ({0!r}, {1}),'.format(name, links[name]))
            self.wrl('    ])')
    
    def gen_type_open(self, Obj):
        if Obj._cont:
            assert()
        # value constraint for OPEN types are actually other ASN.1 types...
        Consts_val = [C for C in Obj._const if C['type'] == CONST_VAL]
        if Consts_val:
            if len(Consts_val) > 1:
                asnlog('WNG: {0}.{1}: multiple OPEN type value constraints, compiling only '\
                       'the first'.format(self._mod_name, Obj._name))
            Const = Consts_val[0]
            # process the root part of the constraint
            ind = 0
            if Const['root']:
                root = []
                for O in Const['root']:
                    O._pyname = '_{0}_val_{1!r}'.format(Obj._pyname, ind)
                    self.gen_type(O)
                    ind += 1
                    root.append(O._pyname)
                root = '[{0}]'.format(', '.join(root))
            else:
                root = '[]'
            # process the extended part of the constraint
            if Const['ext'] is not None:
                ext = []
                for O in Const['ext']:
                    O._pyname = '_{0}_val_{1!r}'.format(Obj._pyname, ind)
                    self.gen_type(O)
                    ind += 1
                    ext.append(O._pyname)
                ext = '[{0}]'.format(', '.join(ext))
            else:
                ext = 'None'
            # creates the ASN1Set which links to the object
            self.wrl('{0}._const_val = ASN1Set(rv={1}, ev={2})'.format(Obj._pyname, root, ext))
        if [C for C in Obj.get_const() if C['type'] not in \
        (CONST_TABLE, CONST_VAL, CONST_CONSTRAIN_BY)]:
            assert()
    
    def gen_type_ext(self, Obj):
        # TODO: apply CONST_COMPS if exists
        pass
    
    def gen_type_embpdv(self, Obj):
        # TODO: apply CONST_COMPS if exists
        pass
    
    def gen_type_charstr(self, Obj):
        # TODO: apply CONST_COMPS if exists
        pass
    
    #--------------------------------------------------------------------------#
    # specific constraints
    #--------------------------------------------------------------------------#
    
    def gen_const_sz(self, Obj):
        # if no local size constraint, just return
        if not [C for C in Obj._const if C['type'] == CONST_SIZE]:
            return
        # size constraint: reducing all size constraint to a single one
        Consts_size = [C for C in Obj.get_const() if C['type'] == CONST_SIZE]
        if Consts_size:
            # size is a set of INTEGER values
            SzProxy = INT()
            Ssz = reduce_setdicts(Consts_size)
            # SIZE has always an lb of 0 for range, even if they are defined as (MIN..XYZ)
            for rr in Ssz._rr:
                if rr.lb is None:
                    rr.lb = 0
            for er in Ssz._er:
                if er.lb is None:
                    er.lb = 0
            self.wrl('{0}._const_sz = {1}'.format(Obj._pyname, set_to_defin(Ssz, SzProxy, self)))
    
    def gen_const_val(self, Obj):
        # if no local value constraint, just return
        if not [C for C in Obj._const if C['type'] == CONST_VAL]:
            return
        # value constraint: reducing all value constraint to a single one
        Consts_val = [C for C in Obj.get_const() if C['type'] == CONST_VAL \
                      and ('excl' not in C or C['excl'] == False)]
        Consts_val_excl = [C for C in Obj.get_const() if C['type'] == CONST_VAL \
                           and ('excl' in C and C['excl'] == True)]
        if Consts_val:
            Sval = reduce_setdicts(Consts_val)
            if Consts_val_excl:
                # TODO: support removing excluded values
                pass
            self.wrl('{0}._const_val = {1}'.format(Obj._pyname, set_to_defin(Sval, Obj, self)))
    
    def gen_const_table(self, Obj):
        # table constraint: processing only a local and single constraint
        Consts_tab = [C for C in Obj._const if C['type'] == CONST_TABLE]
        if Consts_tab:
            if len(Consts_tab) > 1:
                asnlog('WNG: {0}.{1}: multiple table constraint, but compiling only the first'\
                       .format(self._mod_name, Obj._name))
            Const = Consts_tab[0]
            link_name = None
            # check if the same constraint was already defined somewhere in the root object
            if hasattr(self, '_const_tabs'):
                ConstTabVal = Const['tab'].get_val()
                if len(ConstTabVal['root']) \
                or ConstTabVal['ext'] is not None and len(ConstTabVal['ext']):
                    # ensure the table as actual value(s) inside 
                    for ct in self._const_tabs:
                        # HOLLY PYTHON: comparing damned complex dict values...
                        if ConstTabVal == ct[1]:
                            # the table of values get already compiled, just need to link it
                            link_name = ct[0]
                            break
            if link_name is None:
                # create the table set object
                Const['tab']._pyname = '_{0}_tab'.format(Obj._pyname)
                self.gen_set(Const['tab'])
                link_name = Const['tab']._pyname
                if not hasattr(self, '_const_tabs'):
                    self._const_tabs = [(link_name, Const['tab'].get_val())]
                else:
                    self._const_tabs.append( (link_name, Const['tab'].get_val()) )
            # now link it to the Obj constraint
            self.wrl('{0}._const_tab = {1}'.format(Obj._pyname, link_name))
            # define the @ identifier
            if Const['at'] is None:
                self.wrl('{0}._const_tab_at = None'.format(Obj._pyname))
            else:
                self.wrl('{0}._const_tab_at = {1!r}'.format(Obj._pyname, tuple(Const['at'])))
            # define the table object identifier
            try:
                self.wrl('{0}._const_tab_id = {1}'.format(Obj._pyname, repr(Obj._typeref.ced_path[-1])))
            except:
                asnlog('WNG: {0}.{1}: unavailable table constraint ident, not compiling it'\
                       .format(self._mod_name, Obj._name))
                self.wrl('{0}._const_tab_id = None')
    
    def gen_const_contain(self, Obj):
        # CONTAINING constraint: processing only a local and single constraint
        Consts_contain = [C for C in Obj._const if C['type'] == CONST_CONTAINING]
        if Consts_contain:
            if len(Consts_contain) > 1:
                asnlog('WNG: {0}.{1}: multiple CONTAINING constraint, compiling only '\
                       'the first'.format(self._mod_name, Obj._name))
            Const = Consts_contain[0]
            if Const['enc'] is not None:
                # Const['enc'] is an OID value
                EncProxy = OID()
                self.wrl('{0}._const_cont_enc = {1}'\
                         .format(Obj._pyname, value_to_defin(Const['enc'], EncProxy, self)))
            else:
                # create the contained object first
                Const['obj']._pyname = '_{0}_contain'.format(Obj._pyname)
                self.gen_type(Const['obj'])
                # now link it to the Obj constraint
                self.wrl('{0}._const_cont = {1}'.format(Obj._pyname, Const['obj']._pyname))
    
    def gen_const_comp(self, Obj):
        # WITH COMPONENT constraint
        Consts_comp = [C for C in Obj._const if C['type'] == CONST_COMP]
        if Consts_comp:
            # TODO: need to add support for WITH COMPONENT in the compiler
            pass
    
    def gen_const_comps(self, Obj):
        # WITH COMPONENTS constraint: processing only a single constraint
        Consts_comps = [C for C in Obj._const if C['type'] == CONST_COMPS]
        if Consts_comps:
            if len(Consts_comps) > 1:
                asnlog('WNG: {0}.{1}: multiple WITH COMPONENTS constraints, '\
                       'generating only the first'.format(self._mod_name, Obj._name))
            if Consts_comps[0]['ext'] is not None:
                asnlog('INF: {0}.{1}: extensible WITH COMPONENTS constraint, '\
                       'not generating extension'.format(self._mod_name, Obj._name))
            if not Consts_comps[0]['root']:
                return
            '''
            if len(Consts_comps[0]['root']) > 1:
                asnlog('WNG: {0}.{1}: multiple root parts in WITH COMPONENTS constraint, '\
                       'processing only the common components'.format(self._mod_name, Obj._name))
            '''
            #
            # 1) duplicate the content structure of the object
            if not Obj._cont:
                cont, Obj._ext = Obj.get_cont(wext=True)
                Obj._cont = cont.copy()
            else:
                Obj._cont = Obj._cont.copy()
            for ident, Comp in Obj._cont.items():
                Obj._cont[ident] = Comp.__class__(Comp)
            #
            '''
            # TODO: components need actually to stay there, and be kept OPTIONAL
            # this is required for proper encoding (mainly PER, OER)
            # These COMPONENTS constraints need actually to be checked at runtime 
            # in addition to existing ones, without impacting the structure
            # of objects content.
            #
            # 2) handle absent / present components
            # gathering present / absent components from the potentially 
            # multiple possibilities, and keeping only the ones in common
            pres, abse = set(Consts_comps[0]['root'][0]['_pre']), set(Consts_comps[0]['root'][0]['_abs'])
            for Const in Consts_comps[0]['root'][1:]:
                pres.intersection_update(Const['_pre'])
                abse.intersection_update(Const['_abs'])
            for ident in abse:
                # remove the component
                del Obj._cont[ident]
            if Obj.TYPE != TYPE_CHOICE:
                # for CHOICE, the constraint parsing takes care to set in _abs
                # all components to be removed, when a component is set in _pre
                # therefore, present components only need to be set as non optional
                # for SEQUENCE
                for ident in pres:
                    if FLAG_OPT in Obj._cont[ident]._flag:
                        del Obj._cont[ident]._flag[FLAG_OPT]
            '''
            #
            if len(Consts_comps[0]['root']) > 1:
                asnlog('WNG: {0}.{1}: multiple root parts in WITH COMPONENTS constraint, '\
                       'unable to compile them'.format(self._mod_name, Obj._name))
                return
            #
            # 3) apply additional constraint on components
            # only if we have a single root component in the constraint
            Const    = Consts_comps[0]['root'][0]
            Const_kw = set(Const.keys())
            Const_kw.remove('_pre')
            Const_kw.remove('_abs')
            for ident in Const_kw:
                Obj._cont[ident]._const = list(Obj._cont[ident]._const)
                Obj._cont[ident]._const.extend(Const[ident]['const'])
                #print('%s.%s: %r' % (Obj._name, ident, Obj._cont[ident]._const))


#------------------------------------------------------------------------------#
# JSON graph dependency generator
#------------------------------------------------------------------------------#
# generate a JSON file listing all ASN.1 objects dependencies
# then usable with the force-directed graph at https://bl.ocks.org/mbostock/4062045
# node.group is the module which hosts the object
# link.value is a fixed value
# WNG: for large ASN.1 specification, the web browser dies...

def asnmod_build_dep(mods):
    """
    Returns two dicts:
    - one listing all {caller ASN1Obj: list of called ASN1Obj}
    - one listing all {called ASN1Obj: list of caller ASN1Obj} 
    """
    # build two dicts:
    # 1 of {called_object: list of caller objects}
    # 1 of {caller_object: list of called objects}
    CallerDict, CalledDict = {}, {}
    for mod in mods:
        Mod = mods[mod]
        for name in Mod:
            if name[0] != '_':
                Obj = Mod[name]
                objname = (mod, Obj._name)
                for Ref in Obj._ref:
                    if Ref.called in CalledDict:
                        if objname not in CalledDict[Ref.called]:
                            CalledDict[Ref.called].append( objname )
                    else:
                        CalledDict[Ref.called] = [ objname ]
                    if objname in CallerDict:
                        if Ref not in CallerDict[objname]:
                            CallerDict[objname].append( Ref )
                    else:
                        CallerDict[objname] = [ Ref ]
    return CallerDict, CalledDict

class JSONDepGraphGenerator(_Generator):
    """
    JSONDepGraphGenerator generates a JSON file that enables to produce a directed
    graph representing all ASN.1 caller objects linked to all other called objects
    
    The JSON file can be used directly with https://bl.ocks.org/mbostock/4062045
    to be visualized
    """
    
    # the link force is fixed for all linked between caller / callee objects
    LINK_FORCE = 1
    
    def gen(self):
        #
        groups = list(GLOBAL.MOD.keys())
        #
        # building 2 dicts: 1 with referrers objects, 1 with referred objects
        obj_refr, obj_refd = asnmod_build_dep(GLOBAL.MOD)
        #
        self.wrl('{')
        self.indent += 2
        self.wrl('"_comment": "code automatically generated by pycrate_asn1c",')
        #
        self.wrl('"nodes": [')
        self.indent += 2
        nodes = []
        for mod in GLOBAL.MOD:
            if '_obj_' in GLOBAL.MOD[mod]:
                for name in GLOBAL.MOD[mod]['_obj_']:
                    nodes.append('{"id": "%s.%s", "group": %i},'\
                                 % (mod, name, groups.index(mod)))
        # remove last coma
        #nodes[-1] = nodes[-1][:-1]
        last_node = nodes[-1]
        #print('last_node:', last_node)
        del nodes[-1]
        nodes.append( last_node[:-1] )
        #
        for l in nodes:
            self.wrl(l)
        #
        self.indent -= 2
        self.wrl('],')
        #
        self.wrl('"links": [')
        self.indent += 2
        links = []
        for (mod, name) in obj_refr:
            for tgt in obj_refr[(mod, name)]:
                if isinstance(tgt.called, tuple) and \
                len(tgt.called) == 2 and tgt.called[1]:
                    tgt = list(tgt.called)
                    # we must ensure that tgt is really defined within tgt.called[0]
                    # and not imported from another module
                    while tgt[1] not in GLOBAL.MOD[tgt[0]]:
                        tgt[0] = GLOBAL.MOD[tgt[0]]['_imp_'][tgt[1]]
                    links.append('{"source": "%s.%s", "target": "%s.%s", "value": %i},'\
                                 % (mod, name, tgt[0], tgt[1], self.LINK_FORCE))
        # remove last coma
        #links[-1] = links[-1][:-1]
        last_link = links[-1]
        #print('last_link:', last_link)
        del links[-1]
        links.append( last_link[:-1] )
        #
        for l in links:
            self.wrl(l)
        #
        self.indent -= 2
        self.wrl(']')
        #
        self.indent -= 2
        self.wrl('}')

