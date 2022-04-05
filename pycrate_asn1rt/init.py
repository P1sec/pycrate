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
# * File Name : pycrate_asn1rt/init.py
# * Created : 2017-01-31
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils  import *
from .glob   import *
from .refobj import *
from .setobj import *
from .codecs import ASN1CodecBER


def init_modules(*args, **kwargs):
    """
    Generates the GLOBAL.MOD dict referencing all compiled objects
    And for each defined objects:
    - set the _parent attribute for objects inside constructed objects
    - set the _root_*, _ext_*, _cont_tags
    - translates the _typeref attribute from ASN1Ref to a ref to the current ASN1Obj instance
    - bind content and constraints attributes to those from inherited types
    
    args: the list of ASN.1 classes
    kwargs:
        GLOBAL: a specific GLOBAL dict, default is the generic GLOBAL
    """
    if 'GLOBAL' in kwargs:
        GLOB = kwargs['GLOBAL']
    else:
        GLOB = GLOBAL
    for Mod in args:
        GLOB.MOD[Mod._name_] = ASN1Dict()
        GLOB.MOD[Mod._name_]['_oid_']   = Mod._oid_
        GLOB.MOD[Mod._name_]['_obj_']   = Mod._obj_
        if Mod.__name__[:1] != '_':
            # do not process special modules _IMPL_ and _USER_
            GLOB.MOD[Mod._name_]['_type_']  = Mod._type_
            GLOB.MOD[Mod._name_]['_set_']   = Mod._set_
            GLOB.MOD[Mod._name_]['_val_']   = Mod._val_
            GLOB.MOD[Mod._name_]['_class_'] = Mod._class_
            GLOB.MOD[Mod._name_]['_param_'] = Mod._param_
        #
        for objname in Mod._obj_:
            GLOB.MOD[Mod._name_][objname] = getattr(Mod, name_to_defin(objname))
    #
    # set special attributes for some objects
    for Mod in args:
        for Obj in Mod._all_:
            #
            # useful for debugging...
            Obj._mod = Mod._name_
            #
            # setting additional attributes
            if Obj.TYPE == TYPE_INT:
                if Obj._cont is not None:
                    Obj._cont_rev = {Obj._cont[name]: name for name in Obj._cont}
                if Obj._const_val:
                    Obj._const_val._set_root_bnd()
            #
            elif Obj.TYPE in TYPES_CONST_SZ:
                if Obj._const_sz:
                    Obj._const_sz._set_root_bnd()
                #
                if Obj.TYPE == TYPE_BIT_STR:
                    if Obj._cont:
                        Obj._cont_rev = {Obj._cont[name]: name for name in Obj._cont}
                #
                if Obj.TYPE in TYPES_STRING and Obj._const_alpha:
                    Obj._const_alpha._set_root_bnd()
                #
                elif Obj.TYPE in (TYPE_BIT_STR, TYPE_OCT_STR) and Obj._const_cont is not None:
                    # set _const_cont_enc if not defined
                    if not hasattr(Obj, '_const_cont_enc'):
                        Obj._const_cont_enc = None
                #
                elif Obj.TYPE in (TYPE_SEQ_OF, TYPE_SET_OF) and Obj._cont is not None:
                    # set _parent for the component
                    Obj._cont._parent = Obj
            #
            elif Obj.TYPE == TYPE_ENUM and Obj._cont is not None:
                # set _root
                if not Obj._ext:
                    Obj._root = list(Obj._cont.keys())
                else:
                    Obj._root = []
                    for name in Obj._cont:
                        if name not in Obj._ext:
                            Obj._root.append(name)
                # set _cont_rev
                Obj._cont_rev  = {Obj._cont[name]: name for name in Obj._cont}
                # set _const_ind
                if Obj._ext is None:
                    Obj._const_ind = ASN1Set(rr=[ASN1RangeInt(0, len(Obj._root)-1)])
                elif not Obj._ext:
                    Obj._const_ind = ASN1Set(rr=[ASN1RangeInt(0, len(Obj._root)-1)], ev=[])
                else:
                    Obj._const_ind = ASN1Set(rr=[ASN1RangeInt(0, len(Obj._root)-1)], ev=[],
                                             er=[ASN1RangeInt(0, len(Obj._ext)-1)])
                Obj._const_ind._set_root_bnd()
            #
            elif Obj.TYPE in (TYPE_CHOICE, TYPE_SEQ, TYPE_SET, TYPE_CLASS) and Obj._cont is not None:
                # set _parent for each component
                for Comp in Obj._cont.values():
                    Comp._parent = Obj
                #
                if Obj.TYPE == TYPE_CHOICE:
                    # set _root, _const_ind
                    Obj._root, ext = [], []
                    if Obj._ext is not None:
                        ext = Obj._ext
                    for name in Obj._cont:
                        if name in ext:
                            break
                        else:
                            Obj._root.append(name)
                    if Obj._ext is None:
                        Obj._const_ind = ASN1Set(rr=[ASN1RangeInt(0, len(Obj._root)-1)])
                    elif not Obj._ext:
                        Obj._const_ind = ASN1Set(rr=[ASN1RangeInt(0, len(Obj._root)-1)], ev=[])
                    else:
                        Obj._const_ind = ASN1Set(rr=[ASN1RangeInt(0, len(Obj._root)-1)], ev=[],
                                                 er=[ASN1RangeInt(0, len(Obj._ext)-1)])
                    Obj._const_ind._set_root_bnd()
                else:
                    # set _root, _root_mand, _root_opt
                    Obj._root, Obj._root_mand, Obj._root_opt, ext = [], [], [], []
                    if Obj._ext is not None:
                        ext = Obj._ext
                    for name, Comp in Obj._cont.items():
                        if name in ext:
                            break
                        if Comp._opt or Comp._def is not None:
                            Obj._root_opt.append(name)
                        else:
                            Obj._root_mand.append(name)
                        Obj._root.append(name)
                #
                if Obj.TYPE != TYPE_CLASS:
                    # set _ext_ident, _ext_group
                    if Obj._ext is not None:
                        Obj._ext_ident, Obj._ext_group = {}, {}
                        for name in Obj._ext:
                            Comp = Obj._cont[name]
                            if Comp._group is not None:
                                Obj._ext_ident[name] = Comp._group
                                if Comp._group not in Obj._ext_group:
                                    Obj._ext_group[Comp._group] = []
                                Obj._ext_group[Comp._group].append(name)
                #
                if Obj.TYPE in (TYPE_SEQ, TYPE_SET) and Obj._ext is not None:
                    # set _ext_nest and _ext_group_obj
                    Obj._ext_nest, Obj._ext_group_obj = [], {}
                    for ident in Obj._ext:
                        if ident in Obj._ext_ident:
                            # ident is in a group
                            g_idents = Obj._ext_group[Obj._ext_ident[ident]]
                            if g_idents.index(ident) == 0:
                                # 1st component of the group
                                Obj._ext_nest.append( [ident] )
                            else:
                                Obj._ext_nest[-1].append(ident)
                        else:
                            Obj._ext_nest.append(ident)
                    #
                    for gid, idents in Obj._ext_group.items():
                        GSeq = Obj.__class__(name='%s_ext_%d' % (Obj._name, gid),
                                             mode=MODE_TYPE)
                        GSeq._cont = ASN1Dict([(i, Obj._cont[i]) for i in idents])
                        GSeq._parent = Obj
                        GSeq._root = idents
                        GSeq._ext  = None
                        GSeq._root_mand = [i for i in idents if Obj._cont[i]._opt is False and \
                                                                Obj._cont[i]._def is None]
                        GSeq._root_opt  = [i for i in idents if i not in GSeq._root_mand]
                        # add a specific attribute
                        GSeq._gext = True
                        Obj._ext_group_obj[gid] = GSeq
            #
            elif Obj.TYPE == TYPE_OID and Obj._mode == MODE_VALUE:
                if Obj._val in GLOB.OID and GLOB.OID[Obj._val] != Obj._name:
                    if not Obj._SILENT:
                        asnlog('init_modules: different OID objects (%s, %s) with same OID value %r'\
                               % (Obj._name, GLOB.OID[Obj._val], Obj._val))
                elif Obj._val is not None:
                    GLOB.OID[Obj._val] = Obj._name
            #
            elif Obj.TYPE == TYPE_CLASS and Obj._mode == MODE_SET and Obj._val:
                # this should not conflict with the previous check on TYPE_CLASS
                # which must have self._cont defined (hence being MODE_TYPE)
                build_classset_dict(Obj)
                
    #
    # lists all objects defined
    Objs = [Obj for Mod in args for Obj in Mod._all_]
    # lists all objects which inherits in some way from another one
    TRObjs = [Obj for Obj in Objs if Obj._typeref is not None]
    #
    while TRObjs:
        #asnlog('remaining objects: {0!r}'.format(len(Objs)))
        for Obj in TRObjs:
            try:
                # resolve cross-reference
                Obj._tr = get_typeref(Obj, GLOB)
            except:
                pass
            else:
                # this binding step is necessary in order to resolve ref to inner
                # objects (ASN1RefClassField, ASN1RefChoiceComp, ...)
                bind_all_attrs(Obj)
                TRObjs.remove(Obj)
    #
    # When all typeref are resolved, we can set the tag chain and bind attributes 
    # for all objects
    for Obj in Objs:
        Obj._tagc = get_tag_chain(Obj)
        if Obj._typeref is not None:
            bind_all_attrs(Obj)
    #
    # We need another round, at least to set tag-object lookup properly for
    # constructed object
    for Obj in Objs:
        if Obj.TYPE == TYPE_SEQ:
            # set a list of tags for the content
            Obj._cont_tags = [Cont._tagc[0] if Cont._tagc else None for Cont in Obj._cont.values()]
        elif Obj.TYPE == TYPE_CHOICE:
            # set an ASN1Dict of tags: objects for the content
            Obj._cont_tags = get_cont_tags_dict(Obj)
        elif Obj.TYPE == TYPE_SET:
            # set an ASN1Dict of tags: objects for the content
            Obj._cont_tags = get_cont_tags_dict(Obj)
            # add the canonical list of root components according to their tag
            Obj._root_canon = get_cont_tags_canon(Obj)
        #
        # additionally, we make safe checks on all generated objects
        if Obj._SAFE_INIT:
            Obj._safechk_obj()
            if Obj._mode == MODE_VALUE:
                try:
                    Obj._safechk_val(Obj._val)
                except Exception as err:
                    # in case Obj is a field within a CLASS, val can be None
                    par = Obj._parent
                    while par and par.TYPE != TYPE_CLASS:
                        par = par._parent
                    if not par or par.TYPE != TYPE_CLASS:
                        raise(err)
                    elif Obj._val is not None:
                        raise(err)
            elif Obj._mode == MODE_SET:
                try:
                    Obj._safechk_set(Obj._val)
                except Exception as err:
                    # in case Obj is a field within a CLASS, val can be None
                    par = Obj._parent
                    while par and par.TYPE != TYPE_CLASS:
                        par = par._parent
                    if not par or par.TYPE != TYPE_CLASS:
                        raise(err)
                    elif Obj._val is not None:
                        raise(err)


def get_typeref(Obj, GLOB=GLOBAL):
    """
    returns the ASN.1 object corresponding to the typered (ASN1Ref) of Obj
    """
    ref = Obj._typeref
    #
    if isinstance(ref, (ASN1RefType, ASN1RefInstOf)):
        assert( ref.called is not None and ref.ced_path == [] )
        tr = get_asnobj(ref, GLOB)
    #
    elif isinstance(ref, ASN1RefClassField):
        assert( ref.called is not None and len(ref.ced_path) >= 1 )
        cla = get_asnobj(ref, GLOB)
        if cla._param:
            # parameterized object are not compiled
            return None
        classpath = ref.ced_path[:]
        while len(classpath) > 1:
            tr = cla._cont[classpath[0]]
            if tr._typeref is None:
                # CLASS locally defined within CLASS
                cla = tr
            else:
                cla = get_typeref(tr, GLOB)
            del classpath[0]
        tr = cla._cont[classpath[0]]
    #
    elif isinstance(ref, ASN1RefClassIntern):
        assert( ref.called is None and len(ref.ced_path) >= 1 )
        cla = self._parent
        classpath = ref.ced_path[:]
        while len(classpath) > 1:
            tr = cla._cont[classpath[0]]
            if tr._typeref is None:
                # CLASS locally defined within CLASS
                cla = tr
            else:
                cla = get_typeref(tr, GLOB)
            del classpath[0]
        tr = cla._cont[classpath[0]]
    #
    elif isinstance(ref, ASN1RefClassValField):
        assert( ref.called is not None and len(ref.ced_path) >= 1 )
        cla = get_asnobj(ref, GLOB)
        if cla._param:
            # parameterized object are not compiled
            return None
        claval = cla._val
        classpath = ref.ced_path[:]
        while len(classpath) > 0:
            claval = claval[classpath[0]]
            del classpath[0]
        tr = claval
    #
    elif isinstance(ref, ASN1RefChoiceComp):
        assert( ref.called is not None and len(ref.ced_path) >= 1 )
        cho = get_asnobj(ref, GLOB)
        if cho._param:
            # parameterized object are not compiled
            return None
        choicepath = ref.ced_path[:]
        while len(choicepath) > 1:
            tr = cho._cont[choicepath[0]]
            if tr._typeref is None:
                # CHOICE locally defined within CHOICE
                cho = tr
            else:
                cho = get_typeref(tr, GLOB)
            del choicepath[0]
        tr = cho._cont[choicepath[0]] 
    #
    return tr


def get_tag_chain(Obj):
    """
    returns the list of tags from self up to the last referred object
    
    in case one tag is IMPLICIT, the next tag is not put in the list
    """
    obj, tagc, impl = Obj, [], False
    while obj is not None:
        if obj._tag is not None:
            if not impl:
                tagc.append( (ASN1CodecBER.TagClassLUT[obj._tag[1]], obj._tag[0]) )
            if obj._tag[2] == TAG_IMPLICIT:
                impl = True
            else:
                impl = False
        obj = obj._tr
    if not impl and Obj.TYPE not in (TYPE_CHOICE, TYPE_OPEN, TYPE_ANY):
        # add the universal tag
        tagc.append( (0, Obj.TAG) )
    return tagc


def get_cont_tags_dict(Obj):
    """
    returns the ASN1Dict of tags, object for the content of Obj (SET and CHOICE)
    """
    tagd = ASN1Dict()
    for ident, Comp in Obj._cont.items():
        if not Comp._tagc:
            # untagged component
            if Comp.TYPE == TYPE_CHOICE:
                if hasattr(Comp, '_cont_tags'):
                    cho_tagd = Comp._cont_tags
                else:
                    cho_tagd = get_cont_tags_dict(Comp)
                for t in cho_tagd:
                    if t in tagd:
                        assert()
                    cho_ident = cho_tagd[t]
                    if isinstance(cho_ident, list):
                        tagd[t] = [Comp._name] + cho_ident
                    else:
                        tagd[t] = [Comp._name, cho_ident]
            elif Comp.TYPE in (TYPE_OPEN, TYPE_ANY):
                assert()
            else:
                assert()
        elif Comp._tagc[0] in tagd:
            assert()
        else:
            tagd[Comp._tagc[0]] = ident
    return tagd


def get_cont_tags_canon(Obj):
    """
    returns the list of components in the canonical order of their tags
    """
    tagcan = ASN1Dict()
    for ident in Obj._root:
        Comp = Obj._cont[ident]
        if not Comp._tagc:
            # untagged component
            if Comp.TYPE == TYPE_CHOICE:
                cho_tags = get_cont_tags_dict(Comp)
                # use the "lowest" tag of the dict to order it
                cho_tag = sorted(cho_tags.keys())[0]
                if cho_tag in tagcan:
                    assert()
                tagcan[cho_tag] = ident
            elif Comp.TYPE in (TYPE_OPEN, TYPE_ANY):
                assert()
            else:
                assert()
        elif Comp._tagc[0] in tagcan:
            assert()
        else:
            tagcan[Comp._tagc[0]] = ident
    # order the whole stuff
    return [tagcan[k] for k in sorted(tagcan.keys())]


def bind_attrs(Obj, *attrs):
    attr = attrs[0]
    if getattr(Obj, attr) is None:
        tr = Obj._tr if (Obj._tr is not None and not Obj._tr._param) else None
        # look recursively into typeref
        while tr is not None:
            try:
                v = getattr(tr, attr)
            except Exception as err:
                # this can happen when binding certain ASN.1 native types to
                # SEQUENCE object in the _IMPL_ module
                if tr._name in (TYPE_REAL, TYPE_EXT, TYPE_EMB_PDV, TYPE_CHAR_STR):
                    return
                else:
                    raise(err)
            if v is not None:
                setattr(Obj, attr, v)
                if len(attrs) > 1:
                    for a in attrs[1:]:
                        setattr(Obj, a, getattr(tr, a))
                tr = None
            else:
                tr = tr._tr if (tr._tr is not None and not tr._tr._param) else None


def bind_all_attrs(Obj):
    # bind content and constraints from typeref objects
    # _cont, _root, _ext, _root_mand, _root_opt, _ext_ident, _ext_group, cont_tags
    # _const_val, _const_sz, _const_tab, _const_tab_id, _const_tab_at, _const_cont, _const_alpha
    bind_attrs(Obj, '_const_val')
    bind_attrs(Obj, '_const_tab', '_const_tab_id', '_const_tab_at')
    if Obj.TYPE == TYPE_INT:
        bind_attrs(Obj, '_cont', '_cont_rev')
    elif Obj.TYPE in (TYPE_REAL):
        bind_attrs(Obj, '_cont', '_root', '_root_mand', '_root_opt')
        bind_attrs(Obj, '_ext')
    elif Obj.TYPE == TYPE_ENUM:
        bind_attrs(Obj, '_cont', '_root', '_ext', '_cont_rev', '_const_ind')
    elif Obj.TYPE == TYPE_BIT_STR:
        bind_attrs(Obj, '_cont', '_cont_rev')
        bind_attrs(Obj, '_const_sz')
        bind_attrs(Obj, '_const_cont', '_const_cont_enc')
    elif Obj.TYPE == TYPE_OCT_STR:
        bind_attrs(Obj, '_const_sz')
        bind_attrs(Obj, '_const_cont', '_const_cont_enc')
    elif Obj.TYPE in TYPES_STRING:
        bind_attrs(Obj, '_const_sz')
        bind_attrs(Obj, '_const_alpha')
    elif Obj.TYPE in (TYPE_SEQ_OF, TYPE_SET_OF):
        bind_attrs(Obj, '_cont')
        bind_attrs(Obj, '_const_sz')
    elif Obj.TYPE == TYPE_CHOICE:
        bind_attrs(Obj, '_cont', '_root', '_ext', '_const_ind')
    elif Obj.TYPE in (TYPE_SEQ, TYPE_SET):
        bind_attrs(Obj, '_cont', '_root', '_root_mand', '_root_opt')
        bind_attrs(Obj, '_ext', '_ext_nest', '_ext_ident', '_ext_group', '_ext_group_obj')
    elif Obj.TYPE == TYPE_CLASS:
        bind_attrs(Obj, '_cont', '_root', '_root_mand', '_root_opt')
    elif Obj.TYPE in (TYPE_EXT, TYPE_EMB_PDV, TYPE_CHAR_STR):
        bind_attrs(Obj, '_cont', '_root', '_root_mand', '_root_opt')
        bind_attrs(Obj, '_ext')


def build_classset_dict(Obj):
    key = None
    tr = get_typeref(Obj)
    while not tr._cont:
        tr = get_typeref(tr)
        if tr is None:
            break
    if tr._cont is None:
        # something is screwed somewhere
        return
    for Comp in tr._cont.values():
        if Comp._uniq:
            key = Comp._name
    if key is None:
        return
    # check the key (UNIQUE) component
    Obj._lut = {'__key__': key}
    __build_classset_dict(Obj, key, Obj._val.root)
    if Obj._val.ext:
        __build_classset_dict(Obj, key, Obj._val.ext)


def __build_classset_dict(Obj, key, valset):
    for val in valset:
        if key in val:
            keyval = val[key]
            # WARNING: keyval is not always a basic value (e.g. INTEGER),
            # but can be a constructed value, hence a dict or a list
            # We need to make it hashable for Python
            if isinstance(keyval, list):
                keyval = tuple(keyval)
            elif isinstance(keyval, dict):
                keyval = tuple(sorted(keyval.items()))
            #
            if keyval in Obj._lut:
                # this is not as UNIQUE as one can think...
                lutval = Obj._lut[keyval]
                if lutval[0] == CLASET_UNIQ:
                    # switching to MULT
                    Obj._lut[keyval] = (CLASET_MULT, [lutval[1], val])
                else:
                    # already defined as MULT
                    lutval[1].append(val)
            else:
                # this is the first (and hopefully UNIQUE) value
                Obj._lut[keyval] = (CLASET_UNIQ, val)

