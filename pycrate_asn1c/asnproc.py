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
# * File Name : pycrate_asn1c/asnproc.py
# * Created : 2016-03-02
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

import os
import re

from .specdir   import *
from .setobj    import *
from .asnobj    import *
from .asnobj    import _path_stack, _path_pop
from .extractor import get_objs
from .generator import PycrateGenerator, JSONDepGraphGenerator

#------------------------------------------------------------------------------#
# ASN.1 files handling
#------------------------------------------------------------------------------#

_ASN1DIR_PATH = 'pycrate_asn1dir/'


def compile_all(dic=ASN_SPECS, clearing=True, **kwargs):
    """
    compile all ASN.1 modules referenced by `dic'
    if `clearing' is set to True, clear the GLOBAL structure after each module
    """
    for item in dic.items():
        asnlog('[SPEC] {0}'.format(item[0]))
        if isinstance(item[1], tuple):
            kwargs['name'] = item[1][0]
            for flag in item[1][1:]:
                kwargs[flag] = True
        else:
            kwargs['name'] = item[1]
        compile_spec(**kwargs)
        if clearing:
            GLOBAL.clear()
        if isinstance(item[1], tuple):
            for flag in item[1][1:]:
                del kwargs[flag]


def compile_spec(name='LDAP-v3', shortname=None, **kwargs):
    if shortname in ASN_SPECS:
        name = ASN_SPECS[shortname]
        if isinstance(name, tuple):
            name, args = name[0], name[1:]
            for arg in args:
                kwargs[arg] = True
    elif shortname:
        asnlog('WNG: specification {0} not found'.format(shortname))
    spec_dir = get_spec_dir(name)
    spec_obj = get_spec_objects(spec_dir)
    spec_texts, spec_fn = get_spec_files(spec_dir)
    kwargs['filenames'] = spec_fn
    GLOBAL.clear_comp_ns()
    if spec_obj:
        GLOBAL.COMP['ORDER'] = spec_obj
    else:
        GLOBAL.COMP['ORDER'] = None
    #
    asnlog('[proc] starting with ASN.1 specification: {0}'.format(name))
    compile_text(spec_texts, **kwargs)


def get_spec_dir(spec_name):
    import pycrate_asn1c as _asn1c
    path = os.path.dirname(_asn1c.__file__) + os.path.sep + '..' + os.path.sep  + \
           _ASN1DIR_PATH + spec_name + os.path.sep
    return path


def get_spec_files(spec_dir):
    load = []
    try:
        fd = open('%sload_mod.txt' % spec_dir, 'r')
    except Exception as err:
        asnlog('[proc] unable to open load_mod.txt in {0}'.format(spec_dir))
    else:
        try:
            [load.append(fn.strip()) for fn in fd.readlines() if fn[:1] != '#']
        except Exception as err:
            fd.close()
            asnlog('[proc] unable to read load_mod.txt in {0}'.format(spec_dir))
        else:
            fd.close()
    if not load:
        try:
            load = [fn for fn in sorted(os.listdir(spec_dir)) if fn[-4:] == '.asn']
        except Exception as err:
            asnlog('[proc] unable to list {0}'.format(spec_dir))
    if not load:
        raise(ASN1Err('[proc] no ASN.1 spec found in {0}'.format(spec_dir)))
    #
    spec_texts, spec_fn = [], []
    for fn in load:
        try:
            fd = open('%s%s' % (spec_dir, fn), 'r')
        except Exception as err:
            raise(ASN1Err(
                  '[proc] unable to open spec file {0}, {1}'.format(fn, err)))
        try:
            if python_version < 3:
                spec_texts.append( fd.read().decode('utf-8') )
            else:
                spec_texts.append( fd.read() )
        except Exception as err:
            fd.close()
            raise(ASN1Err(
                  '[proc] unable to read spec file {0}, {1}'.format(fn, err)))
        else:
            fd.close()
            spec_fn.append(fn)
    return spec_texts, spec_fn


def get_spec_objects(spec_dir):
    try:
        fd = open('%sload_obj.txt' % spec_dir, 'r')
    except Exception as err:
        asnlog('[proc] unable to open load_obj.txt in {0}'.format(spec_dir))
        return None
    else:
        try:
            spec_obj = [names.strip().split('.') for names in fd.readlines() \
                        if names[:1] != '#']
        except Exception as err:
            asnlog('[proc] unable to read load_obj.txt in {0}'.format(spec_dir))
            fd.close()
            return None
        else:
            fd.close()
            return spec_obj


#------------------------------------------------------------------------------#
# ASN.1 modules processor
#------------------------------------------------------------------------------#
# 1) identify a DEFINITIONS indicating an ASN.1 module
# module-name DEFINITIONS [TAGS processing] ::=
# IMPORT ...
# EXPORT ...
# BEGIN
# [ASN.1 code]
# END
# -> module-name
# -> tags processing options
# -> imports
# -> export
#
# 2) identify all assignments within the ASN.1 BEGIN-END block
# -> 1-line all definitions, remove all blank spaces / CR / comments
# -> tokenize and parse all definitions into ASN1Obj objects

def compile_text(text=u'', **kwargs):
    """Scans a text (or list of texts) for ASN.1 modules definition
    
    Compile them and store all compiled modules within GLOBAL.MOD, indexed by
    module name.
    Each module has the following items:
        - _name_: str, module name
        - _oidstr_: str or None
        - _oid_: list of uint or None, OID of the module
        - _tag_: str (EXPLICIT, IMPLICIT, AUTOMATIC), tagging mode of the module
        - _ext_: str (IMPLIED) or None, extensibility mode of the module
        - _exp_: list of str or None, list of objects' name exported
        - _imp_: dict of imported objects' name (str) and corresponding module name (str)
        - _obj_: list of str, all objects' name defined in the module
        - _type_: list of str, all ASN.1 subtypes' name defined in the module
        - _val_: list of str, all ASN.1 values' name defined in the module
        - _set_: list of str, all ASN.1 values sets' name defined in the module
        - _class_: list of str, all ASN.1 classes' name defined in the module
        - _param_: list of str, all ASN.1 parameterized objects' name defined in the module
        - $object_name: Python instance of ASN1Obj
    
    kwargs:
        - filenames: list of filename in case `text' is also a list of texts
        - autotags: force the AUTOMATIC TAGS behavior
        - extimpl: force the EXTENSIBILITY IMPLIED behaviour
        - verifwarn: force warning instead of raising during the verification stage
    """
    if isinstance(text, (list, tuple)):
        if not all([isinstance(t, str_types) for t in text]):
            raise(ASN1Err('[proc] need only textual definition'))
    elif not isinstance(text, str_types):
        raise(ASN1Err('[proc] need some textual definition'))
    #
    # initialize the basic order in which objects will get compiled
    if GLOBAL.COMP['ORDER']:
        with_order = True
    else:
        GLOBAL.COMP['ORDER'] = []
        with_order = False
    mod_names = []
    #
    # disable the cache in ASN1Obj
    ASN1Obj._CACHE_ENABLED = False
    #
    # build the _IMPL_ module
    build_implicit_mod()
    #
    # 1) scan the text (or list of texts) and extract all ASN.1 modules defined
    if isinstance(text, (tuple, list)):
        for i, t in enumerate(text):
            if 'filenames' in kwargs:
                try:
                    kwargs['filename'] = kwargs['filenames'][i] 
                except:
                    kwargs['filename'] = None
            else:
                kwargs['filename'] = None
            mod_names.extend( _compile_text_pass(t, with_order, **kwargs) )
    else:
        if 'filenames' in kwargs:
            try:
                kwargs['filename'] = kwargs['filenames'][0]
            except:
                kwargs['filename'] = None
        else:
            kwargs['filename'] = None
        mod_names.extend( _compile_text_pass(text, with_order, **kwargs) )
    #
    # 2) All objects being initialized as ASN1Obj instances, we compile them
    # resolving their types and values
    #
    # build the list of objects' name to be resolved
    remain = GLOBAL.COMP['ORDER'][:]
    # process all objects until all are compiled
    while remain:
        asnlog('--- compilation cycle ---')
        remain_len = len(remain)
        compile_modules(remain)
        if remain_len == len(remain):
            # compilation is blocked
            raise(ASN1Err('[proc] unable to compile further, {0} objects remain:\n{1}'\
                  .format(remain_len,
                          '\n'.join(['%s.%s' % (i[0], i[1]) for i in remain]))))
    #
    # 3) build the specific lists of objects' name
    types, sets, values = 0, 0, 0
    for mod_name in mod_names:
        module = GLOBAL.MOD[mod_name]
        for obj_name in module:
            if obj_name[0] != '_':
                Obj = module[obj_name]
                if Obj._mode == MODE_TYPE:
                    module['_type_'].append(obj_name)
                    types += 1
                elif Obj._mode == MODE_SET:
                    module['_set_'].append(obj_name)
                    sets += 1
                elif Obj._mode == MODE_VALUE:
                    module['_val_'].append(obj_name)
                    values += 1
                if Obj._type == TYPE_CLASS:
                    module['_class_'].append(obj_name)
                if Obj._param is not None:
                    module['_param_'].append(obj_name)
    #
    # enable the cache in ASN1Obj
    ASN1Obj._CACHE_ENABLED = True
    #
    # 4) verify all objects compiled
    asnlog('--- verifications ---')
    verify_modules(**kwargs)
    #
    asnlog('[proc] ASN.1 modules processed: {0}'.format(mod_names))
    asnlog('[proc] ASN.1 objects compiled: {0} types, {1} sets, {2} values'\
           .format(types, sets, values))
    asnlog('[proc] done')


def _compile_text_pass(text, with_order, **kwargs):
    text = clean_text(text)
    mod_names = []
    #
    if 'filename' in kwargs and kwargs['filename']:
        fn = ' [%s]' % kwargs['filename']
    else:
        fn = ''
    #
    while True:
        # process the text until all ASN.1 modules have been extracted
        module = ASN1Dict()
        #
        # 1) scan text for module DEFINITION
        m = SYNT_RE_MODULEDEF.search(text)
        if not m:
            break
        
        #print(text[:m.start()])
        #print(text[m.start():m.start()+100])
        
        name, oidstr = module_get_name(text[:m.start()], fn)
        module['_name_'] = name
        if oidstr:
            # setting the complete oid string in module['oidstr'] 
            # and a proper list of uint in module['oid']
            module['_oidstr_'] = oidstr
            OidDummy = OID()
            _path_stack(['val'])
            try:
                rest = OidDummy.parse_value('{%s}' % oidstr)
            except Exception as err:
                _path_pop()
                asnlog('[proc]{0} module {1}: invalid OID value {2}, ignoring it'\
                       .format(fn, name, oidstr))
                module['_oid_'] = []
            else:
                _path_pop()
                module['_oid_'] = OidDummy._val
        else:
            module['_oidstr_'] = ''
            module['_oid_'] = []
        text = text[m.end():]
        #
        # 2) scan text for module option
        m = re.search('::=', text)
        if not m:
            raise(ASN1ProcTextErr('[proc]{0} module {1}: symbol ::= not found'\
                  .format(fn, name)))
        module['_tag_'], module['_ext_'] = module_get_option(text[:m.start()])
        if 'autotags' in kwargs and kwargs['autotags']:
            module['_tag_'] = TAG_AUTO
        if 'extimpl' in kwargs and kwargs['extimpl']:
            module['_ext_'] = 'EXTENSIBILITY IMPLIED'
        #asnlog('[proc] module {0} tagging mode: {1}'.format(name, module['_tag_']))
        #asnlog('[proc] module {0} extensibility: {1}'.format(name, module['_ext_']))
        text = text[m.end():]
        #
        # 3) scan text for BEGIN - END block
        # WNG: old school ASN.1 MACRO (with BEGIN - END block within ASN.1 module)
        # are not supported
        m = re.search('(^|\s)BEGIN(\s)((.|\n)*?)(\s)END($|\s)', text)
        if not m:
            raise(ASN1ProcTextErr('[proc]{0} module {1}: BEGIN - END scheme not found'\
                  .format(fn, name)))
        asnblock = m.group(3)
        text = text[m.end():]
        #
        # 4) scan the asn block for module exports
        module['_exp_'], cur = module_get_export(asnblock)
        if cur:
            asnblock = asnblock[cur:]
        #
        # 5) scan the asnblock for module imports
        imports, cur = module_get_import(asnblock)
        #if name == 'SUPL-REPORT':
        #    assert()
        module['_imp_'] = {}
        if cur:
            asnblock = asnblock[cur:]
            for imp in imports:
                for obj_name in imp['obj']:
                    module['_imp_'][obj_name] = imp['name']
        #
        # 6) init objects lists for the module
        module['_obj_']   = []
        module['_type_']  = []
        module['_set_']   = []
        module['_val_']   = []
        module['_class_'] = []
        module['_param_'] = []
        #
        # 7) scan the asnblock for assignments and initialize all ASN.1 objects
        lines = asnblock.split('\n')
        while len(lines) > 0:
            # module_extract_assign() consumes lines, line by line
            Obj = module_extract_assign(lines)
            Obj._mod = name
            if Obj._name in module:
                raise(ASN1ProcTextErr('[proc]{0} module {1}: duplicate object, {2}'\
                      .format(fn, name, Obj._name)))
            elif Obj._name in module['_imp_']:
                raise(ASN1ProcTextErr('[proc]{0} module {1}: duplicate object with import, {2}'\
                      .format(fn, name, Obj._name)))
            module[Obj._name] = Obj
            module['_obj_'].append(Obj._name)
        #
        asnlog('[proc]{0} module {1} (oid: {2}): {3} ASN.1 assignments found'\
               .format(fn, name, module['_oid_'], len(module)-12))
        # 
        # 8) initalize the module in GLOBAL.MOD
        if name in GLOBAL.MOD:
            # module already compiled and loaded
            if module['_oid_'] and module['_oid_'] == GLOBAL.MOD[name]['_oid_']:
                asnlog('[proc]{0} module {1}: already compiled'.format(fn, name))
            else:
                asnlog('[proc]{0} module {1}: already compiled but OID missing or mismatch'\
                       .format(fn, name))
            if with_order:
                # in case load_obj.txt is provided
                # remove objects of this module from the compilation ORDER list
                for mod_obj_names in GLOBAL.COMP['ORDER'][:]:
                    if mod_obj_names[0] == name:
                        GLOBAL.COMP['ORDER'].remove( mod_obj_names )
        else:
            GLOBAL.MOD[name] = module
            if not with_order:
                # in case load_obj.txt is not provided 
                GLOBAL.COMP['ORDER'].extend(
                    [[name, obj_name] for obj_name in module['_obj_']] )
        #
        # 9) keep track of the module name
        mod_names.append(name)
    #
    return mod_names


def build_implicit_mod():
    """
    Builds all predefined ASN.1 types in the _IMPL_ special module:
    REAL, EXTERNAL, EMBEDDED PDV, CHARACTER STRING, TYPE-IDENTIFIER, ABSTRACT-SYNTAX
    """
    GLOBAL.MOD['_IMPL_'].clear()
    module = GLOBAL.MOD['_IMPL_']
    module['_name_'] = '_IMPL_'
    module['_oid_']  = []
    module['_imp_']  = {}
    module['_obj_'] = [TYPE_REAL, TYPE_EXT, TYPE_EMB_PDV, TYPE_CHAR_STR, TYPE_TYPEIDENT, TYPE_ABSSYNT]
    GLOBAL.COMP['NS']['mod'] = '_IMPL_'
    #
    GLOBAL.COMP['NS']['name'] = 'REAL'
    _REAL = ASN1Obj(name='REAL', mode=MODE_TYPE, type=TYPE_SEQ)
    _path_stack([])
    _REAL._parse_cont_seq(clean_text("""
    {
      mantissa INTEGER,
      base INTEGER (2|10),
      exponent INTEGER
    }
    """.strip()))
    _path_pop()
    _REAL._text_def = ''
    _REAL._mod = '_IMPL_'
    _REAL = _REAL.resolve()
    #
    GLOBAL.COMP['NS']['name'] = 'EXTERNAL'
    _EXTERNAL = ASN1Obj(name='EXTERNAL', mode=MODE_TYPE, type=TYPE_SEQ)
    _path_stack([])
    _EXTERNAL._parse_cont_seq(clean_text("""
    {
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
    }
    """.strip()))
    _EXTERNAL._parse_const(clean_text("""
    (WITH COMPONENTS {
        ...,
        identification (WITH COMPONENTS {
            ...,
            syntaxes ABSENT,
            transfer-syntax ABSENT,
            fixed ABSENT })
    })
    """.strip()))
    _path_pop()
    _EXTERNAL._text_def = ''
    _EXTERNAL._mod = '_IMPL_'
    _EXTERNAL = _EXTERNAL.resolve()
    #
    GLOBAL.COMP['NS']['name'] = 'EMBEDDED PDV'
    _EMBEDDED_PDV = ASN1Obj(name='EMBEDDED PDV', mode=MODE_TYPE, type=TYPE_SEQ)
    _path_stack([])
    _EMBEDDED_PDV._parse_cont_seq(clean_text("""
    {
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
    }
    """.strip()))
    _EMBEDDED_PDV._parse_const(clean_text("""
    (WITH COMPONENTS {
        ...,
        data-value-descriptor ABSENT
    })
    """.strip()))
    _path_pop()
    _EMBEDDED_PDV._text_def = ''
    _EMBEDDED_PDV._mod = '_IMPL_'
    _EMBEDDED_PDV = _EMBEDDED_PDV.resolve()
    #
    GLOBAL.COMP['NS']['name'] = 'CHARACTER STRING'
    _CHARACTER_STRING = ASN1Obj(name='CHARACTER STRING', mode=MODE_TYPE, type=TYPE_SEQ)
    _path_stack([])
    _CHARACTER_STRING._parse_cont_seq(clean_text("""
    {
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
        string-value [1] OCTET STRING 
    }
    """.strip()))
    _path_pop()
    _CHARACTER_STRING._text_def = ''
    _CHARACTER_STRING._mod = '_IMPL_'
    _CHARACTER_STRING = _CHARACTER_STRING.resolve()
    #
    GLOBAL.COMP['NS']['name'] = 'TYPE-IDENTIFIER'
    _TYPE_IDENTIFIER = ASN1Obj(name='TYPE-IDENTIFIER', mode=MODE_TYPE, type=TYPE_CLASS)
    _path_stack([])
    _TYPE_IDENTIFIER._parse_cont_class(clean_text("""
    {
        &id OBJECT IDENTIFIER UNIQUE,
        &Type 
    }
    """.strip()))
    _TYPE_IDENTIFIER._parse_class_syntax(clean_text("""
    WITH SYNTAX {&Type IDENTIFIED BY &id}
    """.strip()))
    _path_pop()
    _TYPE_IDENTIFIER._text_def = ''
    _TYPE_IDENTIFIER._mod = '_IMPL_'
    _TYPE_IDENTIFIER = _TYPE_IDENTIFIER.resolve()
    #
    GLOBAL.COMP['NS']['name'] = 'ABSTRACT-SYNTAX'
    _ABSTRACT_SYNTAX = ASN1Obj(name='ABSTRACT-SYNTAX', mode=MODE_TYPE, type=TYPE_CLASS)
    _path_stack([])
    _ABSTRACT_SYNTAX._parse_cont_class(clean_text("""
    {
        &id OBJECT IDENTIFIER,
        &Type,
        &property BIT STRING {handles-invalid-encodings(0)} DEFAULT {}
    }
    """.strip()))
    _ABSTRACT_SYNTAX._parse_class_syntax(clean_text("""
    WITH SYNTAX { &Type IDENTIFIED BY &id [HAS PROPERTY &property] }
    """.strip()))
    _path_pop()
    _ABSTRACT_SYNTAX._text_def = ''
    _ABSTRACT_SYNTAX._mod = '_IMPL_'
    _ABSTRACT_SYNTAX = _ABSTRACT_SYNTAX.resolve()
    #
    GLOBAL.COMP['NS']['name'] = ''
    module[TYPE_REAL]      = _REAL
    module[TYPE_EXT]       = _EXTERNAL
    module[TYPE_EMB_PDV]   = _EMBEDDED_PDV
    module[TYPE_CHAR_STR]  = _CHARACTER_STRING
    module[TYPE_TYPEIDENT] = _TYPE_IDENTIFIER
    module[TYPE_ABSSYNT]   = _ABSTRACT_SYNTAX


def module_get_name(text, fn):
    # check for the module name
    name_all = SYNT_RE_MODULEREF.findall(text)
    if not name_all:
        raise(ASN1ProcTextErr('[proc]{0} no module name found'.format(fn)))
    name, oidstr = name_all[-1]
    # clean-up the oid
    if oidstr:
        oidstr = re.sub('\s{1,}', ' ', oidstr[1:-1]).strip()
    else:
        oidstr = None
    return name, oidstr


def module_get_option(text=''):
    text = ' %s' % text
    # check for tagging
    m = SYNT_RE_MODULEOPT.search(text)
    if m:
        tag = m.group(1).split()[0].strip()
    else:
        # default ASN.1 mode
        tag = TAG_EXPLICIT
    # check for extensibility
    m = SYNT_RE_MODULEEXT.search(text)
    if m:
        ext = m.group(1).split()[1].strip()
    else:
        ext = None
    return tag, ext


def module_get_export(text=''):
    # check for export clause
    m = SYNT_RE_MODULEEXP.search(text)
    if m:
        # remove CR
        exp = m.group(1).replace('\n', ',').strip()
        # remove duplicated spaces / comas
        exp = re.sub('[ ]{0,},{1,}[ ]{0,},{1,}[ ]{0,}', ', ', exp)
        # split, strip, and keep only strings
        exp = [s for s in map(strip, exp.split(',')) if s != '']
        return exp, m.end()
    else:
        return None, 0


def module_get_import(text=''):
    # check for import clauses (can be from multiple modules)
    m = SYNT_RE_MODULEIMP.search(text)
    if m:
        l = []
        imp = m.group(1).strip()
        if not re.match('\s{0,}', imp):
            # in case of "IMPORTS ;"
            return None, m.end()
        # take care of FROM directives, that can reference the complete module name
        fro = SYNT_RE_MODULEFROM.search(imp)
        while fro:
            # get module name / oid
            name, oidstr, oidref = fro.groups()
            # clean-up the oid
            if oidstr:
                oidstr = re.sub('\s{1,}', ' ', oidstr).strip()
                OidDummy = OID()
                _path_stack(['val'])
                try:
                    rest = OidDummy.parse_value(oidstr)
                except Exception as err:
                    asnlog('IMPORTS directive: invalid OID value, ignoring it')
                    oid = []
                else:
                    oid = OidDummy._val
                _path_pop()
                new_imp = imp[fro.end():].strip()
            elif oidref:
                oidstr = oidref
                # at this stage, nothing is compiled, so there is no way to
                # get the OID value referenced
                oid = []
                new_imp = imp[fro.regs[-1][1]:].strip()
            else:
                oidstr = ''
                oid = []
                new_imp = imp[fro.end():].strip()
            # get all ASN.1 objects reference before
            obj = imp[:fro.start()]
            # clean them up and split them to a list
            obj = map(strip, re.sub('\s{1,}', ' ', obj).split(','))
            # remove {} at the end of parameterized objects
            obj = [o[:-2].strip() if o[-2:] == '{}' else o for o in obj] 
            # fill-in the import list
            l.append({'name':name, 'oidstr':oidstr, 'oid':oid, 'obj':obj})
            # iterate
            imp = new_imp
            fro = SYNT_RE_MODULEFROM.search(imp)
        return l, m.end()
    else:
        return None, 0


def module_extract_assign(lines):
    """
    Consumes the lines to find a 1st assignment "::=".
    From here, scans the left-part of the assignment "::=" on the same line,
    and consumes the lines in order to get the complete definition text 
    of the declared object, right-part of "::=".
    
    It returns an initialized ASN1Obj object with additional attributes:
        - _name: str, first word left-part of the assignment
        - _type: str, TYPE_* only when a native ASN.1 type is used in _text_def
        - _text_decl: str, remaining left-part of the assignment
        - _text_def: str, right-part of the assignment
    """
    # TODO: the way assignments are extracted, scanning for ::=, is bad...
    # e.g. in case an "::=" character string is defined somewhere, 
    # it will break this processing
    #
    content, entered, Obj = [], False, None
    line_num = 0
    #
    for l in lines:
        if l.find('::=') >= 0:
            if not entered:
                # we found a 1st assignment, to parse
                entered = True
                declared, definition = map(strip, l.split('::='))
                if definition:
                    content.append(definition)
                # parse left part of the assignment
                Obj = ASN1Obj()
                Obj._text_decl = declared
            else:
                # we are on a 2nd new assignments, just returning the 1st object
                Obj._text_def = re.sub('\s{1,}', ' ', ' '.join(content).strip())
                del lines[:line_num]
                asnobj_getname(Obj)
                asnobj_getparnum(Obj)
                asnobj_gettype(Obj)
                return Obj
        #
        elif entered:
            content.append(l)
        line_num += 1
    #
    # end of lines
    if Obj is not None:
        Obj._text_def = re.sub('\s{1,}', ' ', ' '.join(content).strip())
    #
    del lines[:]
    asnobj_getname(Obj)
    asnobj_getparnum(Obj)
    asnobj_gettype(Obj)
    return Obj


def asnobj_getname(Obj):
    text = Obj._text_decl
    m0 = match_typeref(text)
    if not m0:
        # 1) check for value assignment
        m1 = SYNT_RE_IDENT.match(text)
        if not m1:
            raise(ASN1ProcTextErr('[proc] invalid syntax for an object name: {0}'\
                  .format(text)))
        # get lower-case 1st lexeme
        Obj._name = m1.group(1)
        Obj._mode = MODE_VALUE
        Obj._text_decl = text[len(Obj._name):].strip()
    else:
        # 2) check for type or set assignment
        # upper-case 1st lexeme
        Obj._name = m0.group(1)
        # object can be MODE_SET or MODE_TYPE
        Obj._text_decl = text[len(Obj._name):].strip()


def asnobj_getparnum(Obj):
    # early process formal parameter to determine the number of required
    # actual parameters
    # it enables to determine early the mode between MODE_TYPE and MODE_SET
    try:
        text, params = extract_multi(Obj._text_decl)
    except Exception as err:
        raise(ASN1ProcTextErr('{0}: {1}'.format(self.fullname(), err)))
    if params is None:
        Obj._parnum = 0
    else:
        Obj._parnum = len(params)
    if Obj._mode != MODE_VALUE:
        if text:
            Obj._mode = MODE_SET
        else:
            Obj._mode = MODE_TYPE


def asnobj_gettype(Obj):
    # early check for native ASN.1 type for MODE_TYPE objects
    # this allows circular referencing between e.g. SEQUENCE content
    text = Obj._text_def
    # 1) try to skip tag
    if text[0:1] == '[':
        text, tag = extract_brack(text)
        if not tag:
            raise(ASN1ProcTextErr('{0}: invalid tagging, {1}'\
                  .format(self._name, Obj._text_def)))
        m = re.match('(IMPLICIT|EXPLICIT)(?:\s)', text)
        if m:
            text = text[m.end():].strip()
    # 2) try to get native type
    try:
        text, const = Obj._parse_type_native(text)
    except:
        pass


def asnobj_compile(Obj):
    """
    Processes an ASN.1 object from its textual description:
    Obj._name Obj._text_decl ::= Obj._text_def
    
    Determines the mode:
        - MODE_TYPE, MODE_SET or MODE_VALUE
    Parses:
        - formal parameters
        - tag
        - type or typeref
        - native content or parameterized content
        - constraints
        - the value for MODE_VALUE objects
        - the set of values for MODE_SET objects
    Compiles the object: translate it into the Python definitive object 
        according to its type
    
    Finally ensures no more text stays unprocessed
    """
    # 0) init GLOBAL namespace for the object
    GLOBAL.COMP['NS']['name']    = Obj._name
    GLOBAL.COMP['NS']['path']    = []
    GLOBAL.COMP['NS']['par']     = None
    GLOBAL.COMP['NS']['setpar']  = []
    GLOBAL.COMP['NS']['setdisp'] = 0
    #
    # 1) parse formal parameters from the left-side of the assignment
    _path_stack(['param'])
    text = Obj.parse_param(Obj._text_decl)
    _path_pop()
    #
    if Obj._param:
        GLOBAL.COMP['NS']['par'] = Obj._param
        GLOBAL.COMP['NS']['setpar'] = []
    #
    # 2) parse the rest of the definition of the object
    _path_stack([])
    if Obj._name[0].islower():
        # MODE_VALUE object
        # parse tag, type, content, constraints, from the left-side of the assignment
        assert(Obj._mode == MODE_VALUE)
        text = Obj.parse_def(text)
    else:
        # MODE_SET or MODE_TYPE object
        # if text is remaining -> MODE_SET, parse tag, type, content, constraints, 
        # from the left-side of the assignment
        if text:
            assert(Obj._mode == MODE_SET)
            text = Obj.parse_def(text)
        else:
            assert(Obj._mode == MODE_TYPE)
            text = Obj.parse_def(Obj._text_def)
    _path_pop()
    #
    # 3) if definition text is remaining: error!
    if text:
        raise(ASN1ProcTextErr('{0}: remaining textual definition, {1}'\
              .format(Obj.fullname(), text)))
    #
    # 4) parse the value or set
    _path_stack(['val'])
    if Obj._mode == MODE_VALUE:
        rest = Obj.parse_value(Obj._text_def)
        assert( Obj._val is not None )
    elif Obj._mode == MODE_SET:
        # extract values from curlybrackets
        rest, text_set = extract_curlybrack(Obj._text_def)
        Obj.parse_set(text_set)
        assert( Obj._val is not None )
    else:
        rest = ''
    _path_pop()
    #
    # 5) if value text is remaining: error !
    if rest:
        raise(ASN1ProcTextErr('{0}: remaining textual value(s) definition, {1}'\
              .format(Obj.fullname(), rest)))
    #
    # 6) create a new object after resolving its type and return it
    if hasattr(Obj, '_new'):
        # case of handling root type parameterization
        # e.g. MyType {CustomType} ::= CustomType
        ObjNew = Obj._new
    else:
        ObjNew = Obj.resolve()
    ObjNew._mod = Obj._mod
    return ObjNew


def init_ns_mod(mod_name):
    GLOBAL.clear_comp_ns()
    GLOBAL.COMP['NS']['mod'] = mod_name
    Mod = GLOBAL.MOD[mod_name]
    # add module's local objects
    GLOBAL.COMP['NS']['obj'].update(
        dict((obj_name, mod_name) for obj_name in Mod if obj_name[0] != '_'))
    # add module's imported objects
    GLOBAL.COMP['NS']['obj'].update(GLOBAL.MOD[mod_name]['_imp_'])
    # tagging and extensibility mode for the module
    GLOBAL.COMP['NS']['tag'] = GLOBAL.MOD[mod_name]['_tag_']
    GLOBAL.COMP['NS']['ext'] = GLOBAL.MOD[mod_name]['_ext_']


def compile_modules(remain):
    GLOBAL.ERR.clear()
    mod_name_prev = ''
    for (mod_name, obj_name) in remain[:]:
        #
        Mod = GLOBAL.MOD[mod_name]
        Obj = Mod[obj_name]
        #
        # 1) build the namespace for the given object
        if mod_name != mod_name_prev:
            init_ns_mod(mod_name)
        #
        # 2) try to compile it
        try:
            ObjNew = asnobj_compile(Obj)
        except ASN1ProcLinkErr:
            parnum = Obj._parnum
            Obj.__init__(name=Obj._name, mode=Obj._mode, type=Obj._type)
            Obj._parnum = parnum
            GLOBAL.ERR[Obj._name] = Obj
            mod_name_prev = mod_name
        else:
            remain.remove([mod_name, obj_name])
            GLOBAL.MOD[mod_name][obj_name] = ObjNew
            GLOBAL.COMP['DONE'].append( [mod_name, obj_name] )
            mod_name_prev = mod_name


#------------------------------------------------------------------------------#
# ASN.1 modules verification
#------------------------------------------------------------------------------#

def warn(msg, raising=True):
    if raising:
        raise(ASN1ObjErr(msg))
    else:
        asnlog('WNG: %s' % msg)


def verify_modules(**kwargs):
    # 1) verify that parameters referrers are correctly implemented
    # 2) verify that constraints applied to a type are allowed for this type
    # 3) verify that multiple constraints of the same type have a non-empty intersection
    # 4) verify the respect of value / size contraints for MODE_VALUE and MODE_SET 
    # objects
    # MODE_VALUE and MODE_SET objects can be found:
    # - in the root of a module
    # - as a DEFAULT argument within a constructed or class type
    # - in the content of a class value or set
    #
    # list of unhandled constraint' types
    CONST_UNHANDLED = [CONST_COMP, CONST_ENCODE_BY, CONST_REGEXP,
                       CONST_CONSTRAIN_BY, CONST_PROPERTY]
    # list of types for which we verify that multiple value constraints are compatible
    TYPE_CONST_VERIF = ASN1Range._TYPE
    #
    #
    if 'verifwarn' in kwargs and kwargs['verifwarn']:
        raising = False
    else:
        raising = True
    #
    for mod, name in GLOBAL.COMP['ORDER']:
        Obj = GLOBAL.MOD[mod][name]
        #
        # for parameterized object, ensure all formal parameter referrers lead
        # to an actual ASN1RefParam instance
        if Obj._param is not None:
            for (param_name, param) in Obj._param.items():
                for path in param['ref']:
                    # this may break in case the referrer path was not handled correctly
                    dest = Obj.select(path)
                    if isinstance(dest, (ASN1RefType, ASN1RefClassField, ASN1RefClassValField,
                                         ASN1RefChoiceComp, ASN1RefSet, ASN1RefValue)):
                        if not isinstance(dest.called, ASN1RefParam):
                            raise(ASN1ObjErr('{0}.{1}: invalid parameter reference, {2}'\
                                              .format(mod, name, dest)))
                        if dest.called.name != param_name:
                            raise(ASN1ObjErr('{0}.{1}: invalid parameter reference name, {2}'\
                                              .format(mod, name, dest.called.name)))
                    else:
                        raise(ASN1ObjErr('{0}.{1}: invalid parameter reference path, {2}'\
                                          .format(mod, name, path)))
        #
        # for standard objects, ensure all ASN1Obj instances composing it are consistent
        else:
            Objs = [Obj]
            Objs.extend( get_objs(Obj) )
            for O in Objs:
                # 0) verify all objects attributes are accessible
                # caching also everything
                void = O.get_typeref()
                void = O.get_refchain()
                void = O.get_classref()
                void = O.fullname()
                try:
                    void = O.get_parent_root()
                    void = O.get_parent_path()
                except Exception as err:
                    warn('get_parent_X() error: %s' % err, raising)
                void = O.get_param()
                void = O.get_tag()
                void = O.get_tag_univ()
                void = O.get_cont()
                try:
                    void = O.get_cont_tags()
                except Exception as err:
                    warn('get_cont_tags() error: %s' % err, raising)
                void = O.get_root()
                void = O.get_root_mand()
                void = O.get_root_opt()
                void = O.get_ext()
                void = O.get_ext_ident()
                void = O.get_ext_group()
                void = O.get_const()
                void = O.get_syntax()
                void = O.get_val()
                #
                # 1) verify constraints' type against object's type
                for const in O._const:
                    if const['type'] == CONST_TABLE:
                        if not isinstance(O._typeref, ASN1RefClassField) and \
                        O.get_typeref().get_classref() is None:
                            # verify O is actually a ref to a Class field
                            raise(ASN1ObjErr('{0}.{1}: internal object {2}, '\
                                             'invalid type for table constraint'\
                                             .format(mod, name, Objs.index(O))))
                    elif const['type'] not in O.CONST + CONST_UNHANDLED:
                        # verify this type of constraint applies to the type of O
                        warn('{0}.{1}: internal object {2}, invalid constraint type'\
                             .format(mod, name, Objs.index(O)), raising)
                #
                # 2) in case a constraint is locally defined for the object,
                # check if multiple constraints of the same type applies to the object
                consts_glob = O.get_const()
                if O._const:
                    ctypes_loc  = [const['type'] for const in O._const]
                    ctypes_glob = [const['type'] for const in consts_glob]
                    for ct in ctypes_loc:
                        if ctypes_glob.count(ct) > 1:
                            # multiple constraints of the same type apply to the object
                            #asnlog('{0}.{1}, internal object {2}: multiple {3} constraints'\
                            #       .format(mod, name, Objs.index(O), ct))
                            if ct == CONST_SIZE:
                                # ensure that at least 1 value comply to all the constraints
                                consts = [const for const in consts_glob if const['type'] == CONST_SIZE]
                                S = reduce_setdicts(consts)
                                if S.is_empty() and not S.is_ext():
                                    # there is no size that can satisfy the list of constraints
                                    warn('{0}.{1}: internal object {2}, '\
                                         'no intersecting constraints of type SIZE'\
                                         .format(mod, name, Objs.index(O)), raising)
                            #elif ct == CONST_VAL and O._type in TYPE_CONST_VERIF:
                            elif ct == CONST_VAL:
                                # ensure that at least 1 value comply to all the constraints
                                consts = [const for const in consts_glob if const['type'] == CONST_VAL]
                                S = reduce_setdicts(consts)
                                if S.is_empty() and not S.is_ext():
                                    # there is no value that can satisfy the list of constraints
                                    warn('{0}.{1}: internal object {2}, '\
                                         'no intersecting constraints of type {3}'\
                                         .format(mod, name, Objs.index(O), ct), raising)
                            elif ct not in CONST_UNHANDLED:
                                asnlog('INF: {0}.{1}, internal object {2}, '\
                                       'multiple constraints of the same type, {3}'\
                                       .format(mod, name, Objs.index(O), ct))
                #
                # 3) for MODE_VALUE and MODE_SET objects, verifies that constraints are respected
                # this can happen within MODE_TYPE CLASS objects too
                if O._mode == MODE_VALUE and O._val is not None:
                    if O._type in TYPE_CONST_SIZE:
                        if not _verify_const_size(O._val, consts_glob):
                            warn('{0}.{1}: internal object {2}, value outside of the SIZE constraint'\
                                 .format(mod, name, Objs.index(O)), raising)
                    if not _verify_const_val(O._val, consts_glob, mod, name, Objs.index(O)):
                        warn('{0}.{1}: internal object {2}, value outside of the constraint'\
                             .format(mod, name, Objs.index(O)), raising)
                #
                elif O._mode == MODE_SET and O._val is not None:
                    if not isinstance(O._val, dict) or \
                    'root' not in O._val or 'ext' not in O._val or \
                    not isinstance(O._val['root'], list) or \
                    not isinstance(O._val['ext'], (NoneType, list)):
                        raise(ASN1ObjErr('{0}.{1}: internal object {2}, '\
                                         'invalid set value'\
                                         .format(mod, name, Objs.index(O))))
                    for val in O._val['root']:
                        if O._type in TYPE_CONST_SIZE:
                            if not _verify_const_size(val, consts_glob):
                                warn('{0}.{1}: internal object {2}, value outside '\
                                     'of the SIZE constraint'.format(mod, name, Objs.index(O)), raising)
                        if not _verify_const_val(val, consts_glob, mod, name, Objs.index(O)):
                            warn('{0}.{1}: internal object {2}, value outside '\
                                 'of the constraint'.format(mod, name, Objs.index(O)), raising)
                    if O._val['ext']:
                        for val in O._val['ext']:
                            if O._type in TYPE_CONST_SIZE:
                                if not _verify_const_size(val, consts_glob):
                                    warn('{0}.{1}: internal object {2}, value outside '\
                                         'of the SIZE constraint'\
                                         .format(mod, name, Objs.index(O)), raising)
                            if not _verify_const_val(val, consts_glob, mod, name, Objs.index(O)):
                                warn('{0}.{1}: internal object {2}, value outside of the constraint'\
                                .format(mod, name, Objs.index(O)), raising)
                #
                # 4) for SEQ / SET, in case it contains an OPEN object with a table constraint
                # check the unicity of values associated to the key to the table
                elif O._mode == MODE_TYPE and O.TYPE in (TYPE_SET, TYPE_SEQ) and O._cont:
                    for comp in O._cont.values():
                        if comp.TYPE in (TYPE_OPEN, TYPE_ANY) and comp._const:
                            for const in comp._const:
                                if const['type'] == CONST_TABLE:
                                    ret = _verify_seq_const_tab(O, comp._name, const, mod, name, Objs.index(O))


def _verify_const_size(val, consts):
    # check if some SIZE constraints are defined
    consts_size = [c for c in consts if c['type'] == CONST_SIZE]
    if len(consts_size) == 0:
        return True
    elif len(consts_size) == 1:
        S = ASN1Set(consts_size[0])
    else:
        S = reduce_setdicts(consts_size)
    #
    if S.is_ext():
        # constraint is extensible, any val size is accepted
        return True
    elif S.in_root(len(val)):
        # size is in the root part of the constraint
        return True
    else:
        return False


def _verify_const_val(val, consts, mod, name, ind):
    # check if some value constraints are defined
    consts_val = [c for c in consts if c['type'] == CONST_VAL]
    if len(consts_val) == 0:
        return True
    elif len(consts_val) == 1:
        S = ASN1Set(consts_val[0])
    else:
        S = reduce_setdicts(consts_val)
    #
    if S.is_ext():
        # constraint is extensible, any val is accepted
        return True
    elif S.in_root(val):
        # value is in the root part of the constraint
        return True
    else:
        return False


def _verify_seq_const_tab(Obj, open_name, const_tab, modname, objname, obj_index):
    # check within a sequence with one of its component being an OPEN type
    # that the key to the table constraint has unique values
    comp_open = Obj._cont[open_name]
    tab_key   = const_tab['at']
    if not tab_key or len(tab_key) != 2 or tab_key[0] != '..' or tab_key[1] not in Obj._cont:
        # no key component defined or
        # complex path to key component, unable to make the verification
        return True
    # get the full tab put into a single list of values
    tab = const_tab['tab']._val['root']
    if const_tab['tab']._val['ext']:
        # create a new list concatenating the root and ext part
        tab = tab + const_tab['tab']._val['ext']
    # for all values, check the one associated to the key component
    comp_key = Obj._cont[tab_key[1]]
    id_key = comp_key.get_typeref()._name
    val_key, val_all, ret = [], [], []
    for val in tab:
        if id_key not in val:
            #asnlog('[WNG] constraint table value without key subvalue %s: %r' % (id_key, val))
            pass
        else:
            if val[id_key] in val_key:
                # duplicated key subvalue, get the corresponding complete value
                if val != val_all[ val_key.index(val[id_key]) ]:
                    # Houston, we got a problem !
                    #asnlog('[WNG] constraint table with duplicated key subvalue %s: %r, '\
                    #       'and different associated value' % (id_key, val[id_key]))
                    if id_key not in ret:
                        ret.append(id_key)
                    #assert()
                else:
                    # duplicated key subvalue, with hopefully same value
                    # nothing to do here
                    pass
            else:
                val_key.append( val[id_key] )
                val_all.append( val )
    if ret:
        asnlog('WNG: {0}.{1}: internal object {2}, non-unique key subvalue {3!r} '\
               'within a table constraint'.format(modname, objname, obj_index, ret))
    return True if ret else False


#------------------------------------------------------------------------------#
# ASN.1 modules generation
#------------------------------------------------------------------------------#

def generate_modules(generator, destfile='/tmp/gen.py'):
    generator(destfile)


def generate_all(dic=ASN_SPECS, destpath=None):
    """
    generate all ASN.1 modules referenced by `dic' into the ../pycrate_asn1dir/
    directory
    """
    if destpath is None:
        import pycrate_asn1c as _asn1c
        destpath = os.path.dirname(_asn1c.__file__) + os.path.sep + '..' + \
                   os.path.sep + _ASN1DIR_PATH
    #
    for item in sorted(dic.items()):
        asnlog('[GEN] {0}'.format(item[0]))
        kwargs = {}
        if isinstance(item[1], tuple):
            kwargs['name'] = item[1][0]
            for flag in item[1][1:]:
                kwargs[flag] = True
        else:
            kwargs['name'] = item[1]
        GLOBAL.clear()
        compile_spec(**kwargs)
        dest = destpath + item[0]
        generate_modules(PycrateGenerator, dest + '.py')
        generate_modules(JSONDepGraphGenerator, dest + '.json')
    #
    GLOBAL.clear()
    #
    # create an __init__.py file for python2
    dest = destpath + '__init__.py'
    fd = open(dest, 'w')
    fd.write('__all__ = [')
    for name in sorted(dic):
        fd.write('\'%s\', ' % name)
    fd.write(']\n')
    fd.close()


if __name__ == '__main__':
    generate_all()
