# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2018. Benoit Michau. ANSSI.
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
# * File Name : pycrate_asn1c/tokenizer.py
# * Created : 2018-03-13
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

import re
from pycrate_asn1c.err     import *
from pycrate_asn1c.utils   import *
from pycrate_asn1c.dictobj import *


# white space and new line
_NL  = '\x0a\x0b\x0c\x0d'
_SNL = '\x09\x0a\x0b\x0c\x0d\x20' + '\xa0' # a0 is not a valid UTF-8 char
REScannerSNL = '[%s]{1,}' % _SNL

# exclude more characters
_EXC = '(?![a-zA-Z0-9\-]{1,})'

# native types
REScannerNTypes = '|'.join((
    'NULL',
    'BOOLEAN',
    'INTEGER',
    'REAL',
    'ENUMERATED',
    'OBJECT IDENTIFIER',
    'RELATIVE-OID',
    'OID-IRI',
    'RELATIVE-OID-IRI',
    'BIT STRING',
    'OCTET STRING',
    'NumericString',
    'PrintableString',
    'VisibleString',
    'ISO646String',
    'IA5String',
    'TeletexString',
    'T61String',
    'VideotexString',
    'GraphicString',
    'GeneralString',
    'UniversalString',
    'BMPString',
    'UTF8String',
    'ObjectDescriptor',
    'GeneralizedTime',
    'UTCTime',
    'TIME',
    'SEQUENCE',
    'SET',
    'CHOICE',
    'EXTERNAL',
    'EMBEDDED PDV',
    'CHARACTER STRING',
    'ANY',
    'CLASS',
    'TYPE-IDENTIFIER',
    'ABSTRACT-SYNTAX',
    'INSTANCE OF',
    'MACRO'
    ))

# integer
REScannerInt = '([+\-](?:[%s]{0,})){0,1}[0-9]{1,}' % _SNL

# real           int     dec                   exp
REScannerReal = '(%s){1}(?:\.([0-9]{1,})){0,1}(?:[eE](%s)){0,1}'\
                % (REScannerInt, REScannerInt)

# bstring
REScannerBStr = '\'[%s01]{0,}\'B' % _SNL

# hstring
REScannerHStr = '\'[%s0-9A-F]{0,}\'H' % _SNL


# tokens' identifiers

# comments and character string
TOK_CMT     = 'CMT'   # comment
TOK_CSTR    = 'CSTR'  # chars string

# definition and tag related
TOK_DEFI    = 'DEFI'  # DEFINITIONS
TOK_EXTI    = 'EXTI'  # EXTENSIBILITY IMPLIED
TOK_BEG     = 'BEG'   # BEGIN
TOK_END     = 'END'   # END
TOK_TAGS    = 'TAGS'  # TAGS
TOK_TUNI    = 'TUNI'  # UNIVERSAL
TOK_TAPP    = 'TAPP'  # APPLICATION
TOK_TPRI    = 'TPRI'  # PRIVATE
TOK_TEXP    = 'TEXP'  # EXPLICIT
TOK_TIMP    = 'TIMP'  # IMPLICIT

# set and value related
TOK_MINF    = 'MINF'  # MINUS-INFINITY
TOK_PINF    = 'PINF'  # PLUS-INFINITY
TOK_NAN     = 'NAN'   # NOT-A-NUMBER
TOK_ALL     = 'ALL'   # ALL
TOK_MIN     = 'MIN'   # MIN
TOK_MAX     = 'MAX'   # MAX
TOK_EXCE    = 'EXCE'  # EXCEPT
TOK_NULL    = 'NULL'  # NULL
TOK_TRUE    = 'TRUE'  # TRUE
TOK_FALS    = 'FALS'  # FALSE
TOK_REAL    = 'REAL'  # real number
TOK_INT     = 'INT'   # integer
TOK_BSTR    = 'BSTR'  # binary string
TOK_HSTR    = 'HSTR'  # hexa string

# other various keywords
TOK_ABS     = 'ABS'   # ABSENT
TOK_AUTO    = 'AUTO'  # AUTOMATIC
TOK_BY      = 'BY'    # BY
TOK_COMP    = 'COMP'  # COMPONENT
TOK_COMPS   = 'COMPS' # COMPONENTS
TOK_CONST   = 'CONST' # CONSTRAINED
TOK_CONT    = 'CONT'  # CONTAINING
TOK_DEF     = 'DEF'   # DEFAULT
TOK_ENC     = 'ENC'   # ENCODED
TOK_EXP     = 'EXP'   # EXPORTS
TOK_FROM    = 'FROM'  # FROM
TOK_IMP     = 'IMP'   # IMPORTS
TOK_INCL    = 'INCL'  # INCLUDES
TOK_OF      = 'OF'    # OF
TOK_OPT     = 'OPT'   # OPTIONAL
TOK_PAT     = 'PAT'   # PATTERN
TOK_PRES    = 'PRES'  # PRESENT
TOK_SIZE    = 'SIZE'  # SIZE
TOK_WSYN    = 'WSYN'  # WITH SYNTAX
TOK_UNIQ    = 'UNIQ'  # UNIQUE

# identifier related
TOK_NTYPE   = 'NTYPE' # native type
TOK_CLAID   = 'CLAID' # &[iI]dentifier
TOK_HID     = 'HID'   # IDENTIFIER
TOK_ID      = 'ID'    # Identifier
TOK_LID     = 'LID'   # identifier

# special (series of) characters
TOK_ASSI    = 'ASSI'  # ::=
TOK_COL     = 'COL'   # :
TOK_SCOL    = 'SCOL'  # ;
TOK_EQU     = 'EQU'   # =
TOK_COM     = 'COM'   # ,
TOK_PARO    = 'PARO'  # (
TOK_PARC    = 'PARC'  # )
TOK_DBRAO   = 'DBRAO' # [[
TOK_DBRAC   = 'DBRAC' # ]]
TOK_BRAO    = 'BRAO'  # [
TOK_BRAC    = 'BRAC'  # ]
TOK_CBRAO   = 'CBRAO' # {
TOK_CBRAC   = 'CBRAC' # }
TOK_TDOT    = 'TDOT'  # ...
TOK_DDOT    = 'DDOT'  # ..
TOK_DOT     = 'DOT'   # .
TOK_DOTA    = 'DOTA'  # .&
TOK_UNIO    = 'UNIO'  # |
TOK_INTER   = 'INTER' # ^
TOK_LTHAN   = 'LTHAN' # <
TOK_GTHAN   = 'GTHAN' # >
TOK_ARRO    = 'ARRO'  # @
TOK_EXCL    = 'EXCL'  # !


TOKS_OBJS   = {TOK_NULL, TOK_NTYPE, TOK_HID, TOK_ID, TOK_LID}
TOKS_TYPES  = {TOK_NULL, TOK_NTYPE, TOK_HID, TOK_ID}
TOKS_OBJS_EXT  = {TOK_NULL, TOK_NTYPE, TOK_HID, TOK_ID, TOK_LID, TOK_CLAID}
TOKS_TYPES_EXT = {TOK_HID, TOK_ID, TOK_CLAID}


REScannerASN1 = re.Scanner([
    #
    (r'(--).*?([%s]|(--)|$)' % _NL,     lambda s, t: (TOK_CMT,   t)),
    (r'(/\*).*?(\*/)',                  lambda s, t: (TOK_CMT,   t)),
    (r'".*?(?<!")"(?!")',               lambda s, t: (TOK_CSTR,  t)),
    #
    (r'::=',                            lambda s, t: TOK_ASSI),
    (r':',                              lambda s, t: TOK_COL),
    (r';',                              lambda s, t: TOK_SCOL),
    (r'=',                              lambda s, t: TOK_EQU),
    (r',',                              lambda s, t: TOK_COM),
    (r'\(',                             lambda s, t: TOK_PARO),
    (r'\)',                             lambda s, t: TOK_PARC),
    (r'\[{2}',                          lambda s, t: TOK_DBRAO),
    (r'\]{2}',                          lambda s, t: TOK_DBRAC),
    (r'\[',                             lambda s, t: TOK_BRAO),
    (r'\]',                             lambda s, t: TOK_BRAC),
    (r'\{',                             lambda s, t: TOK_CBRAO),
    (r'\}',                             lambda s, t: TOK_CBRAC),
    (r'\.\.\.',                         lambda s, t: TOK_TDOT),
    (r'\.\.',                           lambda s, t: TOK_DDOT),
    (r'\.',                             lambda s, t: TOK_DOT),
    (r'\||(?:UNION%s)' % _EXC,          lambda s, t: TOK_UNIO),
    (r'\^|(?:INTERSECTION%s)' % _EXC,   lambda s, t: TOK_INTER),
    (r'<',                              lambda s, t: TOK_LTHAN),
    (r'>',                              lambda s, t: TOK_GTHAN),
    (r'@',                              lambda s, t: TOK_ARRO),
    (r'\!',                             lambda s, t: TOK_EXCL),
    #
    (r'ABSENT%s' % _EXC,                lambda s, t: TOK_ABS),
    (r'ALL%s' % _EXC,                   lambda s, t: TOK_ALL),
    (r'APPLICATION%s' % _EXC,           lambda s, t: TOK_TAPP),
    (r'AUTOMATIC%s' % _EXC,             lambda s, t: TOK_AUTO),
    (r'BEGIN%s' % _EXC,                 lambda s, t: TOK_BEG),
    (r'BY%s' % _EXC,                    lambda s, t: TOK_BY),
    (r'COMPONENT%s' % _EXC,             lambda s, t: TOK_COMP),
    (r'COMPONENTS%s' % _EXC,            lambda s, t: TOK_COMPS),
    (r'CONSTRAINED%s' % _EXC,           lambda s, t: TOK_CONST),
    (r'CONTAINING%s' % _EXC,            lambda s, t: TOK_CONT),
    (r'DEFAULT%s' % _EXC,               lambda s, t: TOK_DEF),
    (r'DEFINITIONS%s' % _EXC,           lambda s, t: TOK_DEFI),
    (r'ENCODED%s' % _EXC,               lambda s, t: TOK_ENC),
    (r'END%s' % _EXC,                   lambda s, t: TOK_END),
    (r'EXCEPT%s' % _EXC,                lambda s, t: TOK_EXCE),
    (r'EXPLICIT%s' % _EXC,              lambda s, t: TOK_TEXP),
    (r'EXPORTS%s' % _EXC,               lambda s, t: TOK_EXP),
    (r'EXTENSIBILITY%sIMPLIED%s' % (REScannerSNL, _EXC),    lambda s, t: TOK_EXTI),
    (r'FALSE%s' % _EXC,                 lambda s, t: TOK_FALS),
    (r'FROM%s' % _EXC,                  lambda s, t: TOK_FROM),
    (r'IMPLICIT%s' % _EXC,              lambda s, t: TOK_TIMP),
    (r'IMPORTS%s' % _EXC,               lambda s, t: TOK_IMP),
    (r'INCLUDES%s' % _EXC,              lambda s, t: TOK_INCL),
    (r'MAX%s' % _EXC,                   lambda s, t: TOK_MAX),
    (r'MIN%s' % _EXC,                   lambda s, t: TOK_MIN),
    (r'MINUS-INFINITY%s' % _EXC,        lambda s, t: TOK_MINF),
    (r'NOT-A-NUMBER%s' % _EXC,          lambda s, t: TOK_NAN),
    (r'NULL%s' % _EXC,                  lambda s, t: (TOK_NULL, t)),
    (r'OF%s' % _EXC,                    lambda s, t: TOK_OF),
    (r'OPTIONAL%s' % _EXC,              lambda s, t: TOK_OPT),
    (r'PATTERN%s' % _EXC,               lambda s, t: TOK_PAT),
    (r'PLUS-INFINITY%s' % _EXC,         lambda s, t: TOK_PINF),
    (r'PRESENT%s' % _EXC,               lambda s, t: TOK_PRES),
    (r'PRIVATE%s' % _EXC,               lambda s, t: TOK_TPRI),
    (r'SIZE%s' % _EXC,                  lambda s, t: TOK_SIZE),
    (r'TAGS%s' % _EXC,                  lambda s, t: TOK_TAGS),
    (r'TRUE%s' % _EXC,                  lambda s, t: TOK_TRUE),
    (r'UNIQUE%s' % _EXC,                lambda s, t: TOK_UNIQ),
    (r'UNIVERSAL%s' % _EXC,             lambda s, t: TOK_TUNI),
    (r'WITH%sSYNTAX%s' % (REScannerSNL, _EXC),              lambda s, t: TOK_WSYN),
    #
    (r'%s' % REScannerReal,             lambda s, t: (TOK_INT,   t)),
    (r'%s' % REScannerInt,              lambda s, t: (TOK_REAL,  t)),
    (r'%s' % REScannerBStr,             lambda s, t: (TOK_BSTR,  t)),
    (r'%s' % REScannerHStr,             lambda s, t: (TOK_HSTR,  t)),
    #
    (r'(%s)%s' % (REScannerNTypes, _EXC),                   lambda s, t: (TOK_NTYPE, t)),
    (r'&[a-zA-Z](?:\-{0,1}[a-zA-Z0-9]{1,}){0,}%s' % _EXC,   lambda s, t: (TOK_CLAID, t)),
    (r'[A-Z](?:\-{0,1}[A-Z0-9]{1,}){0,}%s' % _EXC,          lambda s, t: (TOK_HID,   t)),
    (r'[A-Z](?:\-{0,1}[a-zA-Z0-9]{1,}){0,}%s' % _EXC,       lambda s, t: (TOK_ID,    t)),
    (r'[a-z](?:\-{0,1}[a-zA-Z0-9]{1,}){0,}%s' % _EXC,       lambda s, t: (TOK_LID,   t)),
    #
    (r'%s' % REScannerSNL,              None)
    ],
    flags=re.DOTALL
    )


class Tokenizer(object):
    """handles consciously ASN.1 tokens, forward and backward, while ignoring
    ASN.1 comments
    """
    
    REPR_OFF = 10
    
    GROUP = {
        TOK_PARO  : TOK_PARC,  # ( )
        TOK_DBRAO : TOK_DBRAC, # [[ ]]
        TOK_BRAO  : TOK_BRAC,  # [ ]
        TOK_CBRAO : TOK_CBRAC, # { }
        TOK_BEG   : TOK_END    # BEGIN END
        }
    
    def __init__(self, tokens=[]):
        self.toks = tokens
        # cursor
        self.cur = -1
        # stack of previous cursor value
        self.curp = []
    
    def __repr__(self):
        cur = self.get_cur()
        return repr(self.toks[cur-self.REPR_OFF:cur+self.REPR_OFF])
    
    def get_cur(self):
        return self.cur
    
    def set_cur(self, cur):
        if not -1 <= cur < len(self.toks):
            raise(ASN1TokenizerErr('invalid cursor'))
        else:
            self.cur = cur
    
    def count(self):
        return len(self.toks) - self.cur
    
    def get_tok(self):
        try:
            return self.toks[self.cur]
        except:
            raise(ASN1TokenizerErr('invalid cursor'))
    
    def get_next(self, off=1):
        ind, cnt, curp = 0, 0, self.cur
        for tok in self.toks[1+self.cur:]:
            if tok[0] == TOK_CMT:
                pass
            else:
                ind += 1
            cnt += 1
            if ind == off:
                break
        if ind < off:
            raise(ASN1TokenizerErr('not enough tokens'))
        self.cur += cnt
        self.curp.append(curp)
        return tok
    
    def has_next(self):
        for tok in self.toks[1+self.cur:]:
            if tok[0] == TOK_CMT:
                pass
            else:
                return True
        return False
    
    def get_prev(self, off=1):
        ind, cnt, curp = 0, 0, self.cur
        for tok in self.toks[:self.cur][::-1]:
            if tok[0] == TOK_CMT:
                pass
            else:
                ind += 1
            cnt += 1
            if ind == off:
                break
        if ind < off:
            raise(ASN1TokenizerErr('not enough tokens'))
        self.cur -= cnt
        self.curp.append(curp)
        return tok
    
    def get_upto(self, target):
        curp = self.cur
        while self.get_next() != target:
            # do not extend the stack with previous cursor value
            del self.curp[-1]
        self.curp.append(curp)
        self.cur += 1
        return self.__class__(self.toks[max(0, curp):self.cur-1])
    
    def get_group(self, wbnd=True):
        tok, curp = self.toks[self.cur], self.cur
        if tok in self.GROUP:
            op, clo = tok, self.GROUP[tok]
        else:
            raise(ASN1TokenizerErr('invalid group opening token, %s' % tok))
        depth = 1
        while depth > 0:
            tok = self.get_next()
            # do not extend the stack with previous cursor value
            del self.curp[-1]
            if tok == op:
                depth += 1
            elif tok == clo:
                depth -= 1
            if depth == 0:
                break
        self.curp.append(curp)
        if wbnd:
            return self.__class__(self.toks[curp:1+self.cur])
        else:
            return self.__class__(self.toks[1+curp:self.cur])
    
    def get_comps(self, sep=TOK_COM):
        comps, curp, curlast = [], self.cur, self.cur
        while True:
            try:
                tok = self.get_next()
            except:
                break
            if tok in self.GROUP:
                # jump over the group
                grp = self.get_group()
                # do not extend the stack with previous cursor value
                del self.curp[-1]
            elif tok == sep:
                comps.append(self.__class__(self.toks[curlast:self.cur-1]))
                curlast = self.cur
            else:
                pass
        self.curp.append(curp)
        return comps
    
    def undo(self):
        if not self.curp:
            raise() 
        self.cur = self.curp[-1]
        del self.curp[-1]


# ASN.1 module global structure:
# ModName ModOID DEFINITIONS ModOpts ::= BEGIN ModExports ModImports ModObjects END
#
# ASN.1 object structure:
# ObjName ObjParam ObjType ::= ObjVal
# ObjName ObjParam ObjType ::= ObjSet
# ObjName ObjParam ::= ObjType
# ObjName MACRO ::= BEGIN ... END
#
# ASN.1 object type structure:
# ObjTags ObjType ObjParamAct ObjConsts ObjCont
# CLASS ObjParamAct ObjCont WITH SYNTAX ObjSynt

def tokenize_text(text=u'', **kwargs):
    """tokenize the provided textual ASN.1 specification
    """
    #
    if isinstance(text, (list, tuple)):
        text = u'\n\n'.join(text)
    elif not isinstance(text, str_types):
        raise(ASN1Err('need some textual definition'))
    #
    toks, rest = REScannerASN1.scan(text)
    if rest:
        asnlog('%i remaining chars at the end of spec' % len(rest))
    # build the handler for the tokens
    Tok = Tokenizer(toks)
    modules = ASN1Dict()
    #
    # scan the tokens for all ASN.1 modules defined
    while True:
        module = ASN1Dict()
        #
        # 1) scan tokens for module declaration with DEFINITIONS
        try:
            TokDecl = Tok.get_upto(TOK_DEFI)
        except:
            # no more DEFINITIONS
            break
        #
        name, oid = scan_module_decl(TokDecl)
        module['_name_'] = name
        if oid:
            module['_oidtok_'] = oid
            # TODO: parse the OID value
            
            module['_oid_'] = []
        else:
            module['_oidtok_'] = []
            module['_oid_']    = []
        #
        # 2) scan tokens for module options before assignment ::=
        if Tok.get_tok() != TOK_ASSI:
            try:
                TokOpt = Tok.get_upto(TOK_ASSI)
            except:
                raise(ASN1ProcTextErr('module assignment not found'))
            #
            module['_tag_'], module['_ext_'] = scan_module_opt(TokOpt)
        else:
            module['_tag_'], module['_ext_'] = None, False
            Tok.get_next()
        if 'autotags' in kwargs and kwargs['autotags']:
            module['_tag_'] = TOK_AUTO
        if 'extimpl' in kwargs and kwargs['extimpl']:
            module['_ext_'] = True
        #asnlog('[proc] module %s, tags: %r' % (name, module['_tag_']))
        #asnlog('[proc] module %s, extensibility implied: %r' % (name, module['_ext_']))
        #
        # 3) scan tokens for BEGIN - END block
        if Tok.get_tok() != TOK_BEG:
            raise(ASN1ProcTextErr('missing BEGIN statement'))
        TokDef = Tok.get_group(wbnd=False)
        module['_tok_'] = TokDef
        #asnlog('[proc] module %s: %i tokens' % (name, TokDef.count()))
        if Tok.has_next():
            Tok.get_next()
        #
        # 4) scan the module definition block for exports
        tok = TokDef.get_next()
        if tok == TOK_EXP:
            module['_exp_'] = scan_module_exp(TokDef)
            #asnlog('[proc] module %s: %i tokens' % (name, TokDef.count()))
        else:
            TokDef.undo()
        #
        # 5) scan the module definition block for imports
        tok = TokDef.get_next()
        if tok == TOK_IMP:
            module['_imp_'] = scan_module_imp(TokDef)
            module['_resolv_'] = {}
            for d in module['_imp_']:
                for sym in d['sym']:
                    module['_resolv_'][sym] = d['name']
            #asnlog('[proc] module %s: %i tokens' % (name, TokDef.count()))
            #if module['_imp_']:
            #    asnlog('[proc] module %s: imports parsed' % name)
        else:
            TokDef.undo()
        #
        # 6) scan the module definition block for objects
        objs = scan_objs(TokDef)
        #
        # 7) init objects types for the module
        module['_obj_']   = objs
        module['_type_']  = []
        module['_set_']   = []
        module['_val_']   = []
        module['_class_'] = []
        module['_param_'] = []
        #
        for obj in objs.values():
            if obj['mode'] == MODE_TYPE:
                module['_type_'] = obj['name']
            elif obj['mode'] == MODE_SET:
                module['_set_'] = obj['name']
            elif obj['mode'] == MODE_VALUE:
                module['_val_'] = obj['name']
            else:
                assert()
            if obj['typedef']['type'] == 'CLASS':
                module['_class_'] = obj['name']
            if obj['param']:
                module['_param_'] = obj['name']
        #
        modules[name] = module
    #
    return modules


def scan_module_decl(Tok):
    """extract module name and OID from given tokens
    """
    # scan ModuleIdentifier
    tok = Tok.get_next()
    if tok[0] not in (TOK_HID, TOK_ID):
        raise(ASN1ProcTextErr('invalid module declaration, invalid name %r' % tok))
    name = tok[1]
    if Tok.has_next():
        if Tok.get_next() == TOK_CBRAO:
            oid = Tok.get_group()
        else:
            raise(ASN1ProcTextErr('invalid module declaration'))
    else:
        oid = None
    return name, oid


def scan_module_opt(Tok):
    """extract module options from given tokens
    """
    # scan TagDefault and ExtensionDefault
    # TODO: scan EncodingReferenceDefault first
    tag, ext = None, False
    if not Tok.has_next():
        return tag, next
    tok = Tok.get_next()
    if tok in (TOK_AUTO, TOK_TEXP, TOK_TIMP):
        tag = Tok.get_tok()
        if Tok.get_next() != TOK_TAGS:
            raise(ASN1ProcTextErr('invalid module options, missing TAGS keyword'))
        if not Tok.has_next():
            return tag, ext
        tok = Tok.get_next()
    if tok == TOK_EXTI:
        ext = True
    else:
        raise(ASN1ProcTextErr('invalid module options'))
    if Tok.has_next():
        raise(ASN1ProcTextErr('invalid module options'))
    return tag, ext


def scan_module_exp(Tok):
    """consume the tokens searching for module exports declaration
    """
    tok = Tok.get_next()
    if tok == TOK_ALL:
        if Tok.get_next() != TOK_SCOL:
            raise(ASN1ProcTextErr('invalid module export'))
        else:
            return None
    elif tok[0] in TOKS_OBJS:
        exp = []
        while tok != TOK_SCOL:
            if tok[0] in TOKS_OBJS:
                exp.append(tok[1])
            elif tok == TOK_CBRAO:
                tok = Tok.get_next()
                if tok != TOK_CBRAC:
                    raise(ASN1ProcTextErr('invalid module export, parameterized reference'))
            elif tok != TOK_COM:
                raise(ASN1ProcTextErr('invalid module export'))
            tok = Tok.get_next()
        return exp
    else:
        raise(ASN1ProcTextErr('invalid module export'))


def scan_module_imp(Tok):
    """consume the tokens searching for module imports declaration
    """
    sym, imp = [], []
    tok = Tok.get_next()
    while tok != TOK_SCOL:
        if tok[0] in TOKS_OBJS:
            sym.append(tok[1])
        elif tok == TOK_CBRAO:
            # parameterized ref: ignoring it
            if Tok.get_next() != TOK_CBRAC:
                raise(ASN1ProcTextErr('invalid module import, parameterized reference'))
        elif tok == TOK_FROM:
            tok = Tok.get_next()
            if tok[0] not in (TOK_HID, TOK_ID) or not sym:
                raise(ASN1ProcTextErr('invalid module import'))
            imp.append({'name': tok[1], 'sym': sym})
            sym, rev, tok = [], True, Tok.get_next()
            if tok == TOK_CBRAO:
                # module OID
                imp[-1]['oidtok'] = Tok.get_group()
                # TODO: parse the OID value
                
                rev = False
            elif tok[0] == TOK_LID:
                asnlog('imported module OID reference is ambiguous, %s' % tok[1])
                # will be dealt with at the end
            if rev:
                Tok.undo()
        elif tok != TOK_COM:
            raise(ASN1ProcTextErr('invalid module import'))
        tok = Tok.get_next()
    if sym:
        if len(sym) == 1 and sym[0][0].islower():
            asnlog('imported module ambiguous OID references were actually OID references') 
            # this means all those ambiguous OID ref were actually OID ref for
            # the previous module instead of imported symbols
            for i in range(len(imp)-1):
                if 'oidtok' not in imp[i] and imp[i+1]['sym'][0][0] == TOK_LID:
                    # transfer the symbol as the OID ref of the previous module
                    imp[i]['oidtok'] = imp[i+1]['sym'][0][1]
                    del imp[i+1]['sym'][0]
            imp[-1]['oidtok'] = sym[0]       
        else:
            raise(ASN1ProcTextErr('invalid module import'))
    return imp


def scan_objs(Tok):
    """consume the tokens searching for objects declaration
    """
    objs = ASN1Dict()
    while Tok.has_next():
        objdict = scan_obj(Tok)
        if objdict['name'] in objs:
            asnlog('multiple definitions of %s' % objdict['name'])
        objs[objdict['name']] = objdict
    return objs


def scan_obj(Tok):
    """consume the tokens searching for the complete declaration of a single object
    """
    # ASN.1 object structure:
    # ObjName ObjParam ObjType ::= ObjVal
    # ObjName ObjParam ObjType ::= ObjSet
    # ObjName ObjParam ::= ObjType
    # ObjName MACRO ::= BEGIN ... END
    #
    param, typedef, mode, val = None, {}, None, None
    tok = Tok.get_next()
    if tok[0] == TOK_LID:
        mode = MODE_VALUE
    elif tok[0] in (TOK_ID, TOK_HID):
        mode = MODE_TYPE
    else:
        raise(ASN1ProcTextErr('invalid object name, %r' % (tok, )))
    name = tok[1]
    tok = Tok.get_next()
    if tok == TOK_CBRAO:
        # formal parameters
        param = Tok.get_group()
        tok = Tok.get_next()
    if tok == TOK_BRAO or tok[0] in TOKS_TYPES:
        if tok[1] == 'MACRO':
            # MACRO
            if Tok.get_next() != TOK_ASSI or Tok.get_next() != TOK_BEG:
                raise(ASN1ProcTextErr('%s invalid MACRO definition' % name))
            typedef['type'] = 'MACRO'
            typedef['cont'] = Tok.get_group()
        else:
            # object value or set
            if mode == MODE_TYPE:
                mode = MODE_SET
            # object type will be rescanned in scan_typedef()
            Tok.undo()
            try:
                typedef = scan_typedef(Tok)
            except Exception as Err:
                Err.args = ('%s (%s) invalid definition, %s' % (name, mode, Err.args[0]), )
                raise(Err)
            if Tok.get_next() != TOK_ASSI:
                raise(ASN1ProcTextErr('%s (%s) invalid definition' % (name, mode)))
            try:
                val = scan_val(Tok)
            except Exception as Err:
                Err.args = ('%s (%s) invalid definition, %s' % (name, mode, Err.args[0]), )
                raise(Err)
    elif tok == TOK_ASSI:
        # object type
        if mode == MODE_VALUE:
            raise(ASN1ProcTextErr('%s (%s) invalid definition' % (name, mode)))
        try:
            typedef = scan_typedef(Tok)
        except Exception as Err:
            Err.args = ('%s (%s) invalid definition, %s' % (name, mode, Err.args[0]), )
            raise(Err)
    else:
        raise(ASN1ProcTextErr('%s invalid definition' % name))
    return {'name': name, 'param': param, 'typedef': typedef, 'mode': mode, 'val': val}


def scan_val(Tok):
    """consume the tokens searching for the complete value of a single object
    """
    if Tok.get_next() == TOK_CBRAO:
        val = [Tok.get_group()]
        return val
    else:
        val = [Tok.get_tok()]
    while Tok.has_next():
        tok = Tok.get_next()
        if tok == TOK_DOT:
            val.append(tok)
            tok = Tok.get_next()
            if tok[0] not in TOKS_OBJS_EXT:
                raise(ASN1ProcTextErr('invalid value definition'))
            val.append(tok)
        elif tok == TOK_COL:
            val.append(tok)
            val.extend( scan_val(Tok) )
        elif tok == TOK_CBRAO:
            # parameterized value
            val.append(Tok.get_group())
            return val
        else:
            Tok.undo()
            return val
    return val


def scan_typedef(Tok):
    """consume the tokens searching for the complete type declaration of a single object
    """
    # ASN.1 object type structure:
    # ObjTags ObjType ObjParamAct ObjConsts [OF] ObjCont
    # CLASS ObjCont WITH SYNTAX ObjSynt
    #
    typedict = {'tags': [], 'type': None}
    tok = Tok.get_next()
    if tok == TOK_BRAO:
        # tag(s)
        typedict['tags'] = scan_tags(Tok)
        tok = Tok.get_next()
    if tok[0] in TOKS_TYPES:
        typedict['type'] = scan_type(Tok)
        if not Tok.has_next():
            return typedict
        else:
            try:
                if typedict['type'] == ['CLASS']:
                    _scan_typedef_class(Tok, typedict)
                elif typedict['type'] in (['SET'], ['SEQUENCE']):
                    _scan_typedef_seq(Tok, typedict)
                else:
                    _scan_typedef_std(Tok, typedict)
            except Exception as Err:
                Err.args = ('invalid type definition, %s' % Err.args[0], )
                raise(Err)
            return typedict
    else:
        raise(ASN1ProcTextErr('invalid type definition'))


def scan_tags(Tok):
    tags = []
    while True:
        tags.append( scan_tag(Tok) )
        if Tok.get_next() != TOK_BRAO:
            Tok.undo()
            return tags


def scan_tag(Tok):
    tag = {'val': Tok.get_group(), 'mode': None}
    tok = Tok.get_next()
    if tok in (TOK_TEXP, TOK_TIMP):
        tag['mode'] = tok
    else:
        Tok.undo()
    return tag


def scan_type(Tok):
    typ = [Tok.get_tok()[1]]
    if Tok.has_next():
        tok = Tok.get_next()
        while tok == TOK_DOT:
            tok = Tok.get_next()
            if tok[0] not in TOKS_TYPES_EXT:
                raise(ASN1ProcTextErr('invalid composite type definition'))
            typ.append(tok[1])
            if Tok.has_next():
                tok = Tok.get_next()
            else:
                return typ
        Tok.undo()
    return typ


def _scan_typedef_class(Tok, typedict):
    # CLASS ObjCont WITH SYNTAX ObjSynt
    tok = Tok.get_next()
    if tok != TOK_CBRAO:
        raise(ASN1ProcTextErr('invalid CLASS object definition'))
    typedict['cont'] = Tok.get_group()
    if Tok.has_next():
        tok = Tok.get_next()
        if tok == TOK_WSYN:
            tok = Tok.get_next()
            if tok != TOK_CBRAO:
                raise(ASN1ProcTextErr('invalid CLASS object SYNTAX definition'))
            typedict['synt'] = Tok.get_group()
        else:
            Tok.undo()


def _scan_typedef_seq(Tok, typedict):
    # SEQUENCE / SET ObjCont ObjConsts
    # SEQUENCE / SET ObjConsts [SIZE (...)] OF ObjType
    tok = Tok.get_next()
    if tok == TOK_CBRAO:
        # ObjCont
        typedict['cont'] = Tok.get_group()
        if Tok.has_next():
            tok = Tok.get_next()
            if tok == TOK_PARO:
                typedict['const'] = scan_const(Tok)
            else:
                Tok.undo()
    elif tok in (TOK_PARO, TOK_SIZE):
        if tok == TOK_SIZE:
            # special case of the SIZE constraint outside of a constraint notation
            if Tok.get_next() != TOK_PARO:
                raise(ASN1ProcTextErr('invalid SEQ / SET OF SIZE definition'))
            typedict['const_sz'] = scan_const(Tok)
        else:
            # ObjConsts
            typedict['const'] = scan_const(Tok)
        tok = Tok.get_next()
        if tok != TOK_OF:
            raise(ASN1ProcTextErr('invalid SEQ / SET OF definition'))
        _scan_typedef_seqof(Tok, typedict)
    elif tok == TOK_OF:
        # OF
        _scan_typedef_seqof(Tok, typedict)
    else:
        raise(ASN1ProcTextErr('invalid SEQ / SET definition'))


def _scan_typedef_seqof(Tok, typedict):
    typedict['type'][0] = typedict['type'][0] + ' OF'
    # can have a component name
    tok = Tok.get_next()
    if tok[0] == TOK_LID:
        # component name
        typedict['cont_name'] = tok[1]
    else:
        Tok.undo()
    try:
        typedict['cont'] = scan_typedef(Tok)
    except Exception as Err:
        Err.args = ('invalid SEQ / SET OF definition, %s' % Err.args[0], )
        raise(Err)


def _scan_typedef_std(Tok, typedict):
    # ObjParamAct | ObjCont ObjConsts
    tok = Tok.get_next()
    if tok == TOK_CBRAO:
        typedict['cont'] = Tok.get_group()
        if not Tok.has_next():
            return
        tok = Tok.get_next()
    if tok == TOK_PARO:
        typedict['const'] = scan_const(Tok)
    else:
        Tok.undo()


def scan_const(Tok):
    const = []
    while True:
        const.append( Tok.get_group() )
        if Tok.has_next():
            if Tok.get_next() != TOK_PARO:
                Tok.undo()
                return const
        else:
            return const



def test():
    
    import os
    from pycrate_asn1c.specdir import ASN_SPECS
    
    p = os.path.dirname(__file__) + os.path.sep + '..' + os.path.sep + 'pycrate_asn1dir' + os.path.sep
    M = ASN1Dict()
    
    for S in ASN_SPECS.values():
        if isinstance(S, (list, tuple)):
            S = S[0]
        if S != 'IETF_SNMP':
            for fn in os.listdir( '%s%s/' % (p, S)):
                if fn[-4:] == '.asn':
                    fp = '%s%s/%s' % (p, S, fn)
                    print(fp)
                    if python_version < 3:
                        mods = tokenize_text(open(fp).read().decode('utf-8'))
                    else:
                        mods = tokenize_text(open(fp).read())
                    for modname, moddict in mods.items():
                        M[modname] = moddict
    return M


if __name__ == '__main__':
    import sys
    M = test()
    sys.exit(0)
