# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2017. Benoit Michau. ANSSI. P1sec.
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
# * File Name : pycrate_csn1/trans.py
# * Created : 2017-06-12
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils import *
from .utils import _RE_NAME, _RE_VAL


#------------------------------------------------------------------------------#
# CSN.1 object parser
#------------------------------------------------------------------------------#
# WNG: this parser is not implementing the whole CSN.1 language
# but only what is required in order to parse 3GPP specifications

class CSN1Obj(object):
    """Class to handle CSN.1 object parsing and definition
    
    internal attributes:
        - name: str, named of the object,
            can be a null-string in case of anonymous object
        - num : 
            int, static number of repetition for the object
                default is 1, it can be >= 0
                or -1, for an undefined number of repetitions
            (x:int, (a:int, b:int)) is an alternate possible value in case
                the number of repetitions is dynamic and depends on another 
                object:
                x: backward reference to a field into the parent object which 
                   has to be a list
                a, b: transform in the form x: a*(x+b) to be applied to the 
                      value of the backward reference to get the length of self
        - lref: enforces a limitation to the length in bits during the decoding 
                and potentially the encoding, used for lists and alternatives
            None, no limitation
            int, static limitation to the number of bits
            (x:int, (a:int, b:int)) is an alternate possible value in case the
                limitation of number of bits is dynamic and depends on another 
                object, handling is similar to num
        - ref : set of str, list all reference to external CSN.1 objects
        
        In case the CSN.1 object is a bit-field:
        - bit :
            int, static number of bits for the object
                default is 1, it can be >= 0
                or -1, for an undefined number of bits
            (x:int, (a:int, b:int)) is an alternate possible value in case
                the number of bits is dynamic and depends on another 
                object, handling is similar to num
        - excl: None or CSN1Val, list of excluded values
        
        In case the CSN.1 object is a list of objects:
        - list: list, list of contained objects
        
        In case the CSN.1 object is a list of alternatives:
        - alt : list, list of alternative lists of contained objects
    """
    # CSN.1 default type is unsigned integer
    TYPE = CSN1T_UINT
    # the syntax does not give hint on how to handle an object (like an integer,
    # signed, unsigned, ... or like a bit string ...)
    # hence, the type has to be set by hand, if not handled like this default CSN1T_UINT
    # the only supported alternative yet is CSN1T_BSTR
    
    def __init__(self, name, text='', EOT=None):
        # A CSN.1 object is named or anonymous
        self._name = name
        # A CSN.1 object can be repeated multiple times (self._num >= 0)
        # or until there is no more buffer to consume (self._num == -1)
        self._num  = 1
        # reference to a backward field enforcing the length in bits
        self._lref = None
        # reference to a parent object
        self._par  = None 
        
        # external object's reference(s) tracker, required for regenerating source code
        self._ref  = set()
        #
        # A CSN.1 object is a bit-field (self._bit),
        # a list of CSN.1 objects (self._list)
        # or a list of alternative of list of CSN.1 objects (self._alt)
        self._bit  = None # in case object is a single bit-field
        self._excl = None # in case object is a single bit-field with excluded value
        self._list = None # in case object is a list of objects
        self._alt  = None # in case object is a choice between mutliple alternatives
        #
        if text:
            text = self.parse_def(text, EOT)
    
    def reduce(self):
        """
        optimizes the content of self in various ways
        
        returns a new CSN1Obj if modified, or self
        """
        #
        ret = self
        #
        if hasattr(self, '_alt') and self._alt is not None:
            # processing alternatives
            if hasattr(self, '_err'):
                # ignoring error branch at this time
                # TODO: handle error branch
                del self._alt[self._err]
                del self._err
            #
            if len(self._alt) == 1:
                # if this is an alternative with a single possibility
                # we convert it back to a list
                if isinstance(self._alt[0], list):
                    self._list = self._alt[0]
                else:
                    # this list with a single element will get reduced below
                    self._list = [self._alt[0]]
                self._alt  = None
            #
            elif hasattr(self, '_ref') and not self._ref and \
            self._num == 1 and self._lref is None and \
            all([isinstance(Obj, CSN1Val) for Obj in self._alt]):
                # if this is an alternative between multiple values
                # we convert it to a CSN1Val with the list of given values
                New = CSN1Val(name=self._name)
                for alt in self._alt:
                    New._val.extend( alt._val )
                ret = New
        #
        if hasattr(self, '_list') and self._list is not None:
            # processing list
            if len(self._list) == 1:
                # if this is a list with a single object
                # we return this single object
                # WNG: this could assert in some extrem cases
                New = self._list[0]
                if self._num != 1:
                    assert( New._num == 1 )
                    New._num = self._num
                if self._lref is not None:
                    assert( New._lref is None )
                    New._lref = self._lref
                if hasattr(self, '_trunc'):
                    assert( hasattr(New, '_list') and New._list is not None )
                    New._trunc = True
                # reattribute self._name to the inner object New
                if self._name:
                    New._name = self._name
                ret = New
        #
        if hasattr(self, '_alt') and not self._alt and \
        hasattr(self, '_list') and not self._list:
            # processing bit / octet
            if isinstance(self._bit, integer_types) and \
            isinstance(self._num, integer_types) and self._num > 1:
                self._bit *= self._num
                self._num  = 1
        #
        if isinstance(self, CSN1Ref):
            # processing reference
            if self._obj == 'null' and self._num == 1 and self._lref is None:
                # if this is a ref to null
                # we convert it to a CSN1Val with a single null value
                New = CSN1Val(name=self._name)
                New._val = ['null']
                ret = New
        #
        return ret
    
    def resolve_refs(self):
        """
        resolves all references between internal objects
        
        need to be done after all parents' objects have been reduce() properly
        """
        if isinstance(self._lref, tuple):
            assert( isinstance(self._lref[0], str_types) )
            self._resolve_ref('_lref')
        elif isinstance(self._num, tuple):
            assert( isinstance(self._num[0], str_types) )
            self._resolve_ref('_num')
        #
        if hasattr(self, '_bit') and isinstance(self._bit, tuple):
            # CSN1Bit
            assert( isinstance(self._bit[0], str_types) )
            self._resolve_ref('_bit')
        elif hasattr(self, '_list') and self._list:
            # CSN1List: process internal list objects recursively
            for child in self._list:
                child._par = (self, self._list)
                child.resolve_refs()
        elif hasattr(self, '_alt') and self._alt:
            # CSN1Alt: process internal alternatives objects recursively
            #for alt in [alt for alt in self._alt if isinstance(alt, list)]:
            #    for child in alt[1:]:
            for alt in self._alt:
                if isinstance(alt, list):
                    for child in alt:
                        child._par = (self, alt)
                        child.resolve_refs()
                elif isinstance(alt, CSN1Obj):
                    alt._par = (self, alt)
                    alt.resolve_refs()
                else:
                    assert()
    
    def _resolve_ref(self, attr):
        ref = getattr(self, attr)
        if ref[0][0] == '#':
            # manual conversion is required due to special arithmetic
            setattr(self, attr, (ref[0], (None, None)))
            return
        #
        # check within parents' iteratively to find the reference
        par, path = self._par, []
        while True:
            if par is None:
                # error while searching for the reference
                log('WARN: unable to resolve reference, %s' % ref[0])
                log('    do it by hand within the Python file generated')
                setattr(self, attr, ('# unresolved: %s' % ref[0], (None, None)))
                return
            #
            names = [obj._name for obj in par[1]]
            if ref[0] not in names:
                path.append(-1)
                par = par[0]._par
            else:
                path.append( names.index(ref[0]) )
                break
        setattr(self, attr, (path, ref[1]))
    
    def __repr__(self):
        if self._bit is not None:
            suf = 'Bit'
        elif self._list:
            suf = 'List'
        elif self._alt:
            suf = 'Alt'
        else:
            suf = ''
        return '%s%s(%s)' % (self.__class__.__name__, suf, self._name)
    
    def __continue(self, text, EOT):
        if text:
            if EOT is None:
                return True
            elif text[0:1] not in EOT:
                return True
            else:
                return False
        else:
            return False
    
    def parse_def(self, text, EOT=None):
        """
        parses the text corresponding to the CSN.1 object definition
        
        object definition can be:
        - a bit definition, e.g. "bit (10)" or "bit == 1"
        - a fixed bit value, e.g. "10110" or "HL"
        - a reference to another object, e.g. "< OtherObject >"
        - an inlined object definition, e.g. "< OtherObject: bit(10) >"
        - a list of alternatives, e.g.
          "{ 00 | 11 | 01 < Object-1 > | 10 < Object-2 > }"
        """
        self._text_def = text
        while self.__continue(text, EOT):
            #
            if text[0:3] == 'bit':
                # bit definition
                assert( self._bit is None )
                if self._list is None:
                    self._list = []
                text = self._parse_bit(text)
            #
            elif text[0:5] == 'octet':
                # octet definition
                assert( self._bit is None )
                if self._list is None:
                    self._list = []
                text = self._parse_octet(text)
            #
            elif text and text[0:1] in '01LHn':
                # fixed anonymous bit value
                assert( self._bit is None )
                if self._list is None:
                    self._list = []
                text = self._parse_anon_val(text)
            #
            elif text[0:1] == '<':
                # reference to another object or inlined object definition
                assert( self._bit is None )
                if self._list is None:
                    self._list = []
                text = self._parse_obj(text[1:].lstrip())
            #
            elif text[0:1] == '{':
                # precedence token, subgroup handled as an anonymous object
                assert( self._bit is None )
                if self._list is None:
                    self._list = []
                text = self._parse_grp(text[1:].lstrip())
            #
            elif text[0:1] in ('|', '!'):
                assert( self._bit is None and self._list is not None )
                # put the previous list of object as a potential alternative
                if self._alt is None:
                    self._alt = []
                self.__insert_alt()
                #
                if text[0:1] == '!':
                    # the next list correspond to an error case
                    self._err = len(self._alt)
                #
                text = text[1:].lstrip()
            #
            elif text[0:2] == '//':
                # TODO: handle truncation somewhere
                self._trunc = True
                text = text[2:].lstrip()
            #
            elif text[0:1] == '&':
                lenl, bit, obj = len(self._list), None, None
                assert(lenl >= 1)
                if self._list[-1]._name == '' and self._list[-1]._bit:
                    bit = self._list[-1]
                    off = -2
                else:
                    obj = self._list[-1]
                    off = -1
                #
                # this should happen only within a < ... > struct
                text = self.parse_def(text[1:].lstrip(), '>')
                assert(len(self._list) == lenl + 1)
                # 1 of the 2 objects must be bit
                if bit is None:
                    assert( obj is not None )
                    bit = self._list[-1]
                    assert( bit._name == '' and bit._bit )
                else:
                    assert( bit is not None )
                    obj = self._list[-1]
                #
                assert( isinstance(obj, CSN1Ref) or obj._list or obj._alt )
                obj._lref = bit._bit
                del self._list[off]
                assert(not text or text[0:1] == '>')
                text = text[1:].lstrip()
            #
            else:
                m = re.match(_RE_NAME, text)
                if m:
                    # simple reference
                    assert( self._bit is None and self._list is None and self._alt is None )
                    Ref = CSN1Ref('', m.group())
                    Ref = Ref.reduce()
                    self._list = [Ref]
                    text = text[m.end():].lstrip()
                    if text[0:1] == '>':
                        break
                raise(CSN1Err('{0}: invalid text definition, {1}'\
                      .format(self._name, text)))
        #
        if EOT is None:
            if self._alt is not None:
                # in case self is an alternative object outside of any subgroups 
                # we need to transfer the last list within alt
                self.__insert_alt()
        #
        return text
    
    def __insert_list(self, Obj):
        assert( self._list is not None )
        self._list.append( Obj )
        #
        if isinstance(Obj, CSN1Val):
            pass
        elif isinstance(Obj, CSN1Ref):
            self._ref.add(Obj._obj)
        else:
            self._ref.update(Obj._ref)
    
    def __insert_alt(self):
        assert( self._list )
        # optimization to remove unneeded wrapping list of length 1
        if len(self._list) == 1:
            # if this is a list of a single object
            # we keep only this single object
            self._alt.append( self._list[0] )
        else:
            self._alt.append( self._list )
        self._list = None
    
    def _parse_bit(self, text):
        """
        parses the text corresponding to a bit definition,
        e.g. "bit (10)" or "bit == 1"
        """
        text = text[3:].lstrip()
        if text and text[0:1] in '(*':
            # Obj._bit can be of fixed length, or of dynamic length with a ref
            Obj = CSN1Obj('')
            Obj._bit, text = CSN1Obj._parse_repet(text)
        else:
            Obj = CSN1Obj('')
            Obj._bit = 1
            if text and text[0:1] == '=':
                text = CSN1Obj._parse_nostr(text)
        #
        if text and text[0:2] == '==':
            # this is actually not an object, but a fixed value
            # self (CSN1Obj) will be converted to a CSN1Val afterward
            text = text[2:].lstrip()
            Val = CSN1Val('')
            text = Val.parse_val(text)
            if isinstance(Obj._bit, tuple) or \
            isinstance(Obj._bit, integer_types) and \
            not all([len(v) == Obj._bit for v in Val._val]):
                raise(CSN1Err('%: invalid mix of value and length constraint'\
                      % self._name))
            else:
                Obj = Val
        elif text[0:7] == 'exclude':
            excl, text = CSN1Obj._parse_excl(text[7:].lstrip())
            for val in excl._val:
                assert( len(val) == Obj._bit )
            Obj._excl = excl
        #
        self.__insert_list( Obj.reduce() )
        return text
    
    def _parse_octet(self, text):
        """
        parses the text corresponding to an octet definition,
        e.g. "octet (2)"
        """
        text = text[5:].lstrip()
        if text and text[0:1] in '(*':
            # Obj._bit can be of fixed length, or of dynamic length with a ref
            Obj = CSN1Obj('')
            Obj._bit, text = CSN1Obj._parse_repet(text)
            Obj._num = Obj._bit
            Obj._bit = 8
        else:
            Obj = CSN1Obj('')
            Obj._bit = 8
        #
        self.__insert_list( Obj.reduce() )
        return text
    
    def _parse_anon_val(self, text):
        """
        parses the text corresponding to an anonymous value, e.g. "010"
        """
        Val = CSN1Val('')
        text = Val.parse_val(text)
        self.__insert_list( Val.reduce() )
        return text
    
    def _parse_obj(self, text):
        """
        parses the text corresponding to the definition of another object, 
        e.g. "< AnotherObject ... >"
        """
        m = re.match(_RE_NAME, text)
        if not m:
            raise(CSN1Err('{0}: invalid object name, {1}'\
                  .format(self._name, text)))
        name = m.group().strip()
        if name == 'bit':
            text = self._parse_bit(text)
            if text[0:1] == '>':
                text = text[1:].lstrip()
            else:
                assert( text[0:1] == '&' )
        else:
            text = text[m.end():].lstrip()
            if text[0:1] == ':':
                # inlined CSN.1 object bit definition
                Obj = CSN1Obj(name)
                text = Obj.parse_def(text[1:].lstrip(), EOT='>')
                text = text[1:].lstrip()
                Obj = Obj.reduce()
                if text[0:7] == 'exclude':
                    excl, text = CSN1Obj._parse_excl(text[7:].lstrip())
                    assert( Obj._bit is not None )
                    for val in excl._val:
                        assert( len(val) == Obj._bit )
                    Obj._excl = excl
                if text and text[0:1] in '(*':
                    assert( Obj._num == 1 )
                    Obj._num, text = CSN1Obj._parse_repet(text)
                self.__insert_list( Obj )
            elif text[0:1] == '>':
                # new ref to another object
                Obj = CSN1Ref('', name)
                text = text[1:].lstrip()
                if text and text[0:1] in '(*':
                    Obj._num, text = CSN1Obj._parse_repet(text)
                self.__insert_list( Obj.reduce() )
            else:
                raise(CSN1Err('{0}: invalid internal object definition, {1}'\
                      .format(self._name, text)))
        #
        return text
    
    def _parse_grp(self, text):
        """
        parses the text corresponding to the definition of an embedded object
        up to the terminating "}"
        """
        Obj = CSN1Obj('')
        text = Obj.parse_def(text, EOT='}')
        text = text[1:].lstrip()
        # in case this is an alternative, transfer the last list to alt
        if Obj._alt is not None:
            Obj.__insert_alt()
        if text and text[0:1] in '(*':
            Obj._num, text = CSN1Obj._parse_repet(text)
        self.__insert_list( Obj.reduce() )
        return text
    
    @classmethod
    def _parse_repet(cls, text):
        # parses the arithmetic expression for a length or number of iterations
        # can be a fixed integer value
        # or a dynamic value referencing a value from an upper field
        #    eventually transformed through a function x -> a*(x+b) 
        if text[0:1] == '*':
            text = text[1:].lstrip()
            if text[0:1] == '*':
                # indefinite number of iterations
                text = CSN1Obj._parse_nostr(text[1:].lstrip())
                return -1, text
            elif text[0:1] == '(':
                # fixed of dynamic arithmetic expr
                expr_arithm, text = CSN1Obj._parse_arithm(text)
                text = CSN1Obj._parse_nostr(text)
                return expr_arithm, text
            else:
                # must be an unsigned integer
                m = re.match(r'[0-9\s]{1,}', text)
                if not m:
                    raise(CSN1Err('CSN1Obj._parse_repet: invalid definition, %s'\
                          % text))
                text = CSN1Obj._parse_nostr(text[m.end():].lstrip())
                return int(re.sub(r'\s', '', m.group())), text
        else:
            assert(text[0:1] == '(')
            text_tmp = text[1:].lstrip()
            if text_tmp[0:1] == '*':
                text_tmp = text_tmp[1:].lstrip()
                if text_tmp[0:1] == ')':
                    text = CSN1Obj._parse_nostr(text_tmp[1:].lstrip())
                    return -1, text
            expr_arithm, text = CSN1Obj._parse_arithm(text)
            text = CSN1Obj._parse_nostr(text)
            return expr_arithm, text
    
    @classmethod
    def _parse_nostr(cls, text):
        m = SYNT_RE_NOSTR.match(text)
        if m:
            # TODO: handle this encoding directive, i.e. send construction.
            return text[m.end():].lstrip()
        else:
            return text
    
    _scanner_arithm = [
        ('[0-9\s]{1,}',  TOK_UINT, lambda m: int(re.sub(r'\s', '', m.group()))),
        (_RE_VAL,        TOK_REF,  lambda m: m.group(1).strip()),
        ('\+',           TOK_ADD,  arithm_get_expr),
        ('\-',           TOK_SUB,  arithm_get_expr),
        ('\*',           TOK_MUL,  arithm_get_expr),
        ('\(',           TOK_OPEN, arithm_get_expr),
        ('\)',           TOK_CLOS, arithm_get_expr)
        ]
    
    @classmethod
    def _parse_arithm(cls, text):
        # parses the arithmetic expression between ( and )
        # 1) extract all possible arithm token up to the closure )
        text = text[1:].lstrip()
        op_clo, toks, err = [1, 0], [], False
        while op_clo[1] < op_clo[0]:
            match = False
            for expr, tok, trans in cls._scanner_arithm:
                m = re.match(expr, text)
                if m:
                    toks.append( (tok, trans(m)) )
                    if tok == TOK_OPEN:
                        op_clo[0] += 1
                    elif tok == TOK_CLOS:
                        op_clo[1] += 1
                    # exit the for loop
                    match = True
                    text = text[m.end():].lstrip()
                    break
            if not match:
                # in case of invalid token, we warns and skip the whole expr
                err = True
                break
        #
        if err:
            toks = [str(t[1]) for t in toks]
            # just for counting "(" and ")" to jump over the arithmetic expr
            toks.insert(0, '(')
            toks.append(text[0:1])
            text = text[1:]
            while text and op_clo[1] < op_clo[0]:
                if text[0:1] == '(':
                    op_clo[0] += 1 
                elif text[0:1] == ')':
                    op_clo[1] += 1
                toks.append(text[0:1])
                text = text[1:]
            log('WARN: unable to process arithmetic expression, %s' % ''.join(toks))
            log('    do it by hand within the Python file generated')
            return ('# unprocessed: %s' % ''.join(toks),
                    (None, None)), text.lstrip()
        #
        # remove last closing parenthesis
        del toks[-1]
        # remove unneeded parenthesis
        try:
            ind = [t[0] for t in toks].index(TOK_REF)
        except:
            pass
        else:
            if len(toks) >= 3 and toks[ind-1][0] == TOK_OPEN and toks[ind+1][0] == TOK_CLOS:
                del toks[ind+1]
                del toks[ind-1]
        try:
            return CSN1Obj._process_arithm(toks), text
        except:
            log('WARN: unable to process arithmetic expression, (%s)'\
                % ''.join([str(t[1]) for t in toks]))
            assert()
            log('    do it by hand within the Python file generated')
            return ('# unprocessed: %s' % ''.join([str(t[1]) for t in toks]), 
                    (None, None)), text.lstrip()
    
    @classmethod
    def _process_arithm(cls, toks):
        # process the list of tokens into a single fixed uint or 
        # an lref-style tuple for dynamic value
        if len(toks) == 1:
            if toks[0][0] == TOK_UINT:
                return toks[0][1]
            elif toks[0][0]:
                return (toks[0][1], (1, 0))
            else:
                raise(CSN1Err('unsupported'))
        else:
            # WARNING: this is a very crude and incomplete way to get
            # an affine-like function from the list of tokens...
            # this code is really crappy
            if len(toks) == 3:
                return cls._process_arithm_grp(*toks)
            elif len(toks) == 7:
                if toks[0][0] == TOK_OPEN and toks[4][0] == TOK_CLOS \
                and toks[5][0] == TOK_MUL or toks[6][0] == TOK_UINT:
                    tok_ref, (a, b) = cls._process_arithm_grp(*toks[1:4])
                    if a != 1:
                        raise(CSN1Err('unsupported'))
                    return (tok_ref, (toks[6][1], b))
                elif toks[0][0] == TOK_UINT and toks[1][0] == TOK_MUL \
                and toks[2][0] == TOK_OPEN and toks[6][0] == TOK_CLOS:
                    tok_ref, (a, b) = cls._process_arithm_grp(*toks[3:6])
                    if a != 1:
                        raise(CSN1Err('unsupported'))
                    return (tok_ref, (toks[0][1], b))
                else:
                    raise(CSN1Err('unsupported'))
            else:
                raise(CSN1Err('unsupported'))
    
    @classmethod
    def _process_arithm_grp(cls, tok0, tok1, tok2):
        # get fixed operand and variable ref
        if tok0[0] == TOK_REF:
            tok_ref = tok0[1]
            if tok2[0] == TOK_UINT:
                tok_op  = tok2[1]
            else:
                raise(CSN1Err('unsupported'))
        elif tok0[0] == TOK_UINT:
            tok_op = tok0[1]
            if tok2[0] == TOK_REF:
                tok_ref = tok2[1]
            else:
                raise(CSN1Err('unsupported'))
        else:
            raise(CSN1Err('unsupported'))
        # get operation
        if tok1[0] == TOK_ADD:
            return tok_ref, (1, tok_op)
        elif tok1[0] == TOK_SUB:
            #return tok_ref, (-1, -tok_op)
            if tok0[0] == TOK_REF:
                return tok_ref, (1, -tok_op)
            else:
                return tok_ref, (-1, -tok_op)
        elif tok1[0] == TOK_MUL:
            return tok_ref, (tok_op, 0)
        else:
            raise(CSN1Err('unsupported'))
    
    @classmethod
    def _parse_excl(cls, text):
        if text and text[0:1] in '01LHn':
            m = SYNT_RE_VALUE.match(text)
            if not m:
                raise(CSN1Err('CSN1Obj._parse_excl: invalid value definition, {1}'\
                      .format(text)))
            text_val = re.sub('\s', '', m.group())
            text = text[m.end():].lstrip()
            return CSN1Val('', text_val), text
        elif text[0:1] == '{':
            text = text[1:].lstrip()
            Val = CSN1Val('')
            while text[0:1] != '}':
                text = Val.parse_val(text)
                if text[0:1] == '|':
                    text = text[1:].lstrip()
            return Val, text[1:].lstrip()


class CSN1Ref(CSN1Obj):
    """Class to handle simple reference to other CSN.1 object
    """
    def __init__(self, name, obj):
        self._name = name
        self._obj  = obj
        self._num  = 1
        self._lref = None
        self._par  = None
        self._ref  = set( [obj] )
    
    def __repr__(self):
        if self._name:
            return 'CSN1Ref(%s, obj=%s)' % (self._name, self._obj)
        else:
            return 'CSN1Ref(obj=%s)' % self._obj


class CSN1Val(CSN1Obj):
    """Class to handle CSN.1 value, as used within choice
    """
    def __init__(self, name='', text=''):
        self._name = name
        self._val  = []
        self._num  = 1
        self._lref = None
        self._par  = None
        self._ref  = set()
        if text:
            text = self.parse_val(text)
    
    def __repr__(self):
        if self._name:
            return 'CSN1Val(%s: %r)' % (self._name, self._val)
        else:
            return 'CSN1Val(%r)' % self._val
    
    def parse_val(self, text):
        self._text_val = text
        m = SYNT_RE_VALUE.match(text)
        if not m:
            raise(CSN1Err('{0}: invalid value definition, {1}'\
                  .format(self._name, text)))
        text_val = re.sub('\s', '', m.group())
        text = text[m.end():].lstrip()
        if text and text[0:1] in '(*':
            num, text = CSN1Obj._parse_repet(text)
            if num == -1:
                text_val += '**'
            else:
                text_val = num*text_val
        self._val.append( text_val )
        return text


#------------------------------------------------------------------------------#
# CSN.1 predefined objects
#------------------------------------------------------------------------------#

spare_bit = CSN1Obj('spare bit')
spare_bit._bit = 1

spare_bits = CSN1Obj('spare bits')
spare_bits._bit = 1
spare_bits._num = -1

spare_padding = CSN1Val('spare padding')
spare_padding._val = ['L**']

octet = CSN1Obj('octet')
octet._bit = 8

def get_predef_obj(bit=True, bits=True, padding=True, octet=True):
    """Returns a dict with the following predefined objects:
    <spare bit>
    <spare bits>
    <spare padding>
    """
    ret = {}
    if bit:
        ret['spare_bit'] = spare_bit
        ret['Spare_bit'] = spare_bit
        ret['Spare_Bit'] = spare_bit
    if bits:
        ret['spare_bits'] = spare_bits
        ret['Spare_bits'] = spare_bits
        ret['Spare_Bits'] = spare_bits
    if padding:
        ret['spare_padding'] = spare_padding
        ret['Spare_padding'] = spare_padding
        ret['Spare_Padding'] = spare_padding
    if octet:
        ret['octet'] = octet
        ret['Octet'] = octet
    return ret

def gen_predef_obj(bit=True, bits=True, padding=True, octet=True):
    """Returns the textual definition of the following predifined objects:
    <spare bit>
    <spare bits>
    <spare padding>
    """
    ret = []
    if bit:
        ret.append('''
spare_bit = CSN1Bit(name='spare_bit')
Spare_bit = spare_bit
Spare_Bit = spare_bit
''')
    if bits:
        ret.append('''
spare_bits = CSN1Bit(name='spare_bits', num=-1)
Spare_bits = spare_bits
Spare_Bits = spare_bits
''')
    if padding:
        ret.append('''
spare_padding = CSN1Val(name='spare_padding', val='L', num=-1)
Spare_padding = spare_padding
Spare_Padding = spare_padding 
''')
    if octet:
        ret.append('''
octet = CSN1Bit(name='octet', num=8)
Octet = octet
''')
    return ''.join(ret) + '\n'

def set_predef_arg(Obj, parg):
    for dep in Obj._ref:
        if pythonize_name(dep) in ('spare_bit', 'Spare_bit', 'Spare_Bit'):
            parg[0] = True
        elif pythonize_name(dep) in ('spare_bits', 'Spare_bits', 'Spare_Bits'):
            parg[1] = True
        elif pythonize_name(dep) in ('spare_padding', 'Spare_padding', 'Spare_Padding'):
            parg[2] = True
        elif pythonize_name(dep) in ('octet', 'Octet'):
            parg[3] = True

#------------------------------------------------------------------------------#
# CSN.1 definition translator
#------------------------------------------------------------------------------#

global obj_name

def translate_text(text=u'', **kwargs):
    """Scans a text (or list of texts) for CSN.1 object definitions
    
    translate them and return prototype Python definitions, to be used with
    the CSN.1 runtime
    
    Args:
        text (str, or iterable of str): textual CSN.1 definition(s)
    
    Returns:
        result (3-tuple): a dict with generated Python objects,
                          a set of external references and
                          a text str containing the corresponding Python source code
    """
    if isinstance(text, (list, tuple)):
        text = u'\n\n'.join(text)
    elif not isinstance(text, str_types):
        raise(CSN1Err('[proc] need some textual definition'))
    text = clean_text(text)
    Objs, ret = {}, []
    global obj_name
    #
    # 0) add all predifined objects
    predef = get_predef_obj(True, True, True, True)
    predef_name = list(predef.keys())
    predef_args = [False, False, False, False]
    #
    # 1) process definition until the end of the text
    while text:
        text = process_definition(text, Objs, **kwargs)
    #
    # 2) sort local / external references
    ObjList = list(Objs.keys())
    # collect all references
    RefList = set()
    for Obj in Objs.values():
        for ref in Obj._ref:
            RefList.add(pythonize_name(ref))
    # identify the set of external references
    ExtSet = set()
    for ref in RefList:
        if ref not in ObjList and ref not in predef:
            ExtSet.add(ref)
    #
    # 3) translate objects in the required local referencing order
    while ObjList:
        obj_len = len(ObjList)
        for pyname in ObjList[:]:
            Obj = Objs[pyname]
            if isinstance(Obj, CSN1Val) or not Obj._ref:
                # object without dependency
                obj_name  = pyname
                Obj._root = True
                ret.append( '%s = %s\n' % (pyname, translate_object(Obj)) )
                ObjList.remove( pythonize_name(Obj._name) )
            else:
                if all([pythonize_name(dep) not in ObjList or \
                        pythonize_name(dep) == pyname or \
                        pythonize_name(dep) in predef_name \
                        for dep in Obj._ref]):
                    # object with all local dependencies already defined
                    obj_name  = pyname
                    Obj._root = True
                    ret.append( '%s = %s\n' % (pyname, translate_object(Obj)) )
                    ObjList.remove( pythonize_name(Obj._name) )
                    set_predef_arg(Obj, predef_args)
        # ensure we keep defining objects
        if len(ObjList) == obj_len:
            log('ERR: unable to define objects, %r' % ObjList)
            break
    #l
    # 3) return python source
    return Objs, ExtSet, \
           '# code automatically generated by pycrate_csn1\n' + \
           '# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init\n' + \
           '# add dict for value interpretation with dic={...} in CSN1Bit init\n'  + \
           '# add dict for key interpretation with kdic={...} in CSN1Alt init\n\n' + \
           'from pycrate_csn1.csnobj import *\n' + \
           gen_predef_obj(*predef_args) + \
           '\n'.join(ret)


def process_definition(text, Objs, **kwargs):
    """Processes a single CSN.1 definition and returns a Python object
    """
    # look for the assignment sign ::=
    m = re.search('::=', text)
    if not m:
        log('CSN.1 object assignment sign ::= not found')
        return ''
    # get the object name
    text_name = text[:m.start()].strip()
    text = text[m.end():].strip()
    m = SYNT_RE_NAME.match(text_name)
    if not m:
        raise(CSN1Err('missing CSN.1 object name'))
    name = m.group(1).strip()
    # scan the object definition up to the 1st semi-colon
    m = re.search(';', text)
    if not m:
        raise(CSN1Err('missing CSN.1 object end-of-definition sign ;'))
    text_def = text[:m.start()].strip()
    text = text[m.end():].strip()
    # create a pythonic name
    pyname = pythonize_name(name)
    # populate the object dict
    Obj = CSN1Obj(name, text_def)
    Obj = Obj.reduce()
    Obj.resolve_refs()
    Objs[pyname] = Obj
    return text


def translate_object(Obj):
    if isinstance(Obj, CSN1Ref):
        return translate_ref(Obj)
    elif isinstance(Obj, CSN1Val):
        return translate_val(Obj)
    elif Obj._bit is not None:
        return translate_bit(Obj)
    elif Obj._list is not None:
        return translate_list(Obj)
    elif Obj._alt is not None:
        return translate_alt(Obj)
    else:
        assert()


def _translate_arithm(val):
    if isinstance(val, integer_types):
        return '%i' % val
    else:
        if isinstance(val[1], tuple) and len(val[1]) == 2 and \
        isinstance(val[1][0], integer_types) and \
        isinstance(val[1][1], integer_types):
            if val[1][1] != 0:
                if val[1][0] == 1:
                    trans = 'lambda x: x + %i' % val[1][1]
                else:
                    trans = 'lambda x: %i * (x + %i)' % val[1]
            else:
                if val[1][0] == 1:
                    trans = 'lambda x: x'
                else:
                    trans = 'lambda x: %i * x' % val[1][0]
        else:
            trans = 'lambda: 0'
        if isinstance(val[0], str_types):
            return '(%r, %s)' % (val[0], trans)
        else:
            return '(%s, %s)' % (val[0], trans)


def translate_ref(Obj):
    global obj_name
    name, obj, args = pythonize_name(Obj._name), Obj._obj, []
    if pythonize_name(obj) == obj_name:
        # self reference
        cla = 'CSN1SelfRef'
    elif obj[:11] == '__pycrate__':
        cla = 'CSN1ExtRef'
        if Obj._name:
            args.append( 'name=%r' % name )
        args.append( 'obj=%s' % repr(tuple(obj[12:].split('.'))) )
    else:
        cla = 'CSN1Ref'
        if Obj._name:
            args.append('name=%r' % name)
        args.append( 'obj=%s' % pythonize_name(obj) )
    if Obj._num != 1:
        args.append( 'num=%s' % _translate_arithm(Obj._num) )
    if Obj._lref is not None:
        args.append( 'lref=%s' % _translate_arithm(Obj._lref) )
    return '%s(%s)' % (cla, ', '.join(args))


def translate_val(Obj):
    if len(Obj._val) == 1:
        if Obj._num == 1:
            return 'CSN1Val(name=%r, val=%r)' \
                   % (pythonize_name(Obj._name), Obj._val[0])
        else:
            return 'CSN1Val(name=%r, val=%r, num=%s)' \
                   % (pythonize_name(Obj._name), Obj._val[0],
                      _translate_arithm(Obj._num))
    else:
        # convert to a list of alternatives
        Alt = CSN1Obj(name=Obj._name)
        Alt._alt = [CSN1Val('', v) for v in Obj._val]
        if hasattr(Obj, '_root') and Obj._root:
            Alt._root = True
        return translate_alt(Alt)


def translate_bit(Obj):
    args = []
    if Obj._name:
        args.append( 'name=%r' % pythonize_name(Obj._name) )
    if Obj._bit != 1:
        if isinstance(Obj._bit, integer_types) and \
        isinstance(Obj._num, integer_types) and Obj._num > 1:
            # quick optimization
            Obj._bit *= Obj._num
            Obj._num = 1
        args.append( 'bit=%s' % _translate_arithm(Obj._bit) )
    if Obj._num != 1:
        args.append( 'num=%s' % _translate_arithm(Obj._num) )
    if Obj._lref is not None:
        args.append( 'lref=%s' % _translate_arithm(Obj._lref) )
    if Obj._excl is not None:
        # we only keep raw bit-strings 
        args.append( 'excl=%r' % Obj._excl._val )
    return 'CSN1Bit(%s)' % ', '.join(args)


def translate_list(Obj):
    # translate each list internal object on a new line
    args = []
    if Obj._name:
        args.append( 'name=%r' % pythonize_name(Obj._name) )
    if Obj._num != 1:
        args.append( 'num=%s' % _translate_arithm(Obj._num) )
    if Obj._lref is not None:
        args.append( 'lref=%s' % _translate_arithm(Obj._lref) )
    if hasattr(Obj, '_trunc'):
        args.append( 'trunc=True' )
    if Obj._list:
        args.append( 'list=' + _translate_objlist(Obj._list) )
    return 'CSN1List(%s)' % ', '.join(args)


def translate_alt(Obj):
    selec = build_alt_selector(Obj)
    args = []
    if Obj._name:
        args.append( 'name=%r' % pythonize_name(Obj._name) )
    if Obj._num != 1:
        args.append( 'num=%s' % _translate_arithm(Obj._num) )
    if Obj._lref is not None:
        args.append( 'lref=%s' % _translate_arithm(Obj._lref) )
    if hasattr(Obj, '_trunc'):
        args.append( 'trunc=True' )
    #
    arg_alt = []
    for (val, (val_name, objs)) in selec.items():
        arg_alt.append( '  %r: (%r, %s),\n' % (val, val_name, _translate_objlist(objs)) )
    # sorting alternatives
    arg_alt.sort()
    if len(arg_alt):
        arg_alt = 'alt={\n' + ''.join(arg_alt)[:-2] + '}'
    else:
        arg_alt = 'alt={}'
    args.append( arg_alt )
    return 'CSN1Alt(%s)' % ', '.join(args)


def _translate_objlist(ol):
    ret = ['[\n']
    for obj in ol:
        ret.append( '  %s,\n' % translate_object(obj).replace('\n', '\n  ') )
    if len(ret) > 1:
        ret[-1] = ret[-1][:-2] + ']'
    else:
        ret[0] = ret[0][:-1] + ']' 
    return ''.join(ret)


def build_alt_selector(Obj):
    # define a discriminant for each branch and build a dict according to
    # determined selectors
    selec, has_null, req_null = [], [], []
    for alt in Obj._alt:
        # check the 1st field of each alternative
        if isinstance(alt, CSN1Val):
            # single value that means that we exit the object
            if len(alt._val) > 1:
                # multiple values
                for val in alt._val:
                    if val == 'null':
                        has_null.append( True )
                    else:
                        # potential alternative
                        if val[-2:] == '**':
                            # take care of repeated value (e.g. 0**)
                            nv = ASN1Val()
                            nv.parse_val(val)
                            selec.append( (val[:-2], (pythonize_name(alt._name), [nv])) )
                        else:
                            selec.append( (val, (pythonize_name(alt._name), [])) )
                        has_null.append( False )
            else:
                if alt._val[0] == 'null':
                    # no more bit to consume, exiting the structure
                    has_null.append(True)
                else:
                    # potential alternative
                    if alt._val[0][-2:] == '**':
                        # take care of repeated value (e.g. 0**)
                        selec.append( (alt._val[0][:-2], (pythonize_name(alt._name), [alt])) )
                    else:
                        selec.append( (alt._val[0], (pythonize_name(alt._name), [])) )
                    has_null.append( False )
        #
        elif isinstance(alt, CSN1Ref):
            selec.append( ('', (pythonize_name(alt._name), [alt])) )
            req_null.append( True )
        #
        elif isinstance(alt, list):
            # list of fields
            if isinstance(alt[0], CSN1Val):
                if len(alt[0]._val) > 1:
                    # multiple values
                    # associate all of them with the rest of the objects' list
                    rest = alt[1:]
                    for val in alt[0]._val:
                        if val[-2:] == '**':
                            raise(CSN1Err('unsupported alternative key, %s' % val))
                        selec.append( (val, (pythonize_name(alt[0]._name), rest)) )
                        has_null.append( False )
                else:
                    if alt[0]._val[0][-2:] == '**':
                        raise(CSN1Err('unsupported alternative key, %s' % alt[0]._val[0]))
                    selec.append( (alt[0]._val[0], (pythonize_name(alt[0]._name), alt[1:])) )
                    has_null.append( False )
            elif alt[0]._bit and alt[0]._excl:
                # generate all the possible values and remove the excluded one(s)
                vals = list(map(lambda x: '{0:0>{1}}'.format(bin(x)[2:], alt[0]._bit),
                                range(0, (2<<(alt[0]._bit-1)))))
                for val in alt[0]._excl._val:
                    assert( val in vals )
                    vals.remove(val)
                # and associate all of them to the rest of the objects' list
                rest = alt[1:]
                for val in vals:
                    selec.append( (val, (pythonize_name(alt[0]._name), rest)) )
                    has_null.append( False )
            else:
                # this means that we have a null to exit the structure as 
                # the only other alternative
                selec.append( ('', ('', alt)) )
                req_null.append( True )
        #
        elif isinstance(alt, CSN1Obj) and alt._list \
        and alt._num == 1 and alt._lref is None:
            # list object
            if alt._list[0]._name:
                alt_name = alt._list[0]._name
            elif alt._name:
                alt_name = alt._name
            else:
                alt_name = ''
            if isinstance(alt._list[0], CSN1Val):
                if len(alt._list[0]._val) > 1:
                    # multiple values
                    # associate all of them with the rest of the objects' list
                    rest = alt._list[1:]
                    for val in alt._list[0]._val:
                        if val[-2:] == '**':
                            raise(CSN1Err('unsupported alternative key, %s' % val))
                        selec.append( (val, (pythonize_name(alt_name), rest)) )
                        has_null.append( False )
                else:
                    if alt._list[0]._val[0][-2:] == '**':
                        raise(CSN1Err('unsupported alternative key, %s' %  alt._list[0]._val[0]))
                    selec.append( (alt._list[0]._val[0], (pythonize_name(alt_name), alt._list[1:])) )
                    has_null.append( False )
            elif alt._list[0]._bit and alt._list[0]._excl:
                # generate all the possible values and remove the excluded one(s)
                vals = list(map(lambda x: '{0:0>{1}}'.format(bin(x)[2:], alt._list[0]._bit),
                                range(0, (2<<(alt._list[0]._bit-1)))))
                for val in alt._list[0]._excl._val:
                    assert( val in vals )
                    vals.remove(val)
                # and associate all of them to the rest of the objects' list
                rest = alt._list[1:]
                for val in vals:
                    selec.append( (val, (pythonize_name(alt_name), rest)) )
                    has_null.append( False )
            else:
                # this means that we have a null to exit the structure as 
                # the only other alternative
                selec.append( ('', ('', alt)) )
                req_null.append( True )
        #
        else:
            assert()
    #
    # ensure everything is solvable
    if not req_null:
        # OK, every alternative starts with a value or is null
        d = _build_dict_from_alt(selec)
    elif len(req_null) == 1:
        # one alternative starts with an undetermined value
        if has_null != [True]:
            # the only possible other alternative is a single null field
            raise(CSN1Err('an alternative starts with undetermined value'))
        else:
            # OK
            d = _build_dict_from_alt(selec)
    else:
        # several alternatives starts with an undetermined value
        raise(CSN1Err('mutliple alternatives start with undetermined values'))
    #
    if any(has_null):
        d[None] = ('', [])
    return d


def _build_dict_from_alt(selec):
    d = {}
    for (k, l) in selec:
        # get the list of keys, enventually truncated to the length of k
        if d and not all([_check_keys(k, key) for key in d.keys() if len(key) > 0]):
            raise(CSN1Err('multiple alternatives start with the same value, {0!r}'\
                  .format(k)))
        d[k] = l
    return d


def _check_keys(k1, k2):
    # ensure two CSN1Alt keys are not colliding
    if k1 == k2[:len(k1)] or k1[:len(k2)] == k2:
        return False
    else:
        return True

