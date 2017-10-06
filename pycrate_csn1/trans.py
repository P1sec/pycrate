# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.2
# *
# * Copyright © 2017. Benoit Michau. ANSSI.
# *
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# * 
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# * 
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# * 02110-1301, USA.
# *
# *--------------------------------------------------------
# * File Name : pycrate_csn1/trans.py
# * Created : 2017-06-12
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils import *
from .utils import _RE_NAME

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
        - num : int, number of repetition for the object
            default is 1, it can be >= 0
            or == -1, in this case, there is an undefined number of repetition 
        - lref: int, backward reference to a field into the parent object which 
            has to be a list, enforces the length in bit during decoding 
        - ref : set of str, list all reference to external CSN.1 objects
        
        In case the CSN.1 object is a bit-field:
        - bit : int, number of bits in case the object is a bit-field
        - excl: None or CSN1Val, list of excluded values for a bit-field object
        
        In case the CSN.1 object is a list of objects:
        - list: list, list of contained objects
        
        In case the CSN.1 object is a list of alternatives:
        - alt : list, list of alternative list of contained objects
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
        # this potentially optimize the 1st level of content (in _list or _alt)
        # and eventually returns a new simpler object
        if hasattr(self, '_alt') and self._alt is not None and \
        hasattr(self, '_ref') and not self._ref and \
        self._num == 1 and self._lref is None and \
        all([isinstance(Obj, CSN1Val) for Obj in self._alt]):
            # if this is an alternative between multiple values
            # we convert it to a CSN1Val with the list of given values
            New = CSN1Val(name=self._name)
            for alt in self._alt:
                New._val.extend( alt._val )
            return New
        #
        elif hasattr(self, '_list') and self._list is not None and \
        len(self._list) == 1:
            # if this is a list of a single object
            # we return this single object
            # WNG: this could assert in some extrem cases
            New = self._list[0]
            if self._num != 1:
                assert( New._num == 1 )
                New._num = self._num
            if self._lref is not None:
                assert( New._lref is None )
                New._lref = self._lref
            
            if self._name and not isinstance(New, CSN1Ref):
                New._name = self._name
            return New
        #
        elif isinstance(self, CSN1Ref) and self._name == 'null' and \
        self._num == 1 and self._lref is None:
            # if this is a ref to null
            # we convert it to a CSN1Val with a single null value
            New = CSN1Val(name=self._name)
            New._val = ['null']
            return New
        
        else:
            return self
    
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
        if EOT is None and text:
            return True
        elif EOT and text[0:1] not in EOT:
            return True
        else:
            return False
    
    def parse_def(self, text, EOT=None):
        """
        parses the text corresponding to the CSN.1 object definition
        
        object definition can be:
        - a bit definition, e.g. bit (10)
        - a reference to another object, e.g. < OtherObject >
        - an inlined object definition, e.g. < OtherObject: bit(10) >
        - a list of alternatives, e.g.
          { 00 | 11 | 01 < Object-1 > | 10 < Object-2 > }
        """
        self._text_def = text
        while self.__continue(text, EOT):
            if text[0:3] == 'bit':
                # inlined definition
                assert( self._list is None and self._alt is None )
                text = self._parse_bit(text)
            elif text and text[0:1] in '01LHn':
                # fixed anonymous value
                assert( self._bit is None )
                if self._list is None:
                    self._list = []
                text = self._parse_anon_val(text)
            elif text[0:1] == '<':
                # internal object or value
                assert( self._bit is None )
                if self._list is None:
                    self._list = []
                text = self._parse_obj(text[1:].lstrip())
            elif text[0:1] == '{':
                # precedence token, subgroup handled as an anonymous object
                assert( self._bit is None )
                if self._list is None:
                    self._list = []
                text = self._parse_grp(text[1:].lstrip())
            elif text[0:1] == '|':
                # alternative (list of) object(s)
                assert( self._bit is None and self._list is not None )
                # put the previous list of object as a potential alternative
                if self._alt is None:
                    self._alt = []
                self.__insert_alt()
                text = text[1:].lstrip()
            else:
                m = re.match(_RE_NAME, text)
                if m:
                    # simple reference
                    assert( self._bit is None and self._list is None and self._alt is None )
                    Ref = CSN1Ref(m.group())
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
                # in case self is an alternative object outside of any subgroup 
                # construction, we need to transfer the last list within alt
                self.__insert_alt()
        return text
    
    def __insert_list(self, Obj):
        assert( self._list is not None )
        # optimization to flatten nested anonymous list
        self._list.append( Obj )
        #
        if isinstance(Obj, CSN1Val):
            pass
        elif isinstance(Obj, CSN1Ref):
            self._ref.add(Obj._name)
        else:
            self._ref.update( Obj._ref )
    
    def __insert_alt(self):
        assert( self._list )
        # optimization to remove unneeded wrapping list of length 1
        #self._alt.append( self._list )
        if len(self._list) == 1:
            # if this is a list of a single object
            # we keep only this single object
            self._alt.append( self._list[0] )
        else:
            self._alt.append( self._list )
        self._list = None
    
    def _parse_bit(self, text):
        """
        parses the text corresponding to a bit definition, e.g. "bit (10)"
        """
        text = text[3:].lstrip()
        if text and text[0:1] in '(*':
            self._bit, text = CSN1Obj._parse_repet(text)
        else:
            self._bit = 1
        return text
    
    def _parse_anon_val(self, text):
        """
        parses the text corresponding to an anonymous value, e.g. "010"
        """
        m = SYNT_RE_VALUE.match(text)
        if not m:
            raise(CSN1Err('{0}: invalid value definition, {1}'\
                  .format(self._name, text)))
        text_val = re.sub('\s', '', m.group())
        text = text[m.end():].lstrip()
        self.__insert_list( CSN1Val('', text_val) )
        return text
    
    def _parse_obj(self, text):
        """
        parses the text corresponding to the definition of another object, 
        e.g. < AnotherObject ... >
        """
        m = re.match(_RE_NAME, text)
        if not m:
            raise(CSN1Err('{0}: invalid object name, {1}'\
                  .format(self._name, text)))
        name = m.group().strip()
        text = text[m.end():].lstrip()
        if name == 'bit':
            # special <bit (val(OtherField)) & {<Some struct of length $OtherField>}>
            m = SYNT_RE_LENREF.match(text)
            if not m:
                raise(CSN1Err('{0}: invalid object length reference construction, {1}'\
                      .format(self._name, text)))
            lref = m.group(1)
            # lef must be a local ref, which must be resolve in a backward offset
            for i in range(-1, -len(self._list)-1, -1):
                if self._list[i]._name == lref:
                    # we got it
                    lref = i
                    break
            if not isinstance(lref, integer_types):
                raise(CSN1Err('{0}: unable to resolve length reference, {1}'\
                      .format(self._name, lref)))
            text = text[m.end():].lstrip()
            Obj = CSN1Obj('')
            text = Obj.parse_def(text, EOT='>')
            text = text[1:].lstrip()
            Obj._lref = lref
            Obj = Obj.reduce()
            self.__insert_list(Obj)
        else:
            if text[0:1] == ':':
                # inlined CSN.1 object bit definition
                Obj = CSN1Obj(name)
                text = Obj.parse_def(text[1:].lstrip(), EOT='>')
                text = text[1:].lstrip()
                if text[0:7] == 'exclude':
                    excl, text = CSN1Obj._parse_excl(text[7:].lstrip())
                    assert( Obj._bit is not None )
                    for val in excl._val:
                        assert( len(val) == Obj._bit )
                    Obj._excl = excl
                Obj = Obj.reduce()
                self.__insert_list(Obj)
            elif text[0:1] == '>':
                # new ref to another object
                Obj = CSN1Ref(name)
                Obj = Obj.reduce()
                self.__insert_list( Obj )
                text = text[1:].lstrip()
            else:
                raise(CSN1Err('{0}: invalid internal object definition, {1}'\
                      .format(self._name, text)))
            #
            if text and text[0:1] in '(*':
                Obj._num, text = CSN1Obj._parse_repet(text)
        #
        return text
    
    def _parse_grp(self, text):
        """
        parses the text corresponding to the definition of an embedded object
        up to the terminating }
        """
        Obj = CSN1Obj('')
        text = Obj.parse_def(text, EOT='}')
        text = text[1:].lstrip()
        # in case this is an alternative, transfer the last list to alt
        if Obj._alt is not None:
            Obj.__insert_alt()
        if text and text[0:1] in '(*':
            Obj._num, text = CSN1Obj._parse_repet(text)
        Obj = Obj.reduce()
        self.__insert_list( Obj )
        return text
    
    @classmethod
    def _parse_repet(void, text):
        m = SYNT_RE_REPET.match(text)
        if not m:
            raise(CSN1Err('CSN1Obj._parse_repet: invalid repetition definition, {0}'\
                  .format(text)))
        if m.group(1) or m.group(3):
            # defined number of repetition
            return int(m.group(1)) if m.group(1) else int(m.group(3)), text[m.end():].lstrip()
        else:
            # infinite number of repetition
            return -1, text[m.end():].lstrip()
    
    @classmethod
    def _parse_excl(void, text):
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
    def __init__(self, name):
        self._name = name
        self._num  = 1
        self._lref = None
    
    def __repr__(self):
        return 'CSN1Ref(%s)' % self._name


class CSN1Val(CSN1Obj):
    """Class to handle CSN.1 value, as used within choice
    """
    def __init__(self, name='', text=''):
        self._name = name
        self._val  = []
        self._num  = 1
        self._lref = None 
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
                text_val += '*'
            else:
                text_val = num*text_val
        self._val.append( text_val )


#------------------------------------------------------------------------------#
# CSN.1 predefined objects
#------------------------------------------------------------------------------#

spare_bit = CSN1Obj('spare bit')
spare_bit._bit = 1

spare_bits = CSN1Obj('spare bits')
spare_bits._bit = 1
spare_bits._num = -1


def get_predefined_objects():
    """Returns a dict with the following predefined objects:
    <spare bit>
    <Spare bit>
    <Spare Bit>
    <spare bits>
    <Spare bits>
    <Spare Bits>
    """
    return {'spare_bit' : spare_bit,
            'Spare_bit' : spare_bit,
            'Spare_Bit' : spare_bit,
            'spare_bits': spare_bits,
            'Spare_bits': spare_bits,
            'Spare_Bits': spare_bits}

def gen_predefined_objects():
    return \
'''
spare_bit = CSN1Bit(name='spare_bit')
Spare_bit = spare_bit
Spare_Bit = spare_bit
spare_bits = CSN1Bit(name='spare_bits', num=-1)
Spare_bits = spare_bits
Spare_Bits = spare_bits

'''

#------------------------------------------------------------------------------#
# CSN.1 definition translator
#------------------------------------------------------------------------------#

global obj_name

def translate_text(text=u'', **kwargs):
    """Scans a text (or list of texts) for CSN.1 object definitions
    
    translate them and return prototype Python definitions, to be used with
    the CSN.1 runtime
    """
    if isinstance(text, (list, tuple)):
        text = u'\n\n'.join(text)
    elif not isinstance(text, str_types):
        raise(CSN1Err('[proc] need some textual definition'))
    text = clean_text(text)
    Objs, ret = {}, []
    global obj_name
    #
    # 0) add predifined objects
    predefs = get_predefined_objects()
    predefs_name = list(predefs.keys())
    #
    # 1) process definition until the end of the text
    while text:
        text = process_definition(text, Objs, **kwargs)
    #
    # 2) resolve reference ordering
    Olist = list(Objs.keys())
    while Olist:
        Olen = len(Olist)
        for pyname in Olist[:]:
            Obj = Objs[pyname]
            if isinstance(Obj, CSN1Val) or not Obj._ref:
                # object without dependency
                obj_name  = pyname
                Obj._root = True
                ret.append( '%s = %s\n' % (pyname, translate_object(Obj)) )
                Olist.remove( pythonize_name(Obj._name) )
            else:
                if all([pythonize_name(dep) not in Olist or \
                        pythonize_name(dep) == pyname or \
                        pythonize_name(dep) in predefs_name \
                        for dep in Obj._ref]): 
                    # object with all dependencies already defined
                    obj_name  = pyname
                    Obj._root = True
                    ret.append( '%s = %s\n' % (pyname, translate_object(Obj)) )
                    Olist.remove( pythonize_name(Obj._name) )
        # ensure we keep defining objects
        if len(Olist) == Olen:
            log('WNG: unable to define objects, %r' % Olist)
            break
    #
    # 3) return python source
    return Objs, '# code automatically generated by pycrate_csn1\n' + \
                 '# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT)\n' + \
                 '# add dict for value interpretation with dict={...}\n\n' + \
                 'from pycrate_csn1.csnobj import *\n' + \
                 gen_predefined_objects() + \
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
    Objs[pyname] = Obj.reduce()
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


def translate_ref(Obj):
    global obj_name
    name, args = pythonize_name(Obj._name), []
    if name == obj_name:
        # self reference
        cla  = 'CSN1SelfRef'
    else:
        cla  = 'CSN1Ref'
        args.append( 'obj=%s' % name )
    if hasattr(Obj, '_root') and Obj._root:
        args.append( 'root=True' )
    if Obj._num != 1:
        args.append( 'num=%s' % Obj._num )
    if Obj._lref is not None:
        args.append( 'lref=%s' % Obj._lref )
    return '%s(%s)' % (cla, ', '.join(args))


def translate_val(Obj):
    # no need to set 'root=True' for CSN1Val
    if len(Obj._val) == 1:
        return 'CSN1Val(name=%r, val=%r)' % (pythonize_name(Obj._name), Obj._val[0])
    else:
        # convert to a list of alternatives
        Alt = CSN1Obj(name=Obj._name)
        Alt._alt = [CSN1Val('', v) for v in Obj._val]
        return translate_alt(Alt)


def translate_bit(Obj):
    args = []
    if Obj._name:
        args.append( 'name=%r' % pythonize_name(Obj._name) )
    if hasattr(Obj, '_root') and Obj._root:
        args.append( 'root=True' )
    if Obj._bit != 1:
        args.append( 'bit=%s' % Obj._bit )
    if Obj._num != 1:
        args.append( 'num=%s' % Obj._num )
    if Obj._lref is not None:
        args.append( 'lref=%s' % Obj._lref )
    if Obj._excl is not None:
        # we only keep raw bit-strings 
        args.append( 'excl=%r' % Obj._excl._val )
    return 'CSN1Bit(%s)' % ', '.join(args)


def translate_list(Obj):
    # translate each list internal object on a new line
    args = []
    if Obj._name:
        args.append( 'name=%r' % pythonize_name(Obj._name) )
    if hasattr(Obj, '_root') and Obj._root:
        args.append( 'root=True' )
    if Obj._num != 1:
        args.append( 'num=%s' % Obj._num )
    if Obj._lref is not None:
        args.append( 'lref=%s' % Obj._lref )
    if Obj._list:
        args.append( 'list=' + _translate_objlist(Obj._list) )
    return 'CSN1List(%s)' % ', '.join(args)


def translate_alt(Obj):
    selec, klen = build_alt_selector(Obj)
    args = []
    if Obj._name:
        args.append( 'name=%r' % pythonize_name(Obj._name) )
    if hasattr(Obj, '_root') and Obj._root:
        args.append( 'root=True' )
    if Obj._num != 1:
        args.append( 'num=%s' % Obj._num )
    if Obj._lref is not None:
        args.append( 'lref=%s' % Obj._lref )
    if klen != 1:
        args.append( 'klen=%s' % klen )
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
                        selec.append( (None, (alt._name, [])) )
                        has_null.append( True )
                    else:
                        selec.append( (val, (alt._name, [])) )
                        has_null.append( False )
            else:
                if alt._val[0] == 'null':
                    # no more bit to consume, exiting the structure
                    selec.append( (None, (alt._name, [])) )
                    has_null.append(True)
                else:
                    # potential alternative
                    selec.append( (alt._val[0], (alt._name, [])) )
                    has_null.append( False )
        #
        elif isinstance(alt, CSN1Ref):
            selec.append( ('', (alt._name, [alt])) )
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
                        selec.append( (val, (pythonize_name(alt[0]._name), rest)) )
                        has_null.append( False )
                else:
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
                        selec.append( (val, (pythonize_name(alt_name), rest)) )
                        has_null.append( False )
                else:
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
        return _build_dict_from_alt(selec)
    elif len(req_null) == 1:
        # one alternative starts with an undetermined value
        if has_null != [True]:
            # the only possible other alternative is a single null field
            raise(CSN1Err('an alternative starts with undetermined value'))
        else:
            # OK
            return _build_dict_from_alt(selec)
    else:
        # several alternatives starts with an undetermined value
        raise(CSN1Err('mutliple alternatives start with undetermined values'))


def _build_dict_from_alt(selec):
    d, klen = {}, -1
    for (k, l) in selec:
        if k in d:
            raise(CSN1Err('multiple alternatives start with the same value, {0!r}'\
                  .format(k)))
        if k in ('', None):
            pass
        else:
            if klen >= 0 and klen != len(k):
                raise(CSN1Err('different alternatives with non-uniform start value'))
            else:
                klen = len(k)
        d[k] = l
    if klen == -1:
        klen = 0
    return d, klen

