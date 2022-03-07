# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2016. Benoit Michau. ANSSI.
# * Copyright 2019. Benoit Michau. P1Sec.
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
# * File Name : pycrate_core/elt.py
# * Created : 2016-02-20
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = ['EltErr', 'REPR_RAW', 'REPR_HEX', 'REPR_BIN', 'REPR_HD', 'REPR_HUM',
           'Element', 'Atom', 'Envelope', 'Array', 'Sequence', 'Alt']


from binascii import hexlify

try:
    from json import JSONEncoder, JSONDecoder
except ImportError:
    _with_json = False
else:
    _with_json = True
    JsonEnc = JSONEncoder(sort_keys=True, indent=1)
    JsonDec = JSONDecoder()
    try:
        import JSONDecodeError
    except ImportError:
        # it seems Python2.7 removed support for JSONDecodeError at some point
        JSONDecodeError = ValueError

from .utils  import *
from .charpy import Charpy, CharpyErr


#------------------------------------------------------------------------------#
# Elt specific error
#------------------------------------------------------------------------------#

class EltErr(PycrateErr):
    pass


#------------------------------------------------------------------------------#
# global values for Element representation
#------------------------------------------------------------------------------#

REPR_RAW = 0
REPR_HEX = 1
REPR_BIN = 2
REPR_HD  = 3
REPR_HUM = 4


# for hexdump representation
if python_version < 3:
    def hview(buf, lw=16):
        hv = []
        for o in range(0, len(buf), lw):
            l = buf[o:o+lw]
            # create the hex fmt string for each iteration
            hs = '%.2x ' * len(l) % tuple(map(ord, l))
            hv.append( ' ' + hs + ' '*(3*lw-len(hs)) + '| %r' % l )
        return hv
else:
    def hview(buf, lw=16):
        hv = []
        for o in range(0, len(buf), lw):
            l = buf[o:o+lw]
            # create the hex fmt string for each iteration
            hs = '%.2x ' * len(l) % tuple(l)
            hv.append( ' ' + hs + ' '*(3*lw-len(hs)) + '| %r' % l )
        return hv

#------------------------------------------------------------------------------#
# Element parent class
#------------------------------------------------------------------------------#

### class attributes to be inherited from Element:
    #_SAFE_STAT
    #_SAFE_DYN
### methods to be inherited from Element
    #_log()
    ## envelope, hierarchy, selection routines
    #set_env()
    #get_env()
    #get_next()
    #get_prev()
    #set_hier()
    #inc_hier()
    #dec_hier()
    #get_hier()
    #get_hier_abs()
    #get_header()
    #get_payload()
    ## format routines
    #get_len()
    #set_trans()
    #set_transauto()
    #get_trans()
    ## conversion routines
    #from_bytes()
    #to_bytes()
    #__str__() (py2) / __bytes__() (py3)
    #from_uint()
    #to_uint()
    #from_int()
    #to_int()
    ## representation routines
    #bin()
    #__bin__()
    #hex()
    #__hex__()


class Element(object):
    """
    Parent class for all atomic (Atom and children from base.py) 
    and composite (Envelope, Array, Sequence, Alt) elements
    """
    
    # safety checks against user-provided data
    # when setting static values
    _SAFE_STAT = True
    # when computing automatic values
    _SAFE_DYN = True
    
    # next / prev / header / payload element selection within an envelope
    # select or not transparent element
    ENV_SEL_TRANS = True
    
    # hardcoded class name
    CLASS = 'Element'
    
    # default transparency
    DEFAULT_TRANS = False
    
    # default attributes value
    _env        = None
    _hier       = 0
    _trans      = None
    _transauto  = None
    
    
    def _log(self, msg=''):
        log('[%s] %s' % self._name, msg)
    
    
    #--------------------------------------------------------------------------#
    # envelope, hierarchy and selection routines
    #--------------------------------------------------------------------------#
    
    def set_env(self, env):
        """Set the envelope around self
        
        Args:
            env (element) : direct envelope of the element
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT enabled and env is not a valid envelope
        """
        if env is None:
            try:
                del self._env
            except Exception:
                pass
        else:
            if self._SAFE_STAT and not isinstance(env, (Envelope,
                                                        Array,
                                                        Sequence,
                                                        Alt)):
                    raise(EltErr('{0} [set_env]: env type is {1}, expecting None, '\
                          'Envelope, Sequence, Array or Alt'\
                          .format(self._name, type(self._env).__name__)))
            self._env = env
    
    def get_env(self):
        """Returns the envelope around self
        
        Args:
            None
        
        Returns:
            env (element) : first envelope around element or None
        """
        return self._env
    
    def get_next(self, val=1):
        """Returns the next element in the envelope around self
        
        Args:
            val (int) : number of elements to go to after self
        
        Returns:
            next (element) : next element selected within the envelope
        
        Raises:
            EltErr : if self._SAFE_STAT enabled and val overflows the number of 
                elements within the envelope
        """
        if self._env is None:
            return None
        
        # get index of self within its envelope
        try:
            ind = self._env.index(self)
        except Exception:
            return None
        try:
            if self.ENV_SEL_TRANS:
                return self._env[ind+val]
            else:
                # do not count transparent element within the envelope
                i = 1
                while i <= val:
                    if not self._env[ind+i].get_trans():
                        i += 1
                return self._env[ind+i]
        except EltErr:
            #raise(EltErr('{0} [get_next]: invalid index {1} within envelope {2}'\
            #      .format(self._name, ind+val, self._env._name)))
            return None
    
    def get_prev(self, val=1):
        """Returns the previous element in the envelope around self
        
        Args:
            val (int) : number of elements to go to before self
        
        Returns:
            next (element) : previous element selected within the envelope
        
        Raises:
            EltErr : if self._SAFE_STAT enabled and val overflows the number of 
                elements within the envelope
        """
        if self._env is None:
            return None
        
        # get index of self within its envelope
        try:
            ind = self._env.index(self)
        except Exception:
            return None
        if ind-val < 0:
            return None
        try:
            if self.ENV_SEL_TRANS:
                return self._env[ind-val]
            else:
                # do not count transparent element within the envelope
                i = 1
                while i <= val:
                    if not self._env[ind-i].get_trans():
                        i += 1
                return self._env[ind-i]
        except EltErr:
            #raise(EltErr('{0} [get_prev]: invalid index {1} within envelope {2}'\
            #      .format(self._name, ind-val, self._env._name)))
            return None
    
    def set_hier(self, hier):
        """Set the hierarchical level of self, relative to the one of the 
        envelope around it if exists, absolute otherwise
        
        Args:
            hier (int) : hierarchical level of the element 
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT enabled and hier is not an unsigned 
                integer
        """
        if self._SAFE_STAT:
            self._chk_hier(hier)
        self._hier = hier
    
    def _chk_hier(self, *args):
        if args:
            hier = args[0]
        else:
            hier = self._hier
        if not isinstance(hier, integer_types):
            raise(EltErr('{0} [_chk_hier]: hier type is {1}, expecting integer'\
                  .format(self._name, type(self._hier).__name__)))
        elif hier < 0:
            raise(EltErr('{0} [_chk_hier]: hier value is {1}, expecting unsigned value'\
                  .format(self._name, self._hier)))
    
    def inc_hier(self, hier=1):
        """Increment the hierarchical level of self, relative to the one of the 
        envelope if exists, absolute otherwise
        
        Args:
            hier (int) : value to add to the hierarchical level
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT enabled and resulting hier is not an 
                unsigned integer
        """
        if self._SAFE_STAT:
            self._chk_hier(self._hier + hier)
        self._hier += hier
    
    def dec_hier(self, hier=1):
        """Decrement the hierarchical level of self, relative to the one of the 
        envelope if exists, absolute otherwise
        
        Args:
            hier (int) : value to substract to the hierarchical level
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT enabled and resulting hier is not an 
                unsigned integer
        """
        if self._SAFE_STAT:
            self._chk_hier(self._hier - hier)
        self._hier -= hier
    
    def get_hier(self):
        """Returns the hierarchical level of self within its envelope if exists,
        absolute otherwise
        
        Args:
            None
        
        Returns:
            hier (int) : hierarchical level of self, unsigned
        """
        return self._hier
    
    def get_hier_abs(self):
        """Returns the absolute hierarchical level of self
        
        Args:
            None
        
        Returns:
            hier (int) : hierarchical level of the element, including
                the hierarchy of all envelopes around it
        """
        hier = self._hier
        env  = self._env
        while env is not None:
            hier += env._hier
            env   = env._env
        return hier
    
    def get_header(self):
        """Returns the header of self, according to their hierarchical level.
        The header is the 1st element before self with a lower hierarchy
        
        Args:
            None
        
        Returns:
            hdr (element) : header of self,
                or None if no header is found
        """
        # go over all order of envelopes if necessary to find the 1st element
        # with a lower hierarchical level than the element's one
        elt  = self
        hier = self._hier
        env  = self._env
        #
        if self.ENV_SEL_TRANS:
            while env is not None:
                try:
                    ind = env.index(elt)
                except Exception:
                    return None
                for elt in env[ind-1::-1]:
                    if elt._hier < hier:
                        return elt
                elt  = env
                hier = elt._hier
                env  = elt._env
        else:
            while env is not None:
                try:
                    ind = env.index(elt)
                except Exception:
                    return None
                for elt in env[ind-1::-1]:
                    if not elt.get_trans() and elt._hier < hier:
                        return elt
                elt  = env
                hier = elt._hier
                env  = elt._env
        #
        return None
    
    def get_payload(self):
        """Returns a (sliced) envelope with all the payload elements of self,
        according to their hierarchical level.
        The payload is the list of all elements after self with a higher
        hierarchy, without an element with a lower hierarchy than self in 
        between
        
        Args:
            None
        
        Returns:
            pay (element) : envelope with all payload elements of self,
                or None if no payload is found
        """
        # go over all order of envelopes if necessary to find the 1st element
        # with a higher hierarchical level than the element's one
        elt  = self
        hier = self._hier
        env  = self._env
        #
        if self.ENV_SEL_TRANS:
            while env is not None:
                try:
                    ind_start = env.index(elt)
                except Exception:
                    return None
                ind = 1+ind_start
                ind_pay = [None, None]
                for elt in env[1+ind_start:]:
                    # get the window of indexes corresponding to 
                    # the full payload
                    if elt._hier > hier and ind_pay[0] is None:
                        ind_pay[0] = ind
                    elif elt._hier < hier and ind_pay[0] is not None:
                        ind_pay[1] = ind
                        return env[ind_pay[0]:ind_pay[1]]
                    ind += 1
                if ind_pay[0] is not None:
                    return env[ind_pay[0]:]
                else:
                    elt  = env
                    hier = elt._hier
                    env  = elt._env
        else:
            while env is not None:
                try:
                    ind_start = env.index(elt)
                except Exception:
                    return None
                ind = 1+ind_start
                ind_pay = [None, None]
                for elt in env[1+ind_start:]:
                    # get the window of indexes corresponding to 
                    # the full payload, jumping over transparent element
                    if not elt.get_trans():
                        if elt._hier > hier and ind_pay[0] is None:
                            ind_pay[0] = ind
                        elif elt._hier < hier and ind_pay[0] is not None:
                            ind_pay[1] = ind
                            return env[ind_pay[0]:ind_pay[1]]
                    ind += 1
                if ind_pay[0] is not None:
                    return env[ind_pay[0]:]
                else: 
                    elt  = env
                    hier = elt._hier
                    env  = elt._env
        #
        return None
    
    
    #--------------------------------------------------------------------------#
    # format routines
    #--------------------------------------------------------------------------#
    
    def get_len(self):
        """Returns the length in bytes of self
        
        Args:
            None
        
        Returns:
            bytelen (int) : length in bytes computed
        """
        bl = self.get_bl()
        if bl%8:
            return 1 + bl>>3
        else:
            return bl>>3
    
    def set_trans(self, trans=None):
        """Set the raw transparency of self
        
        Args:
            trans (bool) : raw transparency, default to None
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and trans is not bool
        """
        if trans is None:
            try:
                del self._trans
            except Exception:
                pass
        else:
            if self._SAFE_STAT:
                self._chk_trans(trans)
            self._trans = trans
   
    def _chk_trans(self, *args):
        if args:
            trans = args[0]
        else:
            trans = self._trans
        if not isinstance(trans, (NoneType, bool)):
            raise(EltErr('{0} [_chk_trans]: trans type is {1}, expecting bool'\
                  .format(self._name, type(trans).__name__)))
    
    def set_transauto(self, transauto=None):
        """Set the transparency automation of self
        
        Args:
            transauto (callable) : automate the transparency computation,
                call transauto() to compute trans, default to None
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and transauto is not
                callable
        """
        if transauto is None:
            try:
                del self._transauto
            except Exception:
                pass
        else:
            if self._SAFE_STAT and not callable(transauto):
                raise(EltErr('{0} [set_transauto]: transauto type is {1}, expecting callable'\
                      .format(self._name, type(transauto).__name__)))
            self._transauto = transauto
    
    def get_trans(self):
        """Returns the transparency of self
        
        Args:
            None
        
        Returns:
            trans (bool) : transparency computed, 
                default to class attribute DEFAULT_TRANS
        
        Raises:
            EltErr : if self._SAFE_DYN is enabled and the value produced 
                dynamically is not bool 
        """
        # follow the value resolution order:
        # 1) raw trans
        if self._trans is not None:
            return self._trans
        
        # 2) trans automation
        elif self._transauto is not None:
            trans = self._transauto()
            if self._SAFE_DYN:
                self._chk_trans(trans)
            return trans
        #
        # 3) default transparency
        else:
            return self.DEFAULT_TRANS
    
    def reautomate(self):
        """Reset all attributes of the element which have an automation
        
        Args:
            None
        
        Returns:
            None
        """
        if self._transauto is not None and self._trans is not None:
            del self._trans
    
    #--------------------------------------------------------------------------#
    # conversion routines
    #--------------------------------------------------------------------------#
    
    def from_bytes(self, char):
        """Consume a bytes buffer or Charpy instance `char' and sets the 
        internal value according to it
        
        Args:
            char (bytes or charpy): bytes buffer or charpy instance to be
                consumed
        
        Returns:
            None
        
        Raises:
            EltErr : if `char' has not the correct type
            CharpyErr
        """.format(self.__class__.__name__)
        if isinstance(char, bytes_types):
            char = Charpy(char)
        elif self._SAFE_STAT and not isinstance(char, Charpy):
            raise(EltErr('{0} [from_bytes]: char type is {1}, expecting Charpy'\
                         .format(self._name, type(char).__name__)))
        #
        self._from_char(char)
    
    def to_bytes(self):
        """Produce a bytes buffer from the internal value
        
        Args:
            None
        
        Returns:
            char (bytes) : resulting bytes buffer
        """.format(self.__class__.__name__)
        return pack_val(*self._to_pack())[0]
    
    def from_uint(self, uint, bl=None):
        """Consume an unsigned integer or Charpy instance `uint' and sets the 
        internal value according to it
        
        Args:
            uint (int or charpy): unsigned integer or Charpy instance to be 
                consumed
            bl: length in bits for `uint', if None, the minimum number of 
                bits is used
        
        Returns:
            None
        
        Raises:
            EltErr : if `uint' has not the correct type
            CharpyErr
        """
        if isinstance(uint, integer_types):
            char = Charpy()
            char.set_uint(uint, bl)
            uint = char
        elif self._SAFE_STAT and not isinstance(uint, Charpy):
            raise(EltErr('{0} [from_uint]: uint type is {1}, expecting Charpy'\
                  .format(self._name, type(uint).__name__)))
        #
        self._from_char(uint)
    
    def to_uint(self):
        """Produce an unsigned integer from the internal value
        
        Args:
            None
        
        Returns:
            uint (int) : unsigned integer
        """
        try:
            return bytes_to_uint(self.to_bytes(), self.get_bl())
        except PycrateErr:
            # an invalid value has been set, _SAFE_STAT / DYN is probably disabled
            # for e.g. fuzzing purpose, but there is still need to not break here
            b = self.to_bytes()
            return bytes_to_uint(b, len(b)<<3)
    
    def from_int(self, integ, bl=None):
        """Consume a signed integer or charpy instance `integ' and sets the 
        internal value according to it
        
        Args:
            integ (int or charpy): signed integer or Charpy instance to be 
                consumed
            bl: length in bits for `integ', if None, the minimum number of 
                bits is used
        
        Returns:
            None
        
        Raises:
            EltErr : if `integ' has not the correct type
            CharpyErr
        """
        if isinstance(uint, integer_types):
            char = Charpy()
            char.set_int(integ, bl)
            integ = char
        elif self._SAFE_STAT and not isinstance(integ, Charpy):
            raise(EltErr('{0} [from_int]: integ type is {1}, expecting Charpy'\
                  .format(self._name, type(integ).__name__)))
        #
        self._from_char(integ)
    
    def to_int(self):
        """Produce a signed integer from the internal value
        
        Args:
            None
        
        Returns:
            integ (int) : signed integer
        """
        try:
            return bytes_to_int(self.to_bytes(), self.get_bl())
        except PycrateErr:
            # an invalid value has been set, _SAFE_STAT / DYN is probably disabled
            # for e.g. fuzzing purpose, but there is still need to not break here
            b = self.to_bytes()
            return bytes_to_int(b, len(b)<<3)
    
    if python_version < 3:
        __str__ = to_bytes
    else:
        __bytes__ = to_bytes
    
    #--------------------------------------------------------------------------#
    # representation routines
    #--------------------------------------------------------------------------#
    
    def bin(self):
        bl = self.get_bl()
        if bl == 0:
            return ''
        else:
            bs = bytes_to_bitstr(self.to_bytes())
            if len(bs) > bl:
                return bs[:bl]
            else:
                return bs
    
    def hex(self):
        bl = self.get_bl()
        if bl == 0:
            return ''
        else:
            try:
                return uint_to_hex(bytes_to_uint(self.to_bytes(), bl), bl)
            except PycrateErr:
                # an invalid value has been set, _SAFE_STAT / DYN is probably disabled
                # for e.g. fuzzing purpose, but there is still need to not break here
                return hexlify(self.to_bytes()).decode('ascii')
    
    __bin__ = bin
    __hex__ = hex
    
    #--------------------------------------------------------------------------#
    # json api
    #--------------------------------------------------------------------------#
    
    if _with_json:
        
        def _from_jval(self, val):
            raise(EltErr('not impemented'))
        
        def _from_jval_wrap(self, val):
            try:
                val = val[self._name]
            except Exception:
                raise(EltErr('{0} [_from_jval]: invalid value, {1!r}'.format(self._name, val)))
            else:
                self._from_jval(val)
        
        def from_json(self, txt):
            if self.get_trans():
                return
            else:
                try:
                    val = JsonDec.decode(txt)
                except JSONDecodeError:
                    raise(EltErr('{0} [from_json]: invalid format, {1!r}'.format(self._name, txt)))
                else:
                    self._from_jval_wrap(val)
        
        def _to_jval(self):
            raise(EltErr('not implemented'))
        
        def _to_jval_wrap(self):
            return {self._name: self._to_jval()}
        
        def to_json(self):
            if self.get_trans():
                return ''
            else:
                return JsonEnc.encode(self._to_jval_wrap())


#------------------------------------------------------------------------------#
# Atom class, for base elements
#------------------------------------------------------------------------------#

class Atom(Element):
    """
    Parent class for all atomic elements 
    
    universal attributes:
    - name: str, custom one or class.__name__
    - desc: str, more descriptive text, used for representation
    - rep: int, type of representation (raw, hex, bin)
    - val: type depends on Element subclasses, raw value of the atom
    - bl: int, length of the atom in bits
    - trans: bool, transparency of the atom
    - dic: dict, for extended representation of the value
    - hier: hierarchical level when placed within an envelope
    
    automation attributes:
    - valauto: callable, to automate the production of the atom's raw value
    - blauto: callable, to automate the length in bits of the atom
    - transauto: callable, to automate the determination of element's transparency
    - dicauto: callable, to automate the production of element's dictionnary
    
    contextual attributes:
    - env: envelope, container of the atom
    """
    
    # hardcoded class name
    CLASS = 'Atom'
    
    # tuple of types accepted as input value and used as possible returned value
    # WNG: always ensure to flatten the list of types (e.g. when using 
    # bytes_types or integer_types)
    TYPES = flatten(NoneType, )
    TYPENAMES = get_typenames(*TYPES)
    
    # representation parameters
    # type of representation
    REPR_TYPES = (REPR_RAW, REPR_HEX, REPR_BIN, REPR_HD, REPR_HUM)
    # if > 0, object representation will be truncated at REPR_MAXLEN
    REPR_MAXLEN = 0
    
    # default value / bl / trans / dic
    DEFAULT_VAL     = None
    DEFAULT_BL      = 0
    DEFAULT_TRANS   = False
    DEFAULT_DIC     = {}
    
    # default attributes value
    _env        = None
    _hier       = 0
    _desc       = ''
    _rep        = REPR_RAW
    _bl         = None
    _blauto     = None
    _val        = None
    _valauto    = None
    _trans      = None
    _transauto  = None
    _dic        = None
    _dicauto    = None
    
    __attrs__ = ('_env',
                 '_name',
                 '_desc',
                 '_rep',
                 '_hier',
                 '_bl',
                 '_blauto',
                 '_val',
                 '_valauto',
                 '_trans',
                 '_transauto',
                 '_dic',
                 '_dicauto')
    
    def __init__(self, *args, **kw):
        """Initializes an instance of Atom
        
        Args:
            *args: nothing or atom name (str)
            **kw: 
                name (str): atom name if no args
                desc (str): additional atom description
                rep (int in cls.REPR_TYPES): atom representation type 
                hier (int): atom hierarchy level
                bl (int): atom length in bits
                val (see self.TYPES): atom value
                trans (bool): atom transparency
                dic (dict): atom dictionnary for friendly representation
        """
        # element name in kw, or first args
        if len(args):
            self._name = str(args[0])
        elif 'name' in kw:
            self._name = str(kw['name'])
        # if not provided, it's the class name
        elif not hasattr(self, '_name'):
            self._name = self.__class__.__name__
        
        # element description customization
        if 'desc' in kw:
            self._desc = str(kw['desc'])
        
        # element representation customization
        if 'rep' in kw and kw['rep'] in self.REPR_TYPES:
            self._rep = kw['rep']
        
        # element hierarchy
        if 'hier' in kw:
            self._hier = kw['hier']
        
        # element bit length
        if 'bl' in kw:
            self._bl = kw['bl']
        
        # element value
        if 'val' in kw:
            self._val = kw['val']
        
        # element transparency
        if 'trans' in kw:
            self._trans = kw['trans']
        
        # element dictionnary
        if 'dic' in kw:
            self._dic = kw['dic']
        
        if self._SAFE_STAT:
            self._chk_hier()
            self._chk_bl()
            self._chk_val()
            self._chk_trans()
            self._chk_dic()
    
    #--------------------------------------------------------------------------#
    # format routines
    #--------------------------------------------------------------------------#
    
    def set_val(self, val=None):
        """Set the raw value of self
        
        Args:
            val (see self.TYPES) : raw value, default to None
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT enabled and val does not have the 
                correct type
        """
        if val is None:
            try:
                del self._val
            except Exception:
                pass
        else:
            if self._SAFE_STAT:
                self._chk_val(val)
            self._val = val
    
    def _chk_val(self, *args):
        if args:
            val = args[0]
        else:
            val = self._val
        if not isinstance(val, self.TYPES + (NoneType,) ):
            raise(EltErr('{0} [_chk_val]: val type is {1}, expecting {2}'\
                  .format(self._name, type(val).__name__, self.TYPENAMES)))
    
    def set_valauto(self, valauto=None):
        """Set the value automation callable for self
        
        Args:
            valauto (callable) : automate the value computation,
                call valauto() to compute the value, default to None
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT enabled and valauto is not a callable
        """
        if valauto is None:
            try:
                del self._valauto
            except Exception:
                pass
        else:
            if self._SAFE_STAT and not callable(valauto):
                raise(EltErr('{0} [set_valauto]: valauto type is {1}, expecting callable'\
                      .format(self._name, type(valauto).__name__)))
            self._valauto = valauto
    
    def get_val(self):
        """Returns the value of self
        
        Args:
            None
        
        Returns:
            value (see self.TYPES) : value computed,
                default to class attribute DEFAULT_VAL
        
        Raises:
            EltErr : if self._SAFE_DYN is enabled and the value produced 
                dynamically has not the correct type
        """
        # follow the value resolution order:
        # 1) raw value
        if self._val is not None:
            return self._val
        
        # 2) value automation
        elif self._valauto is not None:
            val = self._valauto()
            if self._SAFE_DYN:
                self._chk_val(val)
            return val
        
        # 3) default value
        else:
            return self.DEFAULT_VAL
    
    # for atomic element, no dict to be returned, but just the standard value
    get_val_d = get_val
    
    def set_bl(self, bl=None):
        """Set the raw length in bits of self
        
        Args:
            bl (int) : raw bit length, default to None
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and bl is not integer
        """
        if bl is None:
            try:
                del self._bl
            except Exception:
                pass
        else:
            if self._SAFE_STAT:
                self._chk_bl(bl)
            self._bl = bl
    
    def _chk_bl(self, *args):
        if args:
            bl = args[0]
        else:
            bl = self._bl
        if not isinstance(bl, integer_types + (NoneType,)):
            raise(EltErr('{0} [_chk_bl]: bl type is {1}, expecting integer'\
                  .format(self._name, type(bl).__name__)))
    
    def set_blauto(self, blauto=None):
        """Set an automation for the length in bits of self, used only when 
        mapping an external buffer to it.
        If bl is None, self._get_bl_from_val() is used
        
        Args:
            blauto (callable) : automate the bl computation,
                call blauto() to compute the bit length, default to None
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and blauto is not a callable
        """
        if blauto is None:
            try:
                del self._blauto
            except Exception:
                pass
        else:
            if self._SAFE_STAT and not callable(blauto):
                raise(EltErr('{0} [set_blauto]: blauto type is {1}, expecting callable'\
                      .format(self._name, type(blauto).__name__)))
            self._blauto = blauto
    
    def set_len(self, l=None):
        """Set the raw length in bytes of self
        
        Args:
            l (int) : raw byte length, default to None
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and l is not integer
        """
        if l is None:
            try:
                del self._bl
            except Exception:
                pass
        else:
            if self._SAFE_STAT:
                # no need to multiply for this chk()
                self._chk_bl(l)
            self._bl = 8*l
    
    def _get_bl_from_val(self):
        # when bl is not defined at all, it is computed from the value set
        return 0
    
    def get_bl(self):
        """Returns the length in bits of self
        
        Args:
            None
        
        Returns:
            bl (int) : length in bits computed
                default to class attribute DEFAULT_BL
        """
        # follow the value resolution order:
        # 0) transparency
        if self.get_trans():
            return 0
        
        # 1) raw bl
        elif self._bl is not None:
            return self._bl
        
        # 2) bl automation: only when parsing buffers
        # see _from_char()
        
        # 3) no bl defined, return the bl computed from the value set
        elif self._val is not None or self._valauto is not None:
            return self._get_bl_from_val()
        
        # 4) no bl defined, no value defines, return the default one
        else:
            return self.DEFAULT_BL
    
    def set_dic(self, dic=None):
        """Set a dictionnary for the value interpretation of self, used for
        object representation
        
        Args:
            dic (dict) : value / interpretation lookup dict, default to None
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and dic is not dict
        """
        if dic is None:
            try:
                del self._dic
            except Exception:
                pass
        else:
            if self._SAFE_STAT:
                self._chk_dic(dic)
            self._dic = dic
        
    
    def _chk_dic(self, *args):
        if args:
            dic = args[0]
        else:
            dic = self._dic
        if not isinstance(dic, (NoneType, dict)):
            raise(EltErr('{0} [_chk_dic]: dic type is {1}, expecting dict'\
                  .format(self._name, type(dic).__name__)))
    
    def set_dicauto(self, dicauto=None):
        """Set an automation for producing the dictionnary which helps in the
        value interpretation of self
        
        Args:
            dicauto (callable) : automate the dic computation,
                call dicauto() to compute the dictionnary, default to None
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and dicauto is not callable
        """
        if dicauto is None:
            try:
                del self._dicauto
            except Exception:
                pass
        else:
            if self._SAFE_STAT and not callable(dicauto):
                raise(EltErr('{0} [set_dicauto]: dicauto type is {1}, expecting callable'\
                      .format(self._name, type(dicauto).__name__)))
            self._dicauto = dicauto
    
    def get_dic(self):
        """Returns the dictionnary for the value interpretation of self
        
        Args:
            None
        
        Returns:
            dic (dict) : dictionnary computed
                default to class attribute DEFAULT_DIC
        
        Raises:
            EltErr : if self._SAFE_DYN is enabled and the dic produced 
                dynamically is not dict
        """
        # follow the value resolution order:
        # 1) raw dic
        if self._dic is not None:
            return self._dic
        
        # 2) dic automation
        if self._dicauto is not None:
            dic = self._dicauto()
            if self._SAFE_DYN:
                self._chk_dic(dic)
            return dic
        #
        # 3) default dic
        return self.DEFAULT_DIC
    
    def get_val_dic(self):
        """Returns the looked-up value through the dictionnary returned by
        self.get_dic()
        
        Args:
            None
        
        Returns:
            dic_val (depends of self.get_dic()) 
        
        Raises:
            EltErr : if self._SAFE_DYN is enabled and the dic produced 
                dynamically is not dict
        """
        if self._dic is None and self._dicauto is None:
            return self._val
        else:
            return self.get_dic().get(self._val, self._val)
        
    def reautomate(self):
        """Reset all attributes of self which have an automation 
        
        Args:
            None
        
        Returns:
            None
        """
        # restore class attributes
        if self._valauto is not None and self._val is not None:
            del self._val
        if self._blauto is not None and self._bl is not None:
            del self._bl
        if self._transauto is not None and self._trans is not None:
            del self._trans
        if self._dicauto is not None and self._dic is not None:
            del self._dic
    
    #--------------------------------------------------------------------------#
    # conversion routines
    #--------------------------------------------------------------------------#
    
    def _to_pack(self):
        """Produces a tuple ready to be packed with pack_val() according to its
        internal value
        """
        if not self.get_trans():
            return [(TYPE_BYTES, b'', 0)]
        else:
            return []
    
    def _from_char(self, char):
        """Consume the charpy intance and set its internal value according to
        it
        """
        if not self.get_trans():
            self.set_val(None)
    
    #--------------------------------------------------------------------------#
    # copy / cloning routines
    #--------------------------------------------------------------------------#
    
    def get_attrs(self):
        """Returns the dictionnary of universal attributes of self
        
        Args:
            None
        
        Returns:
            attrs (dict) : dictionnary of attributes
        """
        return {'name' : self._name,
                'desc' : self._desc,
                'rep'  : self._rep,
                'hier' : self._hier,
                'bl'   : self._bl,
                'val'  : self._val,
                'trans': self._trans,
                'dic'  : self._dic}
    
    def get_attrs_all(self):
        """Returns the dictionnary of all attributes of self
        
        Args:
            None
        
        Returns:
            attrs (dict) : dictionnary of attributes
        """
        return {'env'      : self._env,
                'name'     : self._name,
                'desc'     : self._desc,
                'rep'      : self._rep,
                'hier'     : self._hier,
                'bl'       : self._bl,
                'blauto'   : self._blauto,
                'val'      : self._val,
                'valauto'  : self._valauto,
                'trans'    : self._trans,
                'transauto': self._transauto,
                'dic'      : self._dic,
                'dicauto'  : self._dicauto}
    
    def set_attrs(self, **kw):
        """Updates the attributes of self
        
        Args:
            kw (dict): dict of attributes and associated values
                attributes can be name, desc, rep, hier, bl, val, trans and dic
        
        Returns:
            None
        """
        if 'name' in kw and isinstance(kw['name'], str):
            self._name = kw['name']
        if 'desc' in kw and isinstance(kw['desc'], str) and kw['desc'] != self.__class__._desc:
            self._desc = str(kw['desc'])
        if 'rep' in kw and kw['rep'] in self.REPR_TYPES and \
        kw['rep'] != self.__class__._rep:
            self._rep = kw['rep']
        if 'hier' in kw and kw['hier'] != self.__class__._hier:
            self._hier = kw['hier']
        if 'bl' in kw and kw['bl'] != self.__class__._bl:
            self._bl = kw['bl']
        if 'val' in kw and kw['val'] != self.__class__._val:
            self._val = kw['val']
        if 'trans' in kw and kw['trans'] != self.__class__._trans:
            self._trans = kw['trans']
        if 'dic' in kw and kw['dic'] != self.__class__._dic:
            self._dic = kw['dic']
        #
        if self._SAFE_STAT:
            self._chk_hier()
            self._chk_bl()
            self._chk_val()
            self._chk_trans()
            self._chk_dic()
    
    def clone(self):
        """Produces an independent clone of self
        
        Args:
            None
        
        Returns:
            clone (self.__class__ instance)
        """
        kw = {'rep': self._rep}
        if self._desc != self.__class__._desc:
            kw['desc'] = self._desc
        if self._hier != self.__class__._hier:
            kw['hier'] = self._hier
        if self._bl != self.__class__._bl:
            kw['bl'] = self._bl
        if self._val != self.__class__._val:
            kw['val'] = self._val
        if self._trans != self.__class__._trans:
            kw['trans'] = self._trans
        if self._dic != self.__class__._dic:
            kw['dic'] = self._dic
        return self.__class__(self._name, **kw)
    
    #--------------------------------------------------------------------------#
    # representation routines
    #--------------------------------------------------------------------------#
    
    def repr(self):
        # element transparency
        if self.get_trans():
            trans = ' [transparent]'
        else:
            trans = ''
        # additional description
        if self._desc:
            desc = ' [%s]' % self._desc
        else:
            desc = ''
        # type of representation to be used
        val = self()
        if self._rep in (REPR_RAW, REPR_HUM):
            val_repr = repr(val)
        elif self._rep == REPR_BIN:
            val_repr = '0b' + self.bin()
        elif self._rep in (REPR_HEX, REPR_HD):
            val_repr = '0x' + self.hex()
        if self.REPR_MAXLEN > 0 and len(val_repr) > self.REPR_MAXLEN:
            val_repr = val_repr[:self.REPR_MAXLEN] + '...'
        # value informative addition with dict
        dic = self.get_dic()
        if dic and val in dic:
            val_inf = ' (%s)' % dic[val]
        else:
            val_inf = ''
        return '<%s%s%s : %s%s>' % (self._name, desc, trans, val_repr, val_inf)
    
    def _repr_hd(self):
        # element transparency
        if self.get_trans():
            trans = ' [transparent]'
        else:
            trans = ''
        # additional description
        if self._desc:
            desc = ' [%s]' % self._desc
        else:
            desc = ''
        # type of representation to be used: hview
        buf = self.to_bytes()
        if self.REPR_MAXLEN > 0 and len(buf) > self.REPR_MAXLEN:
            val_repr = hview(buf[:self.REPR_MAXLEN])
            if val_repr:
                return ['<%s%s%s :' % (self._name, desc, trans)] + val_repr + [' ...>']
            else:
                return ['<%s%s%s : ...>' % (self._name, desc, trans)]
        else:
            val_repr = hview(buf)
            if val_repr:
                val_repr[-1] += '>'
                return ['<%s%s%s :' % (self._name, desc, trans)] + val_repr
            else:
                return ['<%s%s%s : >' % (self._name, desc, trans)]
    
    def show(self):
        if self._rep == REPR_HD:
            return '\n'.join([self.get_hier_abs() * '    ' + l for l in self._repr_hd()])
        else:
            return self.get_hier_abs() * '    ' + self.repr()
    
    #--------------------------------------------------------------------------#
    # Python built-ins override
    #--------------------------------------------------------------------------#
    
    __call__ = get_val
    __repr__ = repr
    #if python_implementation != 'PyPy':
        # PyPy iterator implementation leads to an infinite loop
        # __iter__() calls __len__(), but here, get_bl() calls __iter__()
    #    __len__ = get_bl


#------------------------------------------------------------------------------#
# Envelope parent class
#------------------------------------------------------------------------------#

class Envelope(Element):
    """
    Class for envelopes: special element which acts as a container for other
    elements (atom, envelope, array, sequence, alt)
    
    class attribute:
    - GEN: tuple of elements which is used to build the envelope content at 
    initialization
    
    universal attributes:
    - content: list of elements, cloned from the GEN tuple
    - trans: bool, transparency of the envelope
    - hier: hierarchical level when placed in an envelope
    
    automation attribute:
    - transauto: callable, to automate the determination of envelope's 
    transparency
    
    contextual attributes:
    - env: envelope, container of the current envelope
    
    Envelope provides methods identical to Python list and dict in order to 
    manage elements within its content easily
    """
    
    # hardcoded class name
    CLASS = 'Envelope'
    
    # default transparency
    DEFAULT_TRANS = False
    
    # default attributes value
    _env       = None
    _hier      = 0
    _desc      = ''
    _blauto    = None
    _trans     = None
    _transauto = None
    _GEN       = tuple()
    
    __attrs__ = ('_env',
                 '_name',
                 '_desc',
                 '_hier',
                 '_blauto',
                 '_trans',
                 '_transauto',
                 '_GEN',
                 '_content',
                 '_by_name',
                 '_by_id',
                 '_it'
                 '_it_saved')
    
    def __init__(self, *args, **kw):
        """Initializes an instance of Envelope
        
        Args:
            *args: nothing or envelope name (str)
            **kw:
                name (str): envelope name if no args
                desc (str): additional envelope description
                hier (int): envelope hierarchy level
                trans (bool): envelope transparency
                GEN (tuple of elements): to override the GEN class attribute
                content (dict): to broadcast settings into the elements within 
                    the content
                val (None, dict, tuple or list): to broadcast values into the
                    elements within the content, using self.set_val()
                bl (tuple, list or dict): to broadcast bl into the elements 
                    within the content, using self.set_bl()
        """
        # iterator index initialization, required by __iter__()
        # current iterator index:
        self._it = 0
        # saved iterator indexes, when nested iterations happen
        self._it_saved = [] 
        
        # envelope name in kw, or first args
        if len(args):
            self._name = str(args[0])
        elif 'name' in kw:
            self._name = str(kw['name'])
        # if not provided, it's the class name
        elif not hasattr(self, '_name'):
            self._name = self.__class__.__name__
        
        # envelope description customization
        if 'desc' in kw:
            self._desc = str(kw['desc'])
        
        # envelope hierarchy
        if 'hier' in kw:
            self._hier = kw['hier']
        
        # envelope transparency
        if 'trans' in kw:
            self._trans = kw['trans']
        
        if 'GEN' in kw:
            GEN, clo = kw['GEN'], False
        else:
            GEN, clo = self._GEN, True
        
        if self._SAFE_STAT:
            self._chk_hier()
            self._chk_trans()
            self._chk_gen(GEN)
        
        # content list generation
        self._content, self._by_id, self._by_name = [], [], []
        if clo:
            self.extend([elt.clone() for elt in GEN])
        else:
            self.extend(GEN)
        
        # if a content dict is passed as argument
        # broadcast it to the given content items
        if 'content' in kw:
            #self._log('Envelope.__init__(content):', kw['content'])
            for i in kw['content']:
                self.__getitem__(i).set_attr(**kw['content'][i])
        
        # if a val dict is passed as argument
        # broadcast it to given content items
        if 'val' in kw:
            self.set_val( kw['val'] )
        
        # if a bl dict is passed as argument
        # broadcast it to given content items
        if 'bl' in kw:
            self.set_bl( kw['bl'] )
    
    def _chk_gen(self, gen):
        if not isinstance(gen, tuple) or \
        not all([isinstance(elt, Element) for elt in gen]):
            raise(EltErr('{0} [_chk_gen]: invalid envelope generator GEN'\
                  .format(self._name)))
    
    #--------------------------------------------------------------------------#
    # envelope, hierarchy and selection routines
    #--------------------------------------------------------------------------#
    # no change from Element
    
    #--------------------------------------------------------------------------#
    # format routines
    #--------------------------------------------------------------------------#
    
    def set_val(self, vals):
        """Set the raw values to the given elements of the content of self
        
        Args:
            vals (None, tuple, list or dict) :
                tuple or list of all element's value
                or dict of element's name, element's value
                or dict of element's index, element's value
        
        Returns:
            None
        
        Raises:
            EltErr : if element's name, index or value are invalid, or value
                setting raises
        """
        if vals is None:
            [elt.set_val(None) for elt in self.__iter__()]
        elif isinstance(vals, (tuple, list)):
            for ind, elt in enumerate(self.__iter__()):
                elt.set_val(vals[ind])
        elif isinstance(vals, dict):
            # ordered values is sometimes required, depending of the structure
            # -> happens in particular when an Alt() is present in the envelope
            vals_ind = {self._by_name.index(k): v for (k, v) in vals.items() \
                        if isinstance(k, str_types)}
            if vals_ind:
                if len(vals_ind) == len(vals):
                    vals = vals_ind
                else:
                    vals = {k: v for (k, v) in vals.items() \
                            if isinstance(k, integer_types)}
                    vals.update(vals_ind)
            for k in sorted(vals.keys()):
                self.__setitem__(k, vals[k])
        elif self._SAFE_STAT:
            raise(EltErr('{0} [set_val]: vals type is {1}, expecting None, '\
                  'tuple, list or dict'.format(self._name, type(vals).__name__)))
    
    def get_val(self):
        """Returns the list of values of all the elements of the content of self
        
        Args:
            None
        
        Returns:
            value (list) : list of values computed
        
        Raises:
            EltErr : if one element within the content raises
        """
        return [elt() for elt in self.__iter__()]
    
    def get_val_d(self):
        """Returns the dict of element names and values of the content of self
        Wanrning: in case several elements have the same name, the returned value 
        won't be complete.
        
        Args:
            None
        
        Returns:
            value (dict) : dict of names and values
        
        Raises:
            EltErr : if one element within the content raises
        """
        return {elt._name: elt.get_val_d() for elt in self.__iter__()}
    
    def set_bl(self, bl):
        """Set the raw bit length to the given elements of the content of self
        
        Args:
            bl (tuple, list or dict) :
                tuple or list of all element's bitlen
                or dict of element's name, element's bitlen
                or dict of element's index, element's bitlen
        
        Returns:
            None
        
        Raises:
            EltErr : if element's name, index or bl are invalid, or bit length
                setting raises
        """
        if isinstance(bl, (tuple, list)):
            for ind, elt in enumerate(self.__iter__()):
                elt.set_bl(bl[ind])
        elif isinstance(bl, dict):
            for key, val in bl.items():
                self.__getitem__(key).set_bl(val)
        elif self._SAFE_STAT:
            raise(EltErr('{0} [set_bl]: bl type is {1}, expecting tuple, list '\
                         'or dict'.format(self._name, type(bl).__name__)))
    
    def set_blauto(self, blauto=None):
        """Set an automation for the length in bits of self, used only when 
        mapping an external buffer to it.
        
        Args:
            blauto (callable) : automate the bl computation,
                call blauto() to compute the bit length, default to None
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and blauto is not a callable
        """
        if blauto is None:
            try:
                del self._blauto
            except Exception:
                pass
        else:
            if self._SAFE_STAT and not callable(blauto):
                raise(EltErr('{0} [set_blauto]: blauto type is {1}, expecting callable'\
                      .format(self._name, type(blauto).__name__)))
            self._blauto = blauto
    
    def get_bl(self):
        """Returns the total length in bits of self
        
        Args:
            None
        
        Returns:
            bl (int) : length in bits computed (sum of the content)
        
        Raises:
            EltErr : if one element within the content raises
        """
        if self.get_trans():
            return 0
        else:
            return sum([elt.get_bl() for elt in self.__iter__()])
    
    def reautomate(self):
        """Reset all attributes of the element which have an automation within 
        the content of self
        
        Args:
            None
        
        Returns:
            None
        """
        if self._transauto is not None and self._trans is not None:
            del self._trans
        [elt.reautomate() for elt in self._content]
    
    #--------------------------------------------------------------------------#
    # conversion routines
    #--------------------------------------------------------------------------#
    
    def _to_pack(self):
        """Produces a list of tuples  (type, val, bl) ready to be packed with 
        pack_val()
        """
        if not self.get_trans():
            pl = []
            [pl.extend(elt._to_pack()) for elt in self.__iter__()]
            return pl
        else:
            return []
    
    def _from_char(self, char):
        """Dispatch the consumption of a Charpy intance to the elements within
        the content
        """
        # TODO: in cases some ranges of elt within self have a fixed _bl
        # it would be more efficient to unpack them in a single shot, 
        # especially if these are int / uint on 8, 16, 32, 64 bits
        if self.get_trans():
            return
        # truncate char if length automation is set
        if self._blauto is not None:
            char_lb = char._len_bit
            char._len_bit = char._cur + self._blauto()
            if char._len_bit > char_lb:
                raise(EltErr('{0} [_from_char]: bit length overflow'.format(self._name)))
        #
        for elt in self.__iter__():
            elt._from_char(char)
        #
        # in case of length automation, set the original length back
        if self._blauto is not None:
            char._len_bit = char_lb
    
    #--------------------------------------------------------------------------#
    # copy / cloning routines
    #--------------------------------------------------------------------------#
    
    def get_attrs(self):
        """Returns the dictionnary of universal attributes of self and the 
        elements within its content
        
        Args:
            None
        
        Returns:
            attrs (dict) : dictionnary of attributes
        """
        return {'name'   : self._name,
                'desc'   : self._desc,
                'hier'   : self._hier,
                'trans'  : self._trans,
                'content': {elt._name: elt.get_attrs() for elt in self._content}}
    
    def get_attrs_all(self):
        """Returns the dictionnary of all attributes of self and the elements 
        within its content
        
        Args:
            None
        
        Returns:
            attrs (dict) : dictionnary of attributes
        """
        return {'env'      : self._env,
                'name'     : self._name,
                'desc'     : self._desc,
                'hier'     : self._hier,
                'trans'    : self._trans,
                'transauto': self._transauto,
                'content'  : {elt._name: elt.get_attrs_all() for elt in self._content}}
    
    def set_attrs(self, **kw):
        """Updates the attributes of self and the elements within its content
        
        Args:
            kw (dict): dict of attributes and associated values
                attributes can be name, desc, hier, trans, bl, val and content
        
        Returns:
            None
        """
        if 'name' in kw and isinstance(kw['name'], str):
            self._name = kw['name']
        if 'desc' in kw and isinstance(kw['desc'], str) and kw['desc'] != self.__class__._desc:
            self._desc = str(kw['desc'])
        if 'hier' in kw and kw['hier'] != self.__class__._hier:
            self._hier = kw['hier']
        if 'trans' in kw and kw['trans'] != self.__class__._trans:
            self._trans = kw['trans']
        #
        if self._SAFE_STAT:
            self._chk_hier()
            self._chk_trans()
        #
        if 'content' in kw:
            for name, attrs in kw['content'].items():
                self.__getitem__(name).set_attrs(**attrs)
        if 'bl' in kw:
            self.set_bl(kw['bl'])
        if 'val' in kw:
            self.set_val(kw['val'])
    
    def clone(self):
        """Produces an independent clone of self
        
        Args:
            None
        
        Returns:
            clone (self.__class__ instance)
        """
        kw = {}
        if self._desc != self.__class__._desc:
            kw['desc'] = self._desc
        if self._hier != self.__class__._hier:
            kw['hier'] = self._hier
        if self._trans != self.__class__._trans:
            kw['trans'] = self._trans
        # substitute the Envelope generator with clones of the current 
        # envelope's content
        kw['GEN'] = tuple([elt.clone() for elt in self._content])
        return self.__class__(self._name, **kw)
    
    #--------------------------------------------------------------------------#
    # Python list / dict methods emulation
    #--------------------------------------------------------------------------#
    
    def append(self, elt):
        """Append the element `elt' at the end of the content of self
        
        Args:
            elt (element) : element to be appended
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and the type of `elt' is 
                not Element
        """
        if self._SAFE_STAT and not isinstance(elt, Element):
            raise(EltErr('{0} [append]: arg type is {1}, expecting element'\
                  .format(self._name, type(elt).__name__)))
        # append elt to content
        self._content.append(elt)
        # populate by_id and by_name list
        self._by_id.append(id(elt))
        self._by_name.append(elt._name)
        # inform elt of its new envelope
        elt.set_env(self)
    
    def count(self, name):
        """Count the number of elements with name `name' in the content of self
        
        Args:
            name (str) : name to be used for counting
        
        Returns:
            cnt (int): number of iteration of `name'
        
        Raises:
            EltErr : if name `name' has not the right type
        """
        try:
            return self._by_name.count(name)
        except Exception as err:
            raise(EltErr('{0} [count]: {1}'.format(self._name, err)))
    
    def extend(self, elt_iter):
        """Append the list of elements `elt_iter' at the end of the content of
        self
        
        Args:
            elt_iter (iterable of elements) : list of elements to be appended
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and the types produced by
               `elt_iter' is not Element
        """
        for elt in elt_iter:
            if self._SAFE_STAT and not isinstance(elt, Element):
                raise(EltErr('{0} [extend]: iterated arg type is {1}, expecting element'\
                      .format(self._name, type(elt).__name__)))
            self._content.append(elt)
            self._by_id.append(id(elt))
            self._by_name.append(elt._name)
            elt.set_env(self)
    
    def index(self, elt):
        """Provide the index of the element `elt' within the content of self
        
        Args:
            elt (element) : element to be looked-up in the envelope
        
        Returns:
            ind (int) : index of the element within the envelope
        
        Raises:
            EltErr : element `elt' is not in the content
        """.format(self.__class__.__name__)
        try:
            return self._by_id.index(id(elt))
        except Exception as err:
            raise(EltErr('{0} [index]: {1}'.format(self._name, err)))
    
    def insert(self, index, elt):
        """Insert the element `elt' at the given index in the content of self
        
        Args:
            index (int) : index where to insert `elt'
            elt (element) : element to be inserted
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and the type of `elt' is 
                not Element, or if insertion at the given index fails  
        """
        if self._SAFE_STAT and not isinstance(elt, Element):
            raise(EltErr('{0} [insert]: arg type is {1}, expecting element'\
                  .format(self._name, type(elt).__name__)))
        try:
            self._content.insert(index, elt)
        except Exception as err:
            raise(EltErr('{0} [insert]: {1}'.format(self._name, err)))
        else:
            self._by_name.insert(index, elt._name)
            self._by_id.insert(index, id(elt))
            elt.set_env(self)
    
    def pop(self):
        """Pop the last element of the content of self
        
        Args:
            None
        
        Returns:
            elt (element) : last element of the content
        """
        try:
            elt = self._content.pop()
        except Exception as err:
            raise(EltErr('{0} [pop]: {1}'.format(self._name, err)))
        else:
            # remove it from by_id and by_name lists
            self._by_id.pop()
            self._by_name.pop()
            # elt has no envelope anymore
            elt.set_env(None)
            # return it
            return elt
    
    def remove(self, elt):
        """Remove the element `elt' from the content of self
        
        Args:
            elt (element) : element to be removed
        
        Returns:
            None
        
        Raises:
            EltErr : if element `elt' is not in the content
        """
        try:
            ind = self._by_id.index(id(elt))
        except Exception as err:
            raise(EltErr('{0} [remove]: {1}'.format(self._name, err)))
        else:
            del self._content[ind], self._by_id[ind], self._by_name[ind]
            elt.set_env(None)
    
    def replace(self, old, new):
        """Replace the element `old' with the element `new' in the content of 
        self
        
        Args:
            old (element) : element to be removed
            new (element) : element to be inserted
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and the type of `new' is not 
                Element, or if element `old' is not in the content
        """
        if self._SAFE_STAT and not isinstance(new, Element):
            raise(EltErr('{0} [replace]: new type is {1}, expecting element'\
                  .format(self._name, type(new).__name__)))
        #
        try:
            ind = self._by_id.index(id(old))
        except Exception as err:
            raise(EltErr('{0} [replace] error with old: {1}'.format(self._name, err)))
        else:
            # remove old
            del self._content[ind], self._by_name[ind], self._by_id[ind]
            old.set_env(None)
            # insert new
            self._content.insert(ind, new)
            self._by_name.insert(ind, new._name)
            self._by_id.insert(ind, id(new))
            new.set_env(self)
            new.set_hier(old.get_hier())
    
    def clear(self):
        """Clear the content of self
        
        Args:
            None
        
        Returns:
            None
        """
        if python_version < 3:
            del self._content[:]
            del self._by_id[:]
            del self._by_name[:]
        else:
            self._content.clear()
            self._by_id.clear()
            self._by_name.clear()
    
    def __iter__(self):
        self._it_saved.append(self._it)
        self._it = 0
        return self
    
    def __next__(self):
        if self._it >= len(self._content):
            if self._it_saved:
                # in case of nested iteration
                self._it = self._it_saved.pop() + 1
            raise(StopIteration())
        else:
            it = self._it
            self._it += 1
            if self.ENV_SEL_TRANS:
                # do not take element transparency into account
                return self._content[it]
            elif not self._content[it].get_trans():
                # non-transparent element
                return self._content[it]
            else:
                # transparent element, pass it and try the next one
                return self.__next__()
    
    if python_version < 3:
        next = __next__
    
    def __getitem__(self, key):
        if isinstance(key, str_types):
            try:
                return self._content[self._by_name.index(key)]
            except Exception as err:
                raise(EltErr('{0} [__getitem__] str item: {1}'.format(self._name, err)))
        elif isinstance(key, integer_types):
            #print(self._name, self._content, len(self._content), key) #len(self), key)
            try:
                return self._content[key]
            except Exception as err:
                raise(EltErr('{0} [__getitem__] int item: {1}'.format(self._name, err)))
        elif isinstance(key, slice):
            # a new `slice' envelope is produced
            # _env and _hier attributes of elements in the content of self are not
            # updated as the slice envelope is not supposed to become the new home 
            # of those
            slice_env = Envelope('slice')
            try:
                slice_env._content = self._content[key]
            except Exception as err:
                raise(EltErr('{0} [__getitem__] slice item: {1}'.format(self._name, err)))
            else:
                slice_env._by_name = self._by_name[key]
                slice_env._by_id = self._by_id[key]
                return slice_env
        else:
            raise(EltErr('{0} [__getitem__]: envelope item must be int, str or slice'\
                  .format(self._name)))
    
    def __setitem__(self, key, val):
        if isinstance(key, str_types):
            try:
                self._content[self._by_name.index(key)].set_val(val)
            except Exception as err:
                raise(EltErr('{0} [__setitem__] error with key {1!r}, val {2!r}: {3}'\
                      .format(self._name, key, val, err)))
        elif isinstance(key, integer_types):
            try:
                self._content[key].set_val(val)
            except Exception as err:
                raise(EltErr('{0} [__setitem__] error with key {1!r}, val {2!r}: {3}'\
                      .format(self._name, key, val, err)))
        elif isinstance(key, slice):
            try:
                [elt.set_val(val[i]) for (i, elt) in enumerate(self._content[key])]
            except Exception as err:
                raise(EltErr('{0} [__setitem__] error with key {1!r}, val {2!r}: {3}'\
                      .format(self._name, key, val, err)))
        else:
            raise(EltErr('{0} [__setitem__]: envelope item must be int, str or slice'\
                  .format(self._name)))
    
    def __delitem__(self, key):
        if isinstance(key, str_types):
            try:
                ind = self._by_name.index(key)
            except Exception as err:
                raise(EltErr('{0} [__delitem__] str item: {1}'.format(self._name, err)))
            else:
                self._content[ind]._env = None
                del self._content[ind], self._by_name[ind], self._by_id[ind]
        elif isinstance(key, integer_types):
            try:
                self._content[key]._env = None
            except Exception as err:
                raise(EltErr('{0} [__delitem__] int item: {1}'.format(self._name, err)))
            else:
                del self._content[key], self._by_name[key], self._by_id[key]
        elif isinstance(key, slice):
            try:
                [elt.set_env(None) for elt in self._content[key]]
            except Exception as err:
                raise(EltErr('{0} [__delitem__] slice item: {1}'.format(self._name, err)))
            else:
                del self._content[key], self._by_name[key], self._by_id[key]
        else:
            raise(EltErr('{0} [__delitem__]: envelope item must be int, str or slice'\
                  .format(self._name)))
    
    #--------------------------------------------------------------------------#
    # representation routines
    #--------------------------------------------------------------------------#
    
    def repr(self):
        # element transparency
        if self.get_trans():
            trans = ' [transparent]'
        else:
            trans = ''
        # additional description
        if self._desc:
            desc = ' [%s]' % self._desc
        else:
            desc = ''
        #
        return '<%s%s%s : %s>' % \
               (self._name, desc, trans, ''.join(map(repr, self._content)))
    
    def show(self):
        # element transparency
        if self.get_trans():
            trans = ' [transparent]'
        else:
            trans = ''
        # additional description
        if self._desc:
            desc = ' [%s]' % self._desc
        else:
            desc = ''
        #
        return '\n '.join(
            [self.get_hier_abs()*'    ' + '### %s%s%s ###' % (self._name, desc, trans)] + \
            [elt.show().replace('\n', '\n ') for elt in self.__iter__()])
    
    #--------------------------------------------------------------------------#
    # Python built-ins override
    #--------------------------------------------------------------------------#
    
    __call__ = get_val
    __repr__ = repr
    #if python_implementation != 'PyPy':
        # PyPy iterator implementation lead to an infinite loop
        # __iter__() calls __len__(), but here, get_bl() calls __iter__()
    #    __len__ = get_bl
    
    #--------------------------------------------------------------------------#
    # json interface
    #--------------------------------------------------------------------------#
    
    if _with_json:
        
        def _from_jval(self, val):
            if not isinstance(val, list):
                raise(EltErr('{0} [_from_jval]: invalid format, {1!r}'.format(self._name, val)))
            i = 0
            for e in self._content:
                if not e.get_trans():
                    try:
                        e._from_jval_wrap(val[i])
                    except Exception:
                        break
                    else:
                        i += 1
            # ensure all non-transparent elements were set
            for e in self._content[1+self._content.index(e):]:
                if not e.get_trans() and e.get_bl():
                    raise(EltErr('{0} [_from_jval]: missing elements, {1} ...'\
                          .format(self._name, e._name)))
        
        def _to_jval(self):
            return [e._to_jval_wrap() for e in self._content if not e.get_trans()]


class Array(Element):
    """
    Class for arrays: special element which acts as a container for a list of
    values for a given immutable element (atom, envelope, array, sequence, alt)
    
    class attribute:
    - GEN: element which is used to build the array template at initialization
    
    universal attributes:
    - tmpl: element, cloned from the GEN, used as proxy for generating an
    array of elements from values in content
    - tmpl_val: default value for the template to be used in the content, when 
    not explicitely set
    - num: number of iterations of the template within the content
    - content: list of values, formatted for the content 
    - trans: bool, transparency of the array
    - hier: hierarchical level when placed within an envelope
    
    automation attribute:
    - numauto: callable, to automate the determination of the number of 
    template's iteration
    - blauto: callable, to automate the length in bits to be decoded
    - transauto: callable, to automate the determination of array's 
    transparency
    
    contextual attributes:
    - env: envelope, container of the array
    
    Array provides methods identical to Python list and dict in order to 
    manage Element's instances within its content easily
    """
    
    # hardcoded class name
    CLASS = 'Array'
    
    # default transparency
    DEFAULT_TRANS = False
    
    # default attributes value
    _env       = None
    _hier      = 0
    _desc      = ''
    _trans     = None
    _transauto = None
    _num       = None
    _numauto   = None
    _blauto    = None
    _GEN       = Atom()
    
    __attrs__ = ('_env',
                 '_name',
                 '_desc',
                 '_hier',
                 '_trans',
                 '_transauto',
                 '_num',
                 '_numauto',
                 '_blauto',
                 '_GEN',
                 '_tmpl',
                 '_tmpl_val',
                 '_tmpl_bl',
                 '_tmpl_pack',
                 '_val',
                 '_it',
                 '_it_saved')
    
    
    def __init__(self, *args, **kw):
        """Initializes an instance of Array
        
        Args:
            *args: nothing or instance name (str)
            **kw:
                name (str): array name if no args
                desc (str): additional array description
                hier (int): array hierarchy level
                trans (bool): array transparency
                GEN (element): to override the GEN class attribute
                tmpl_val (element's value): to set a default value for the 
                    template generated from GEN
                tmpl_bl (element's bl): to set default bit length for the 
                    template generated from GEN
                num (int): number of iteration within the array content
                val (None, tuple, list or dict): values to be set in the array
        """
        # iterator index initialization, required by __iter__()
        # current iterator index:
        self._it = 0
        # saved iterator indexes, when nested iterations happen
        self._it_saved = [] 
        
        # array name in kw, or first args
        if len(args):
            self._name = str(args[0])
        elif 'name' in kw:
            self._name = str(kw['name'])
        # if not provided, it's the class name
        elif not hasattr(self, '_name'):
            self._name = self.__class__.__name__
        
        # array description customization
        if 'desc' in kw:
            self._desc = str(kw['desc'])
        
        # array hierarchy
        if 'hier' in kw:
            self._hier = kw['hier']
        
        # array transparency
        if 'trans' in kw:
            self._trans = kw['trans']
        
        if 'GEN' in kw:
            GEN, clo = kw['GEN'], False
        else:
            GEN, clo = self._GEN, True
        
        if self._SAFE_STAT:
            self._chk_hier()
            self._chk_trans()
            if not isinstance(GEN, Element):
                raise(EltErr('{0} [__init__]: invalid array generator GEN'\
                      .format(self._name)))
        
        if clo:
            self._tmpl = GEN.clone()
        else:
            self._tmpl = GEN
        self._tmpl._env = self
        
        # setting default values and format for the template element
        if 'tmpl_val' in kw:
            try:
                self._tmpl.set_val(kw['tmpl_val'])
            except Exception as err:
                raise(EltErr('{0} [__init__] set template value error: {1}'\
                      .format(self._name, err)))
        if 'tmpl_bl' in kw:
            try:
                self._tmpl.set_bl(kw['tmpl_bl'])
            except Exception as err:
                raise(EltErr('{0} [__init__] set template bl error: {1}'\
                      .format(self._name, err)))
        
        # set default value, and values container
        self._tmpl_val  = self._tmpl()
        self._tmpl_bl   = self._tmpl.get_bl()
        self._tmpl_pack = self._tmpl._to_pack()
        self._val = []
        
        # array number of content
        if 'num' in kw:
            self.set_num(kw['num'])
        
        # values in the array
        if 'val' in kw:
            self.set_val(kw['val'])
    
    #--------------------------------------------------------------------------#
    # envelope, hierarchy and selection routines
    #--------------------------------------------------------------------------#
    # nothing changes from Element
    
    #--------------------------------------------------------------------------#
    # format routines
    #--------------------------------------------------------------------------#
    
    def set_val(self, vals):
        """Set an array of raw values according to the template
        
        Args:
            vals (None, tuple, list or dict) : tuple / list of values 
                or dict of array's index, array's value
        
        Returns:
            None
        
        Raises:
            EltErr : if array's index or value is invalid
        """
        if vals is None:
            self._val = []
        #
        elif isinstance(vals, dict):
            max_ind = max(vals.keys())
            if self._SAFE_STAT:
                # ensure the val dict indexes are valid
                if not all([isinstance(k, integer_types) for k in vals]):
                    raise(EltErr('{0} [set_val] vals keys are not all integers'\
                          .format(self._name)))
                # ensure the max index does not overflow a fixed max size
                if self._num is not None and max_ind >= self._num:
                    raise(EltErr('{0} [set_val] vals index {1} overflow (max {2})'\
                          .format(self._name, max_ind, self._num)))
            # in case the current value self._val does not goes up to the max index
            # just extend it with the default value
            if len(self._val) <= max_ind:
                self._val.extend( (1+max_ind-len(self._val)) * (self._tmpl_val, ) )
            for i, v in vals.items():
                self._tmpl.set_val(v)
                self._val[i] = self._tmpl.get_val()
            # reset the template's value
            self._tmpl.set_val(None)
        #
        elif isinstance(vals, (tuple, list)):
            if self._SAFE_STAT and self._num is not None and len(vals) != self._num:
                # ensure vals length does not overflow a fixed number of iteration
                raise(EltErr('{0} [set_val] invalid number of values: {1} instead of {2}'\
                      .format(self._name, len(vals), self._num)))
            #
            self._val = []
            for v in vals:
                self._tmpl.set_val(v)
                self._val.append(self._tmpl())
            # reset the template's value
            self._tmpl.set_val(None)
        #
        else:
            raise(EltErr('{0} [set_val]: vals type is {1}, expecting None, tuple, list or dict'\
                  .format(self._name, type(vals).__name__)))
    
    def get_val(self):
        """Returns the list of values of self according to its template
        
        Args:
            None
        
        Returns:
            value (list) : array of values
        """
        return self._val
    
    # for array element, no dict to be returned, but just the standard list of values
    get_val_d = get_val
    
    def set_num(self, num=None):
        """Set the raw number of iteration of the template in the array's value
        
        Args:
            num (int) : raw number of iteration, default to None
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and bitlen is not integer
        """
        if num is None:
            try:
                del self._num
            except Exception:
                pass
        else:
            if self._SAFE_STAT and not isinstance(num, integer_types):
                raise(EltErr('{0} [set_num]: num type is {1}, expecting integer'\
                      .format(self._name, type(num).__name__)))
            self._num = num
            # clean up extra values if already set
            if len(self._val) > num:
                del self._val[num:]
            # extend values if not already set
            elif len(self._val) < num:
                self._val.extend( (num-len(self._val)) * (self._tmpl_val, ) )
    
    def set_numauto(self, numauto=None):
        """Set an automation for the number of iteration of the template in the
        array's value, used only when mapping an external buffer to self
        
        Args:
            numauto (callable) : automate the num computation, call numauto() 
                to compute num, default to None
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and numauto is not a callable
        """
        if numauto is None:
            try:
                del self._numauto
            except Exception:
                pass
        else:
            if self._SAFE_STAT and not callable(numauto):
                raise(EltErr('{0} [set_numauto]: numauto type is {1}, expecting callable'\
                      .format(self._name, type(numauto).__name__)))
            self._numauto = numauto
    
    def get_num(self):
        """Returns the number of iterations of the template in the array's value
        
        Args:
            None
        
        Returns:
            num (int) : number of elements, default to the number of values
        """
        # follow the value resolution order:
        # 1) raw num
        if self._num is not None:
            return self._num
        
        # 2) num automation: only when parsing buffers (in _from_char)
        # see _from_char()
        
        # 3) no num defined, return the num from the values already set
        else:
            return len(self._val)
    
    def set_blauto(self, blauto=None):
        """Set an automation for the length in bits of self, used only when 
        mapping an external buffer to it.
        
        Args:
            blauto (callable) : automate the bl computation,
                call blauto() to compute the bit length, default to None
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and blauto is not a callable
        """
        if blauto is None:
            try:
                del self._blauto
            except Exception:
                pass
        else:
            if self._SAFE_STAT and not callable(blauto):
                raise(EltErr('{0} [set_blauto]: blauto type is {1}, expecting callable'\
                      .format(self._name, type(blauto).__name__)))
            self._blauto = blauto
    
    def get_bl(self):
        """Returns the length in bits of self
        
        Args:
            None
        
        Returns:
            bl (int) : length in bits computed
        
        Raises:
            EltErr : if one element within the content raises
        """
        if self.get_trans():
            return 0
        else:
            ret = []
            for v in self._val:
                if v == self._tmpl_val:
                    ret.append(self._tmpl_bl)
                else:
                    self._tmpl.set_val(v)
                    ret.append(self._tmpl.get_bl())
            self._tmpl.set_val(None)
            return sum(ret)
    
    def reautomate(self):
        """Reset all attributes of self and its template which have an automation 
        
        Args:
            None
        
        Returns:
            None
        """
        if self._transauto is not None and self._trans is not None:
            del self._trans
        if self._numauto is not None and self._num is not None:
            del self._num
        self._tmpl.reautomate()
    
    #--------------------------------------------------------------------------#
    # conversion routines
    #--------------------------------------------------------------------------#
    
    def _to_pack(self):
        """Produces a list of tuple ready to be packed with pack_val() from the
        array's values through the template
        """
        if not self.get_trans():
            if self._SAFE_STAT and self._num is not None and len(self._val) != self._num:
                raise(EltErr('{0} [_to_pack] invalid number of values: {1} instead of {2}'\
                      .format(self._name, len(self._val), self._num)))
            pl = []
            for v in self._val:
                if v == self._tmpl_val:
                    pl.extend(self._tmpl_pack)
                else:
                    self._tmpl.set_val(v)
                    pl.extend(self._tmpl._to_pack())
            self._tmpl.set_val(None)
            return pl
        else:
            return []
    
    def _from_char(self, char):
        """Dispatch the consumption of a Charpy intance to the values within the
        array through the template
        """
        if self.get_trans():
            return
        # 1) determine the number of iteration of the template within the array
        if self._numauto is not None:
            num = self._numauto()
            if self._SAFE_DYN and not isinstance(num, integer_types):
                raise(EltErr('{0} [_from_char]: num type produced is {1}, expecting integer'\
                      .format(self._name, type(num).__name__)))
        elif self._num is not None:
            num = self._num
        else:
            # num is None, _from_char will consume the charpy instance until
            # it raises
            num = None
        # 2) truncate char if length automation is set
        if self._blauto is not None:
            char_lb = char._len_bit
            char._len_bit = char._cur + self._blauto()
            if char._len_bit > char_lb:
                raise(EltErr('{0} [_from_char]: bit length overflow'.format(self._name)))
        # 3) init value
        self._val = []
        # 4) consume char and fill in self._val
        if num is not None:
            for i in range(num):
                self._tmpl._from_char(char)
                self._val.append(self._tmpl())
        else:
            # there is no predefined limit in the number of iteration
            # consume the charpy instance until its empty and raises
            while True:
                # remember charpy cursor position, to restore it when it raises
                cur = char._cur
                try:
                    self._tmpl._from_char(char)
                except CharpyErr:
                    char._cur = cur
                    break
                else:
                    self._val.append(self._tmpl())
        self._tmpl.set_val(None)
        # 5) in case of length automation, set the original length back
        if self._blauto is not None:
            char._len_bit = char_lb
    
    #--------------------------------------------------------------------------#
    # copy / cloning routines
    #--------------------------------------------------------------------------#
    
    def get_attrs(self):
        """Returns the dictionnary of universal attributes of self and its 
        template
        
        Args:
            None
        
        Returns:
            attr (dict) : dictionnary of attributes
        """
        return {'name'    : self._name,
                'desc'    : self._desc,
                'hier'    : self._hier,
                'trans'   : self._trans,
                'num'     : self._num,
                'val'     : self._val,
                'tmpl'    : self._tmpl.get_attrs(),
                'tmpl_val': self._tmpl_val,
                'tmpl_bl' : self._tmpl_bl}
    
    def get_attrs_all(self):
        """Returns the dictionnary of all attributes of self and its template 
        
        Args:
            None
        
        Returns:
            attr (dict) : dictionnary of attributes
        """
        return {'name'     : self._name,
                'desc'     : self._desc,
                'hier'     : self._hier,
                'trans'    : self._trans,
                'transauto': self._transauto,
                'num'      : self._num,
                'numauto'  : self._numauto,
                'val'      : self._val,
                'tmpl'     : self._tmpl.get_attrs_all(),
                'tmpl_val' : self._tmpl_val,
                'tmpl_bl'  : self._tmpl_bl}
    
    def set_attrs(self, **kw):
        """Updates the attributes of self and its template
        
        Args:
            kw (dict): dict of attributes and associated values
                attributes can be name, desc, hier, trans, tmpl, val and num

        Returns:
            None
        """
        if 'name' in kw and isinstance(kw['name'], str):
            self._name = kw['name']
        if 'desc' in kw and isinstance(kw['desc'], str) and kw['desc'] != self.__class__._desc:
            self._desc = kw['desc']
        if 'hier' in kw and kw['hier'] != self.__class__._hier:
            self._hier = kw['hier']
        if 'trans' in kw and kw['trans'] != self.__class__._trans:
            self._trans = kw['trans']
        #
        if self._SAFE_STAT:
            self._chk_hier()
            self._chk_trans()
        #
        if 'tmpl' in kw:
            self._tmpl.set_attrs(**kw['tmpl'])
            self._tmpl_val  = self._tmpl()
            self._tmpl_bl   = self._tmpl.get_bl()
            self._tmpl_pack = self._tmpl._to_pack()
        #
        if 'val' in kw:
            self.set_val(kw['val'])
        if 'num' in kw:
            self.set_num(kw['num'])
    
    def clone(self):
        """Produces an independent clone of self
        
        Args:
            None
        
        Returns:
            clone (self.__class__ instance)
        """
        kw = {}
        if self._desc != self.__class__._desc:
            kw['desc'] = self._desc
        if self._hier != self.__class__._hier:
            kw['hier'] = self._hier
        if self._trans != self.__class__._trans:
            kw['trans'] = self._trans
        if self._num != self.__class__._num:
            kw['num'] = self._num
        if self._val:
            kw['val'] = self._val[:]
        # substitute the Array generator with the current array's template
        kw['GEN'] = self._tmpl.clone()
        return self.__class__(self._name, **kw)
    
    #--------------------------------------------------------------------------#
    # Python list / dict methods emulation
    #--------------------------------------------------------------------------#
    
    def append(self, val):
        """Append the value `val' at the end of the array's value
        
        Args:
            val (depends of self._tmpl) : value to be appended
        
        Returns:
            None
        
        Raises:
            EltErr
        """
        if self._SAFE_STAT:
            if self._num is not None and len(self._val) == self._num:
                raise(EltErr('{0} [append] val length {1} overflow (num {2})'\
                      .format(self._name, 1+len(self._val), self._num)))
        # use the template to format the value
        if val != self._tmpl_val:
            self._tmpl.set_val(val)
            self._val.append(self._tmpl())
            self._tmpl.set_val(None)
        else:
            self._val.append(val)
    
    # here, .count() is the number of iteration in the array
    count = get_num
    
    def extend(self, vals):
        """Append the list of values `vals' at the end of the array's value
        
        Args:
            vals (list) : list of values to be appended
        
        Returns:
            None
        
        Raises:
            EltErr
        """
        if self._SAFE_STAT:
            if self._num is not None and len(vals) > (self._num-len(self._val)):
                raise(EltErr('{0} [extend]: val length {1} overflow (num {2})'\
                      .format(self._name, len(self._val)+len(vals), self._num)))
        # use the template to format the values
        for val in vals:
            if val != self._tmpl_val:
                self._tmpl.set_val(val)
                self._val.append(self._tmpl())
            else:
                self._val.append(val)
        self._tmpl.set_val(None)
    
    def index(self, val):
        """Provide the index of the first iteration of value `val' within the
        array's value
        
        Args:
            val (depends of self._tmpl) : value to get the index of
        
        Returns:
            ind (int) : index of the value within the array
        
        Raises:
            EltErr : if value `val' is not in self._val
        """
        try:
            return self._val.index(val)
        except Exception as err:
            raise(EltErr('{0} [index]: {1}'.format(self._name, err)))
    
    def insert(self, index, val):
        """Insert the value `val' at the given index in array's value
        
        Args:
            index (int) : index where to insert `val'
            val (depends of self._tmpl) : value to be inserted
        
        Returns:
            None
        
        Raises:
            EltErr : if insertion at the given index fails 
        """
        if self._SAFE_STAT:
            if self._num is not None and len(self._val) == self._num:
                raise(EltErr('{0} [insert] val length {1} overflow (num {2})'\
                      .format(self._name, 1+len(self._val), self._num)))
        # use the template to format the value
        if val != self._tmpl_val:
            self._tmpl.set_val(val)
            val = self._tmpl()
            self._tmpl.set_val(None)
        try:
            self._val.insert(index, val)
        except Exception as err:
            raise(EltErr('{0} [insert]: {1}'.format(self._name, err)))
    
    def pop(self):
        """Pop the last value of the array wrapped within the its template
        
        Args:
            None
        
        Returns:
            elt (Element) : last element of the instance
        """
        if self._SAFE_STAT and self._num is not None and len(self._val) == self._num:
            raise(EltErr('{0} [pop] val length {1} underflow (num {2})'\
                  .format(self._name, len(self._val)-1, self._num)))
        try:
            val = self._val.pop()
        except Exception as err:
            raise(EltErr('{0} [pop]: {1}'.format(self._name, err)))
        else:
            clone = self._tmpl.clone()
            clone._val = val
            return clone
    
    def remove(self, val):
        """Remove the first iteration of value `val' in the array's value
        
        Args:
            val (depends of self._tmpl) : value to be removed
        
        Returns:
            None
        
        Raises:
            EltErr : if value `val' is not in {0}
        """
        if self._SAFE_STAT and self._num is not None and len(self._val) == self._num:
            raise(EltErr('{0} [remove] val length {1} underflow (num {2})'\
                  .format(self._name, len(self._val)-1, self._num)))
        try:
            self._val.remove(val)
        except Exception as err:
            raise(EltErr('{0} [remove]: {1}'.format(self._name, err)))
    
    def replace(self, old, new):
        """Replace the value `old' with the value `new' in the array's value
        
        Args:
            old (depends of self._tmpl) : value to be removed
            new (depends of self._tmpl) : value to be inserted
        
        Returns:
            None
        
        Raises:
            EltErr : if element `old' is not in self._val
        """
        try:
            ind = self._val.index(old)
        except Exception as err:
            raise(EltErr('{0} [replace] invalid old: {1}'.format(self._name, err)))
        # use the template to format the value
        if new != self._tmpl_val:
            self._tmpl.set_val(new)
            new = self._tmpl()
            self._tmpl.set_val(None)
        del self._val[ind]
        self._val.insert(ind, new)
    
    def clear(self):
        """Clear the values of self
        
        Args:
            None
        
        Returns:
            None
        """
        if python_version < 3:
            del self._val[:]
        else:
            self._val.clear()
    
    def __iter__(self):
        self._it_saved.append(self._it)
        self._it = 0
        return self
    
    def __next__(self):
        if self._it >= len(self._val) or self._tmpl.get_trans():
            if self._it_saved:
                # in case of nested iteration
                self._it = self._it_saved.pop() + 1
            raise(StopIteration())
        else:
            it = self._it
            self._it += 1
            clone = self._tmpl.clone()
            clone.set_val(self._val[it])
            clone._env = self
            return clone
    
    if python_version < 3:
        next = __next__
    
    def __getitem__(self, key):
        if isinstance(key, integer_types):
            try:
                val = self._val[key]
            except Exception as err:
                raise(EltErr('{0} [__getitem__] int item: {1}'\
                      .format(self._name, err)))
            clone = self._tmpl.clone()
            clone.set_val(val)
            return clone
        elif isinstance(key, slice):
            try:
                val = self._val[key]
            except Exception as err:
                raise(EltErr('{0} [__getitem__] slice item: {1}'\
                      .format(self._name, err)))
            slice_env = Array('slice', GEN=self._tmpl.clone())
            slice_env.set_val(val)
            return slice_env
        else:
            raise(EltErr('{0} [__getitem__]: array item must be int or slice'.format(self._name)))
    
    def __setitem__(self, key, val):
        if isinstance(key, integer_types):
            if val != self._tmpl_val:
                self._tmpl.set_val(val)
                val = self._tmpl()
                self._tmpl.set_val(None)
            try:
                self._val[key] = val
            except Exception as err:
                raise(EltErr('{0} [__setitem__] int item: {1}'\
                      .format(self._name, err)))
        elif isinstance(key, slice):
            for i, k in enumerate(key):
                try:
                    self.__setitem__(k, val[i])
                except Exception as err:
                    raise(EltErr('{0} [__setitem__] slice item: {1}'\
                          .format(self._name, err)))
        else:
            raise(EltErr('{0} [__setitem__]: array item must be int or slice'.format(self._name)))
    
    def __delitem__(self, key):
        if self._SAFE_STAT and self._num is not None and len(self._val) == self._num:
            raise(EltErr('{0} [__delitem__] val length {1} underflow (num {2})'\
                  .format(self._name, len(self._val)-1, self._num)))
        if isinstance(key, integer_types):
            try:
                del self._val[key]
            except Exception as err:
                raise(EltErr('{0} [__delitem__] int item: {1}'.format(self._name, err)))
        elif isinstance(key, slice):
            try:
                del self._val[key]
            except Exception as err:
                raise(EltErr('{0} [__delitem__] slice item: {1}'.format(self._name, err)))
        else:
            raise(EltErr('{0} [__delitem__]: array item indices must be int or slice'\
                  .format(self._name)))
    
    #--------------------------------------------------------------------------#
    # representation routines
    #--------------------------------------------------------------------------#
    
    def repr(self):
        # element transparency
        if self.get_trans():
            trans = ' [transparent]'
        else:
            trans = ''
        # additional description
        if self._desc:
            desc = ' [%s]' % self._desc
        else:
            desc = ''
        #
        return '<%s%s%s : %s>' % \
               (self._name, desc, trans, ''.join(map(repr, self.__iter__())))
    
    def show(self):
        # element transparency
        if self.get_trans():
            trans = ' [transparent]'
        else:
            trans = ''
        # additional description
        if self._desc:
            desc = ' [%s]' % self._desc
        else:
            desc = ''
        #
        return '\n '.join(
            [self.get_hier_abs()*'    ' + '### %s%s%s ###' % (self._name, desc, trans)] + \
            [elt.show().replace('\n', '\n ') for elt in self.__iter__()])
    
    #--------------------------------------------------------------------------#
    # Python built-ins override
    #--------------------------------------------------------------------------#
    
    __call__ = get_val
    __repr__ = repr
    #if python_implementation != 'PyPy':
        # PyPy iterator implementation lead to an infinite loop
        # __iter__() calls __len__(), but here, get_bl() calls __iter__()
    #    __len__ = get_bl
    
    #--------------------------------------------------------------------------#
    # json interface
    #--------------------------------------------------------------------------#
    
    if _with_json:
        
        def _from_jval(self, val):
            if not isinstance(val, list):
                raise(EltErr('{0} [_from_jval]: invalid format, {1!r}'.format(self._name, val)))
            # 1) determine the number of iteration of the template within the array
            if self._numauto is not None:
                num = self._numauto()
                if self._SAFE_DYN and not isinstance(num, integer_types):
                    raise(EltErr('{0} [_from_jval]: num type produced is {1}, expecting integer'\
                          .format(self._name, type(num).__name__)))
            elif self._num is not None:
                num = self._num
            else:
                # num is None, from_json will consume the txt until it raises
                num = None
            # 2) init value
            self._val = []
            # 3) consume val
            if num is not None and len(val) != num:
                raise(EltErr('{0} [_from_jval]: invalid number of values: {1} instead of {2}'\
                      .format(self._name, len(val), num)))
            for v in val:
                self._tmpl._from_jval_wrap(v)
                self._val.append( self._tmpl.get_val() )
        
        def _to_jval(self):
            if self._SAFE_STAT and self._num is not None and len(self._val) != self._num:
                raise(EltErr('{0} [_to_jval] invalid number of values: {1} instead of {2}'\
                      .format(self._name, len(self._val), self._num)))
            ret = []
            for v in self._val:
                self._tmpl.set_val(v)
                ret.append( self._tmpl._to_jval_wrap() )
            return ret


class Sequence(Element):
    """
    Class for sequences: special element which acts as a container for a list of
    instances cloned from a mutable template element (atom, envelope, array, 
    sequence, alt)
    
    class attribute:
    - GEN: element which is used to build the sequence template at initialization
    
    universal attributes:
    - tmpl: element, cloned from the GEN, used as proxy for generating a
    sequence of clones into content, also used as default value
    - content: list of elements
    - num: number of iteration of elements within the content
    - trans: bool, transparency of the sequence
    - hier: hierarchical level when placed within an envelope
    
    automation attribute:
    - numauto: callable, to automate the determination of the number of content's 
    iteration
    - blauto: callable, to automate the length in bits to be decoded
    - transauto: callable, to automate the determination of sequence's 
    transparency
    
    contextual attributes:
    - env: envelope, container of the sequence
    
    Sequence provides methods identical to Python list and dict in order to 
    manage Element's instances within its content easily
    
    Warning: transparency of certain elements within the Sequence's content is not
    handled. Elements within the content must not be made transparent (e.g. with 
    set_trans()), but must be remove()d instead.
    """
    
    # hardcoded class name
    CLASS = 'Sequence'
    
    # default transparency
    DEFAULT_TRANS = False
    
    # default attributes value
    _env       = None
    _hier      = 0
    _desc      = ''
    _trans     = None
    _transauto = None
    _num       = None
    _numauto   = None
    _blauto    = None
    _GEN       = Atom()
    
    __attrs__ = ('_env',
                 '_name',
                 '_desc',
                 '_hier',
                 '_trans',
                 '_transauto',
                 '_num',
                 '_numauto',
                 '_blauto',
                 '_tmpl',
                 '_content',
                 '_it',
                 '_it_saved')
    
    
    def __init__(self, *args, **kw):
        """Initializes an instance of Sequence
        
        Args:
            *args: nothing or instance name (str)
            **kw:
                name (str): sequence name if no args
                desc (str): additional sequence description
                hier (int): sequence hierarchy level
                trans (bool): sequence transparency
                GEN (element): to override the GEN class attribute
                tmpl_val (element's value): to set a default value for the 
                    template generated from GEN
                tmpl_bl (element's bl): to set default bit length for the 
                    template generated from GEN
                num (int): number of iteration within the sequence content
                val (None, tuple, list or dict): values to be set in the sequence
        """
        # iterator index initialization
        # current iterator index:
        self._it = 0
        # saved iterator indexes, when nested iterations happen
        self._it_saved = [] 
        
        # sequence envelope
        self._env = None
        
        # sequence name in kw, or first args
        if len(args):
            self._name = str(args[0])
        elif 'name' in kw:
            self._name = str(kw['name'])
        # if not provided, it's the class name
        elif not hasattr(self, '_name'):
            self._name = self.__class__.__name__
        
        # sequence description customization
        if 'desc' in kw:
            self._desc = str(kw['desc'])
        
        # sequence hierarchy
        if 'hier' in kw:
            self.set_hier(kw['hier'])
        
        # sequence transparency
        if 'trans' in kw:
            self.set_trans(kw['trans'])
        
        if 'GEN' in kw:
            GEN, clo = kw['GEN'], False
        else:
            GEN, clo = self._GEN, True
        
        # verifying sequence generator
        if self._SAFE_STAT:
            self._chk_hier()
            self._chk_trans()
            if not isinstance(GEN, Element):
                raise(EltErr('{0} [__init__]: invalid sequence generator GEN'\
                      .format(self._name)))
        
        if clo:
            self._tmpl = GEN.clone()
        else:
            self._tmpl = GEN
        self._tmpl._env = self
        
        if 'tmpl_val' in kw:
            try:
                self._tmpl.set_val(kw['tmpl_val'])
            except Exception:
                raise(EltErr('{0} [__init__] set template value error: {1}'\
                      .format(self._name, err)))
        
        if 'tmpl_bl' in kw:
            try:
                self._tmpl.set_bl(kw['tmpl_bl'])
            except Exception:
                raise(EltErr('{0} [__init__] set template bl error: {1}'\
                      .format(self._name, err)))
        
        # set default value, and values container
        self._content = []
        
        # sequence number of content
        if 'num' in kw:
            self.set_num(kw['num'])
        
        # values in the sequence
        if 'val' in kw:
            self.set_val(kw['val'])
    
    #--------------------------------------------------------------------------#
    # envelope, hierarchy and selection routines
    #--------------------------------------------------------------------------#
    # nothing changes from Element
    
    #--------------------------------------------------------------------------#
    # format routines
    #--------------------------------------------------------------------------#
    
    def set_val(self, vals):
        """Set a sequence of template clones with the given values
        
        Args:
            vals (None, tuple, list or dict) : list of values 
                or dict of element's index, element's value
        
        Returns:
            None
        
        Raises:
            EltErr : if element's index or value is invalid
        """
        #
        if vals is None:
            self._content = []
        #
        elif isinstance(vals, dict):
            max_ind = max(vals.keys())
            if self._SAFE_STAT:
                # ensure the val dict indexes are valid
                if not all([isinstance(k, integer_types) for k in vals]):
                    raise(EltErr('{0} [set_val] vals keys are not all integers'\
                          .format(self._name)))
                # ensure the max index does not overflow a fixed max size
                if self._num is not None and max_ind >= self._num:
                    raise(EltErr('{0} [set_val] vals index {1} overflow (max {2})'\
                          .format(self._name, max_ind, self._num)))
            # in case the current content self._content does not goes up to the max 
            # val dict index, just extend it with the template element
            if len(self._content) <= max_ind:
                self._content.extend( (1+max_ind-len(self._content)) * (self._tmpl, ) )
            # set values at given key indexes
            for i, v in vals.items():
                c = self._content[i]
                if c == self._tmpl:
                    # in case of tmpl, clone it before assigning the value
                    c = c.clone()
                    c._env = self
                    self._content[i] = c
                c.set_val(v)
        #
        elif isinstance(vals, (tuple, list)):
            if self._SAFE_STAT and self._num is not None and len(vals) > self._num:
                # ensure vals length does not overflow a fixed number of iteration
                raise(EltErr('{0} [set_val] invalid number of values: {1} instead of {2}'\
                      .format(self._name, len(vals), self._num)))
            # in case the current content self._content does not goes up to the max 
            # val dict index, just extend it with the template element
            if len(self._content) < len(vals):
                self._content.extend( (len(vals)-len(self._content)) * (self._tmpl, ) )
            for i, v in enumerate(vals):
                c = self._content[i]
                if c == self._tmpl:
                    # in case of tmpl, clone it before assigning the value
                    c = c.clone()
                    c._env = self
                    self._content[i] = c
                c.set_val(v)
        #
        else:
            raise(EltErr('{0} [set_val]: vals type is {1}, expecting None, tuple, list or dict'\
                  .format(self._name, type(vals).__name__)))
    
    def get_val(self):
        """Returns the list of values of self
        
        Args:
            None
        
        Returns:
            value (list) : list of values computed
        """
        return [elt() for elt in self._content]  
    
    def get_val_d(self):
        """Returns the list of values obtained with get_val_d() from the content of self
        Wanrning: in case several elements have the same name, the returned value 
        won't be complete.
        
        Args:
            None
        
        Returns:
            value (list) : list of values obtained with get_val_d()
        
        Raises:
            EltErr : if one element within the content raises
        """
        return [elt.get_val_d() for elt in self._content]
    
    def set_num(self, num=None):
        """Set the raw number of iteration of the template in the sequence's 
        content
        
        Args:
            num (int) : raw number of iteration, default to None
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and bitlen is not integer
        """
        if num is None:
            try:
                del self._num
            except Exception:
                pass
        else:
            if self._SAFE_STAT and not isinstance(num, integer_types):
                raise(EltErr('{0} [set_num]: num type is {1}, expecting integer'\
                      .format(self._name, type(num).__name__)))
            self._num = num
            # clean up extra content if already set
            if len(self._content) > num:
                del self._content[num:]
            # extend content if not already set
            elif len(self._content) < num:
                self._content.extend( (num-len(self._content)) * (self._tmpl, ) )
    
    def set_numauto(self, numauto=None):
        """Set an automation for the number of iteration of the template in the
        sequence's content, used only when mapping an external buffer to self
        
        Args:
            numauto (callable) : automate the num computation, call numauto() 
                to compute num, default to None
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and numauto is not a
                callable
        """
        if numauto is None:
            try:
                del self._numauto
            except Exception:
                pass
        else:
            if self._SAFE_STAT and not callable(numauto):
                raise(EltErr('{0} [set_numauto]: numauto type is {1}, expecting callable'\
                      .format(self._name, type(numauto).__name__)))
            self._numauto = numauto
    
    def get_num(self):
        """Returns the number of iterations of the template in the sequence's
        content
        
        Args:
            None
        
        Returns:
            num (int) : number of elements, default to the number of values
        """
        # follow the value resolution order:
        # 1) raw num
        if self._num is not None:
            return self._num
        
        # 2) num automation: only when parsing buffers (in _from_char)
        # see _from_char()
        
        # 3) no num defined, return the num from the content already set
        else:
            return len(self._content)
    
    def set_blauto(self, blauto=None):
        """Set an automation for the length in bits of self, used only when 
        mapping an external buffer to it.
        
        Args:
            blauto (callable) : automate the bl computation,
                call blauto() to compute the bit length, default to None
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and blauto is not a callable
        """
        if blauto is None:
            try:
                del self._blauto
            except Exception:
                pass
        else:
            if self._SAFE_STAT and not callable(blauto):
                raise(EltErr('{0} [set_blauto]: blauto type is {1}, expecting callable'\
                      .format(self._name, type(blauto).__name__)))
            self._blauto = blauto
    
    def get_bl(self):
        """Returns the length in bits of self
        
        Args:
            None
        
        Returns:
            bl (int) : length in bits computed
        
        Raises:

            EltErr : if one element within the content raises
        """
        if self.get_trans():
            return 0
        else:
            return sum([elt.get_bl() for elt in self._content])
    
    def reautomate(self):
        """Reset all attributes of self, its content and its template which have 
        an automation 
        
        Args:
            None
        
        Returns:
            None
        """
        if self._transauto is not None and self._trans is not None:
            del self._trans
        if self._numauto is not None and self._num is not None:
            del self._num
        [elt.reautomate() for elt in self._content if elt != self._tmpl]
        self._tmpl.reautomate()
    
    #--------------------------------------------------------------------------#
    # conversion routines
    #--------------------------------------------------------------------------#
    
    def _to_pack(self):
        """Produces a list of tuple ready to be packed with pack_val() from the
        sequence's content
        """
        if not self.get_trans():
            if self._SAFE_STAT and self._num is not None and len(self._content) != self._num:
                raise(EltErr('{0} [_to_pack]: invalid number of repeated content: {1} instead of {2}'\
                      .format(self._name, len(self._content), self._num)))
            pl = []
            [pl.extend(elt._to_pack()) for elt in self._content]
            return pl
        else:
            return []
    
    def _from_char(self, char):
        """Dispatch the consumption of a Charpy intance to the elements within
        the sequence's content
        """
        if self.get_trans():
            return
        # 1) determine the number of iteration of the template within the sequence
        if self._numauto is not None:
            num = self._numauto()
            if self._SAFE_DYN and not isinstance(num, integer_types):
                raise(EltErr('{0} [_from_char]: num type produced is {1}, expecting integer'\
                      .format(self._name, type(num).__name__)))
        elif self._num is not None:
            num = self._num
        else:
            # num is None, _from_char will consume the charpy instance until
            # it raises
            num = None
        # 2) truncate char if length automation is set
        if self._blauto is not None:
            char_lb = char._len_bit
            char._len_bit = char._cur + self._blauto()
            if char._len_bit > char_lb:
                raise(EltErr('{0} [_from_char]: bit length overflow'.format(self._name)))
        # 3) init content
        self._content = []
        # 4) consume char and fill in self._content
        if num is not None:
            for i in range(num):
                clone = self._tmpl.clone()
                clone._env = self
                clone._from_char(char)
                self._content.append(clone)
        else:
            # there is no predefined limit in the number of repeated content
            # consume the charpy instance until its empty and raises
            while True:
                # remember charpy cursor position, to restore it when it raises
                cur = char._cur
                clone = self._tmpl.clone()
                clone._env = self
                try:
                    clone._from_char(char)
                except CharpyErr:
                    char._cur = cur
                    break
                else:
                    self._content.append(clone)
        # 5) in case of length automation, set the original length back
        if self._blauto is not None:
            char._len_bit = char_lb
    
    #--------------------------------------------------------------------------#
    # copy / cloning routines
    #--------------------------------------------------------------------------#
    
    def get_attrs(self):
        """Returns the dictionnary of universal attributes of self, its template
        and content
        
        Args:
            None
        
        Returns:
            attr (dict) : dictionnary of attributes
        """
        return {'name'   : self._name,
                'desc'   : self._desc,
                'hier'   : self._hier,
                'trans'  : self._trans,
                'num'    : self._num,
                'tmpl'   : self._tmpl.get_attrs(),
                'content': [elt.get_attrs() for elt in self._content]}
    
    def get_attrs_all(self):
        """Returns the dictionnary of all attributes of self, its content 
        template and its values
        
        Args:
            None
        
        Returns:
            attr (dict) : dictionnary of attributes
        """
        
        return {'env'      : self._env,
                'name'     : self._name,
                'desc'     : self._desc,
                'hier'     : self._hier,
                'trans'    : self._trans,
                'transauto': self._transauto,
                'num'      : self._num,
                'numauto'  : self._numauto,
                'tmpl'     : self._tmpl.get_attrs_all(),
                'content'  : [elt.get_attrs_all() for elt in self._content]}
    
    def set_attrs(self, **kw):
        """Updates the attributes of self, its template and its content
        
        Args:
            kw (dict): dict of attributes and associated values
                attributes can be name, desc, hier, trans, tmpl, val and num

        Returns:
            None
        """
        if 'name' in kw and isinstance(kw['name'], str):
            self._name = kw['name']
        if 'desc' in kw and isinstance(kw['desc'], str) and kw['desc'] != self.__class__._desc:
            self._desc = str(kw['desc'])
        if 'hier' in kw and kw['hier'] != self.__class__._hier:
            self._hier = kw['hier']
        if 'trans' in kw and kw['trans'] != self.__class__._trans:
            self._trans = kw['trans']
        #
        if self._SAFE_STAT:
            self._chk_hier()
            self._chk_trans()
        #
        if 'tmpl' in kw:
            try:
                self._tmpl.set_attrs(**kw['tmpl'])
            except Exception as err:
                raise(EltErr('{0} [set_attrs] invalid tmpl: {1}'.format(self._name, err)))
        #
        if 'val' in kw:
            self.set_val(kw['val'])
        if 'num' in kw:
            self.set_num(kw['num'])
    
    def clone(self):
        """Produces an independent clone of self
        
        Args:
            None
        
        Returns:
            clone (self.__class__ instance)
        """
        kw = {}
        if self._desc != self.__class__._desc:
            kw['desc'] = self._desc
        if self._hier != self.__class__._hier:
            kw['hier'] = self._hier
        if self._trans != self.__class__._trans:
            kw['trans'] = self._trans
        if self._num != self.__class__._num:
            kw['num'] = self._num
        
        # substitute the sequence generator with the current sequence's template
        kw['GEN'] = self._tmpl.clone()
        clone = self.__class__(self._name, **kw)
        # clone all elements within the content
        clone._content = [elt.clone() for elt in self._content]
        [elt.set_env(clone) for elt in clone._content]
        return clone
    
    #--------------------------------------------------------------------------#
    # Python list / dict methods emulation
    #--------------------------------------------------------------------------#
    
    def append(self, elt):
        """Append the element `elt' at the end of the sequence's content
        
        Args:
            elt (element) : element to be appended
        
        Returns:
            None
        
        Raises:
            EltErr
        """
        if self._SAFE_STAT:
            if not isinstance(elt, Element):
                raise(EltErr('{0} [append]: elt type is {1}, expecting element'\
                             .format(self._name, type(elt).__name__)))
            if self._num is not None and len(self._content) == self._num:
                raise(EltErr('{0} [append]: content length {1} overflow (max {2})'\
                             .format(self._name, 1+len(self._content), self._num)))
        #
        self._content.append(elt)
        elt._env = self
    
    # here, .count() is the number of iteration in the sequence
    count = get_num
    
    def extend(self, elts):
        """Append the list of elements `elts' at the end of sequence's content
        
        Args:
            elts (list) : iterable of elements to be appended
        
        Returns:
            None
        
        Raises:
            EltErr
        """
        if self._SAFE_STAT:
            if not all([isinstance(elt, Element) for elt in elts]):
                raise(EltErr('{0} [extend]: elts type must be element'.format(self._name))) 
            elif self._num is not None and len(elts) > (self._num-len(self._content)):
                raise(EltErr('{0} [extend]: content length {1} overflow (max {2})'\
                      .format(self._name, len(elts)+len(self._content), self._num)))
        #
        self._content.extend(elts)
        [elt.set_env(self) for elt in elts]
    
    def index(self, elt):
        """Provide the index of the element `elt' within the sequence's content
        
        Args:
            elt (element) : element to get the index of
        
        Returns:
            ind (int) : index of the element within the sequence
        
        Raises:
            EltErr : if `elt' is not in self._content
        """
        try:
            return self._content.index(elt)
        except Exception as err:
            raise(EltErr('{0} [index]: {1}'.format(self._name, err)))
    
    def insert(self, index, elt):
        """Insert the element `elt' at the given index in sequence's content
        
        Args:
            index (int) : index where to insert `elt'
            elt (element) : element to be inserted
        
        Returns:
            None
        
        Raises:
            EltErr : if `elt' is not an element or
                if insertion at the given index fails
        """
        if self._SAFE_STAT:
            if not isinstance(elt, Element):
                raise(EltErr('{0} [insert]: elt type is {1}, expecting element'\
                      .format(self._name, type(elt).__name__)))
            if self._num is not None and len(self._content) == self._num:
                raise(EltErr('{0} [insert]: content length {1} overflow (max {2})'\
                      .format(self._name, 1+len(self._content), self._num)))
        try:
            self._content.insert(index, elt)
        except Exception as err:
            raise(EltErr('{0} [insert]: {1}'.format(self._name, err)))
        else:
            elt._env = self
    
    def pop(self):
        """Pop the last element of sequence's content
        
        Args:
            None
        
        Returns:
            elt (Element) : last element of the instance
        
        Raises:
            EltErr : if no element are already set in self
        """
        if self._SAFE_STAT and self._num is not None and len(self._content) == self._num:
            raise(EltErr('{0} [pop] content length {1} underflow (num {2})'\
                  .format(self._name, len(self._content)-1, self._num)))
        try:
            elt = self._content.pop()
        except Exception as err:
            raise(EltErr('{0} [pop]: {1}'.format(self._name, err)))
        else:
            if elt == self._tmpl:
                return elt.clone()
            else:
                elt._env = None
                return elt
    
    def remove(self, elt):
        """Remove the element `elt' from the sequence's content
        
        Args:
            elt (element) : element to be removed
        
        Returns:
            None
        
        Raises:
            EltErr : if `elt' is not in self
        """
        if self._SAFE_STAT and self._num is not None and len(self._content) == self._num:
            raise(EltErr('{0} [remove] content length {1} underflow (num {2})'\
                  .format(self._name, len(self._content)-1, self._num)))
        try:
            self._content.remove(elt)
        except Exception as err:
            raise(EltErr('{0} [remove]: {1}'.format(self._name, err)))
        else:
            if elt != self._tmpl:
                elt._env = None
    
    def replace(self, old, new):
        """Replace the element `old' with the element `new' in the sequence's 
        content
        
        Args:
            old (element) : element to be removed,
                alternatively, old can be the element's index (int)
            new (element) : element to be inserted
        
        Returns:
            None
        
        Raises:
            EltErr : if element `old' is not in self or
                if `new' is not an element
        """.format(self.__class__.__name__)
        if isinstance(old, Elt):
            try:
                ind = self._content.index(old)
            except Exception as err:
                raise(EltErr('{0} [replace] invalid old: {1}'.format(self._name, err)))
        elif isinstance(old, integer_types):
            ind = old
            try:
                old = self._content[ind]
            except Exception:
                raise(EltErr('{0} [replace] invalid old index: {1}'.format(self._name, ind)))
        elif self._SAFE_STAT:
            raise(EltErr('{0} [replace]: elt type is {1}, expecting element or index'\
                         .format(self._name, type(elt).__name__)))
        del self._content[ind]
        if old != self._tmpl:
            old._env = None
        self._content.insert(ind, new)
        new._env = self
    
    def clear(self):
        """Clear the content of self
        
        Args:
            None
        
        Returns:
            None
        """
        if python_version < 3:
            del self._content[:]
        else:
            self._content.clear()
    
    def __iter__(self):
        self._it_saved.append(self._it)
        self._it = 0
        return self
    
    def __next__(self):
        if self._it >= len(self._content) or self._tmpl.get_trans():
            if self._it_saved:
                # in case of nested iteration
                self._it = self._it_saved.pop() + 1
            raise(StopIteration())
        else:
            it = self._it
            self._it += 1
            if self.ENV_SEL_TRANS:
                # do not take element transparency into account
                return self._content[it]
            elif not self._content[it].get_trans():
                # non-transparent element
                return self._content[it]
            else:
                # transparent element, pass it and try the next one
                return self.__next__()
    
    if python_version < 3:
        next = __next__
    
    def __getitem__(self, key):
        if isinstance(key, integer_types):
            try:
                return self._content[key]
            except Exception as err:
                raise(EltErr('{0} [__getitem__] int item: {1}'.format(self._name, err)))
        elif isinstance(key, slice):
            slice_env = Sequence('slice', GEN=self._tmpl.clone())
            try:
                slice_env._content = self._content[key]
            except Exception as err:
                raise(EltErr('{0} [__getitem__] slice item: {1}'.format(self._name, err)))
            return slice_env
        else:
            raise(EltErr('{0} [__getitem__]: sequence item must be int or slice'\
                  .format(self._name)))
    
    def __setitem__(self, key, val):
        if isinstance(key, integer_types):
            try:
                elt = self._content[key]
            except Exception as err:
                raise(EltErr('{0} [__setitem__] int item: {1}'.format(self._name, err)))
            if elt == self._tmpl:
                self._content[key] = self._tmpl.clone()
            self._content[key].set_val(val)
        elif isinstance(key, slice):
            for i, k in enumerate(key):
                try:
                    self.__setitem__(k, val[i])
                except Exception as err:
                    raise(EltErr('{0} [__setitem__] slice item: {1}'\
                          .format(self._name, err)))
        else:
            raise(EltErr('{0} [__setitem__]: sequence item must be int or slice'\
                  .format(self._name)))
    
    def __delitem__(self, key):
        if self._SAFE_STAT and self._num is not None and len(self._content) == self._num:
            raise(EltErr('{0} [__delitem__] content length {1} underflow (num {2})'\
                  .format(self._name, len(self._content), self._num)))
        if isinstance(key, integer_types):
            try:
                elt = self._content[key]
            except Exception as err:
                raise(EltErr('{0} [__delitem__] int item: {1}'.format(self._name, err)))
            del self._content[key]
            if elt != self._tmpl:
                elt._env = None
        elif isinstance(key, slice):
            try:
                elts = self._content[key]
            except Exception as err:
                raise(EltErr('{0} [__delitem__] slice item: {1}'.format(self._name, err)))
            del self._content[key]
            [elt.set_env(None) for elt in elts if elt != self._tmpl]
        else:
            raise(EltErr('{0} [__delitem__]: sequence item must be int or slice'\
                  .format(self._name)))
    
    #--------------------------------------------------------------------------#
    # representation routines
    #--------------------------------------------------------------------------#
    
    def repr(self):
        # element transparency
        if self.get_trans():
            trans = ' [transparent]'
        else:
            trans = ''
        # additional description
        if self._desc:
            desc = ' [%s]' % self._desc
        else:
            desc = ''
        #
        return '<%s%s%s : %s>' % \
               (self._name, desc, trans, ''.join(map(repr, self._content)))
    
    def show(self):
        # element transparency
        if self.get_trans():
            trans = ' [transparent]'
        else:
            trans = ''
        # additional description
        if self._desc:
            desc = ' [%s]' % self._desc
        else:
            desc = ''
        #
        return '\n '.join( 
            [self.get_hier_abs()*'    ' + '### %s%s%s ###' % (self._name, desc, trans)] + \
            [elt.show().replace('\n', '\n ') for elt in self._content])
    
    #--------------------------------------------------------------------------#
    # Python built-ins override
    #--------------------------------------------------------------------------#
    
    __call__ = get_val
    __repr__ = repr
    #if python_implementation != 'PyPy':
        # PyPy iterator implementation lead to an infinite loop
        # __iter__() calls __len__(), but here, get_bl() calls __iter__()
    #    __len__ = get_bl
    
    #--------------------------------------------------------------------------#
    # json interface
    #--------------------------------------------------------------------------#
    
    if _with_json:
        
        def _from_jval(self, val):
            if not isinstance(val, list):
                raise(EltErr('{0} [_from_jval]: invalid format, {1!r}'.format(self._name, val)))
            # 1) determine the number of iteration of the template within the array
            if self._numauto is not None:
                num = self._numauto()
                if self._SAFE_DYN and not isinstance(num, integer_types):
                    raise(EltErr('{0} [_from_jval]: num type produced is {1}, expecting integer'\
                          .format(self._name, type(num).__name__)))
            elif self._num is not None:
                num = self._num
            else:
                # num is None, from_json will consume the txt until it raises
                num = None
            # 2) consume txt and fill in self._content
            if num is not None and len(val) != num:
                raise(EltErr('{0} [_from_jval]: invalid number of values: {1} instead of {2}'\
                      .format(self._name, len(val), num)))
            # trying to keep potential mutated tmpl from the existing content
            if len(self._content) < len(val):
                while len(self._content) < len(val):
                    clone = self._tmpl.clone()
                    self._content.append(clone)
                    clone._env = self
            elif len(self._content) > len(val):
                del self._content[len(val):]
            for i, v in enumerate(val):
                self._content[i]._from_jval_wrap(v)
        
        def _to_jval(self):
            if self._SAFE_STAT and self._num is not None and len(self._content) != self._num:
                raise(EltErr('{0} [_to_jval]: invalid number of repeated content: {1} instead of {2}'\
                      .format(self._name, len(self._content), self._num))) 
            return [e._to_jval_wrap() for e in self._content if not e.get_trans()]


class Alt(Element):
    """
    Class for alternatives: special element which acts as a container for a list of
    alternatives between several elements (atom, envelope, array, sequence, alt)
    
    class attribute:
    - GEN: dict of elements which is used to build all alternatives content at 
    initialization, keys are values that must correspond to the selector element
    
    universal attributes:
    - sel: selector callback to get the value which is used to select one of the 
    alternatives
    - content: dict of selector values and elements cloned from the GEN dict
    - trans: bool, transparency of the alternative
    - hier: hierarchical level when placed in an envelope
    
    automation attribute:
    - transauto: callable, to automate the determination of alternative's 
    transparency
    
    contextual attributes:
    - env: envelope, container of the current alternative
    
    Alt provides methods identical to Python list and dict in order to 
    manage elements within its content easily
    """
    
    # hardcoded class name
    CLASS = 'Alt'
    
    # explicit representation behaviour
    # if True, returns an explicit representation of the alternative including
    # its selection value
    # otherwise, returns directly the representation of the selected alternative
    REPR_EXPL = True
    
    # default transparency
    DEFAULT_TRANS = False
    
    # default element in case of invalid selection value
    # if set to None, each invalid selection will raise an EltErr
    DEFAULT = Envelope('none')
    
    # default attributes value
    _env       = None
    _hier      = 0
    _desc      = ''
    _blauto    = None
    _trans     = None
    _transauto = None
    _GEN       = {}
    _sel       = lambda a, b: None
    
    # Warning:
    # When setting the selection callback as class attribute _sel, prototype is
    # lambda a, b: ..., both a & b being self, when instantiated
    # When setting the selection callback during / after initialization, prototype is
    # lambda a: ..., a being self
    
    __attrs__ = ('_env',
                 '_name',
                 '_desc',
                 '_hier',
                 '_blauto',
                 '_trans',
                 '_transauto',
                 '_GEN',
                 '_sel',
                 '_content')
    
    def __init__(self, *args, **kw):
        """Initializes an instance of Alt
        
        Args:
            *args: nothing or alt name (str)
            **kw:
                name (str): alt name if no args
                desc (str): additional alt description
                hier (int): alt hierarchy level
                trans (bool): alt transparency
                GEN (dict of key, elements): to override the GEN class attribute
                sel (cb): callable to automate the alternative selection
                    warning: this cb must always have a single argument which 
                             is self
                val (None, dict, tuple or list): to broadcast values into the
                    element selected within the content, using self.set_val()
                bl (tuple, list or dict): to broadcast bl into the element 
                    selected within the content, using self.set_bl()
        """
        # alt name in kw, or first args
        if len(args):
            self._name = str(args[0])
        elif 'name' in kw:
            self._name = str(kw['name'])
        # if not provided, it's the class name
        elif not hasattr(self, '_name'):
            self._name = self.__class__.__name__
        
        # alt description customization
        if 'desc' in kw:
            self._desc = str(kw['desc'])
        
        # alt hierarchy
        if 'hier' in kw:
            self._hier = kw['hier']
        
        # alt transparency
        if 'trans' in kw:
            self._trans = kw['trans']
        
        if 'GEN' in kw:
            self._GEN = kw['GEN']
        
        # default alternative
        if 'DEFAULT' in kw:
            self.DEFAULT = kw['DEFAULT']
        elif self.__class__.DEFAULT:
            self.DEFAULT = self.__class__.DEFAULT.clone()
        
        if self._SAFE_STAT:
            self._chk_hier()
            self._chk_trans()
            self._chk_gen(self._GEN)
            if self.DEFAULT is not None and \
            not isinstance(self.DEFAULT, Element):
                raise(EltErr('{0} [__init__]: invalid DEFAULT element'\
                      .format(self._name)))
        
        # content is populated with clones from GEN in a lazy way
        # through calling get_alt()
        self._content = {}
        
        # alternative selection callback
        if 'sel' in kw:
            self.set_sel( kw['sel'] )
        
        # if a val dict is passed as argument
        # broadcast it to given content items
        if 'val' in kw:
            self.set_val( kw['val'] )
        
        # if a bl dict is passed as argument
        # broadcast it to given content items
        if 'bl' in kw:
            self.set_bl( kw['bl'] )
    
    def _chk_gen(self, gen):
        if not isinstance(gen, dict) or \
        not all([isinstance(elt, Element) for elt in gen.values()]):
            raise(EltErr('{0} [_chk_gen]: invalid alt generator or content'\
                  .format(self._name)))
    
    #--------------------------------------------------------------------------#
    # envelope, hierarchy and selection routines
    #--------------------------------------------------------------------------#
    # no change from Element
    
    #--------------------------------------------------------------------------#
    # format routines
    #--------------------------------------------------------------------------#
    
    def set_sel(self, cb):
        """Sets the alternative selection automation for self
        
        Args:
            cb (callable) : automate the alternative selection
        
        Returns:
            None
        
        Raises:
            EltErr : is self._SAFE_STAT enabled and cb is not a callable
        """
        if self._SAFE_STAT and not callable(cb):
            raise(EltErr('{0} [set_sel]: cb type is {1}, expecting callable'\
                  .format(self._name, type(cb).__name__)))
        self._sel = cb
    
    def get_sel(self):
        """Gets the key corresponding to the alternative to be selected 
        """
        try:
            return self._sel(self)
        except Exception:
            return None
    
    def get_alt(self):
        """Gets the selected alternative
        
        Args:
            None
        
        Returns:
            elt : selected alternative element
        
        Raises:
            EltErr : if the selection value is invalid and no DEFAULT is set
        """
        sv = self.get_sel()
        if sv in self._content:
            elt = self._content[sv]
            elt.set_env(self.get_env())
            return elt
        elif sv in self._GEN:
            elt = self._GEN[sv].clone()
            self.insert(sv, elt)
            return elt
        elif self.DEFAULT is not None:
            self.DEFAULT.set_env(self.get_env())
            return self.DEFAULT
        else:
            raise(EltErr('{0} [set_val]: invalid selection value {1!r}'\
                  .format(self._name, sv)))
    
    def set_blauto(self, blauto=None):
        """Set an automation for the length in bits of self, used only when 
        mapping an external buffer to it.
        
        Args:
            blauto (callable) : automate the bl computation,
                call blauto() to compute the bit length, default to None
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and blauto is not a callable
        """
        if blauto is None:
            try:
                del self._blauto
            except Exception:
                pass
        else:
            if self._SAFE_STAT and not callable(blauto):
                raise(EltErr('{0} [set_blauto]: blauto type is {1}, expecting callable'\
                      .format(self._name, type(blauto).__name__)))
            self._blauto = blauto
    
    # standard methods passthrough
    def set_val(self, val=None):
        self.get_alt().set_val(val)
    
    def _chk_val(self, *args):
        self.get_alt()._chk_val(*args)
    
    #def set_valauto(self, valauto=None):
    #    self.get_alt().set_valauto(valauto)
    
    def get_val(self):
        return self.get_alt().get_val()
    
    # for alt element, no dict to be returned, but just the standard list of values
    def get_val_d(self):
        alt = self.get_alt()
        if isinstance(alt, Envelope):
            return alt.get_val_d()
        else:
            return alt.get_val()
    
    def set_bl(self, bl=None):
        self.get_alt().set_bl(bl)
    
    def _chk_bl(self, *args):
        self.get_alt()._chk_bl(*args)
    
    #def set_blauto(self, blauto=None):
    #    self.get_alt().set_blauto(blauto)
    
    def set_len(self, l=None):
        self.get_alt().set_len(l)
    
    def _get_bl_from_val(self):
        return self.get_alt()._get_bl_from_val()
    
    def get_bl(self):
        return self.get_alt().get_bl()
    
    def set_dic(self, dic=None):
        self.get_alt().set_dic(dic)
    
    def _chk_dic(self, *args):
        self.get_alt()._chk_dic(*args)
    
    #def set_dicauto(self, dicauto=None):
    #    self.get_alt()._chk_dicauto(dicauto)
    
    def get_dic(self):
        return self.get_alt().get_dic()
    
    def get_val_dic(self):
        return self.get_alt().get_val_dic()
    
    def reautomate(self):
        """Resets all attributes of the element which have an automation within 
        the content of self
        
        Args:
            None
        
        Returns:
            None
        """
        if self._transauto is not None and self._trans is not None:
            del self._trans
        [elt.reautomate() for elt in self._content.values()]
    
    #--------------------------------------------------------------------------#
    # conversion routines
    #--------------------------------------------------------------------------#
    
    def _to_pack(self):
        """Produces a list of tuples (type, val, bl) ready to be packed with 
        pack_val()
        """
        if not self.get_trans():
            return self.get_alt()._to_pack()
        else:
            return []
    
    def _from_char(self, char):
        """Dispatch the consumption of a Charpy intance to the selected element 
        within the content
        """
        if not self.get_trans():
            # truncate char if length automation is set
            if self._blauto is not None:
                char_lb = char._len_bit
                char._len_bit = char._cur + self._blauto()
                if char._len_bit > char_lb:
                    raise(EltErr('{0} [_from_char]: bit length overflow'.format(self._name)))
            self.get_alt()._from_char(char)
            # in case of length automation, set the original length back
            if self._blauto is not None:
                char._len_bit = char_lb
    
    #--------------------------------------------------------------------------#
    # copy / cloning routines
    #--------------------------------------------------------------------------#
    
    def get_attrs(self):
        """Returns the dictionnary of universal attributes of self and the 
        elements within its content
        
        Args:
            None
        
        Returns:
            attrs (dict) : dictionnary of attributes
        """
        return {'name'   : self._name,
                'desc'   : self._desc,
                'hier'   : self._hier,
                'trans'  : self._trans,
                'content': {sv: elt.get_attrs() for (sv, elt) in self._content.items()}}
    
    def get_attrs_all(self):
        """Returns the dictionnary of all attributes of self and the elements 
        within its content
        
        Args:
            None
        
        Returns:
            attrs (dict) : dictionnary of attributes
        """
        return {'env'      : self._env,
                'name'     : self._name,
                'desc'     : self._desc,
                'hier'     : self._hier,
                'trans'    : self._trans,
                'transauto': self._transauto,
                'sel'      : self._sel,
                'content'  : {sv: elt.get_attrs_all() for (sv, elt) in self._content.items()}}
    
    def set_attrs(self, **kw):
        """Updates the attributes of self and the elements within its content
        
        Args:
            kw (dict): dict of attributes and associated values
                attributes can be name, desc, hier, trans, bl, val and sel
        
        Returns:
            None
        """
        if 'name' in kw and isinstance(kw['name'], str):
            self._name = kw['name']
        if 'desc' in kw and isinstance(kw['desc'], str) and kw['desc'] != self.__class__._desc:
            self._desc = str(kw['desc'])
        if 'hier' in kw and kw['hier'] != self.__class__._hier:
            self._hier = kw['hier']
        if 'trans' in kw and kw['trans'] != self.__class__._trans:
            self._trans = kw['trans']
        #
        if self._SAFE_STAT:
            self._chk_hier()
            self._chk_trans()
        #
        if 'sel' in kw:
            self.set_sel(kw['sel'])
        if 'bl' in kw:
            self.set_bl(kw['bl'])
        if 'val' in kw:
            self.set_val(kw['val'])
    
    def clone(self):
        """Produces an independent clone of self
        
        Args:
            None
        
        Returns:
            clone (self.__class__ instance)
        """
        kw = {
            'GEN': self._GEN,
            'DEFAULT': self.DEFAULT.clone(),
            'sel': self._sel
            }
        if self._desc != self.__class__._desc:
            kw['desc'] = self._desc
        if self._hier != self.__class__._hier:
            kw['hier'] = self._hier
        if self._trans != self.__class__._trans:
            kw['trans'] = self._trans
        clone = self.__class__(self._name, **kw)
        clone.insert(self.get_sel(), self.get_alt().clone())
        return clone
    
    #--------------------------------------------------------------------------#
    # Python list / dict methods emulation
    #--------------------------------------------------------------------------#
    
    def update(self, elt_alt):
        """Updates the dict of alternatives element with the content of `elt_alt'
        
        Args:
            elt_alt (dict of {selection value: element}) : dict of alternatives
                to update self._content with
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and one of the alternative has
                an invalid type
        """
        for sv, elt in elt_alt.items():
            if self._SAFE_STAT and not isinstance(elt, Element):
                raise(EltErr('{0} [update]: alternative arg type is {1}, expecting element'\
                      .format(self._name, type(elt).__name__)))
            self._content[sv] = elt
            elt.set_env(self.get_env())
    
    def insert(self, sv, elt):
        """Insert the element `elt' with the given selection value `sv' in the 
        content of self
        
        Args:
            sv : selectio value
            elt (element) : element to be inserted
        
        Returns:
            None
        
        Raises:
            EltErr : if self._SAFE_STAT is enabled and the type of `elt' is 
                not Element, or if selection value is invalid
        """
        if self._SAFE_STAT and not isinstance(elt, Element):
            raise(EltErr('{0} [insert]: arg type is {1}, expecting element'\
                  .format(self._name, type(elt).__name__)))
        try:
            self._content[sv] = elt
        except Exception:
            raise(EltErr('{0} [insert]: selection value is invalid, {1}'.format(self._name, sv)))
        else:
            elt.set_env(self.get_env())
    
    def index(self, elt):
        """Provide the selection value of the element `elt' within the content 
        of self
        
        Args:
            elt (element) : element to be looked-up in the alt
        
        Returns:
            ind (int) : selection value of the element within the envelope
        
        Raises:
            EltErr : element `elt' is not in the content
        """
        for sv, alt in self._content.items():
            if elt == alt:
                return sv
        raise(EltErr('{0} [index]: non existent element, {1}'.format(self._name, elt)))
    
    def clear(self):
        """Clears the content of self
        
        Args:
            None
        
        Returns:
            None
        """
        self._content.clear()
    
    # subscript methods passthrough
    
    def __getitem__(self, key):
        return self.get_alt().__getitem__(key)
    
    def __setitem__(self, key, val):
        return self.get_alt().__setitem__(key, val)
    
    def __delitem(self, key):
        return self.get_alt().__delitem__(key)
    
    #--------------------------------------------------------------------------#
    # representation routines
    #--------------------------------------------------------------------------#
    
    def repr(self):
        if self.REPR_EXPL:
            sv, alt = self.get_sel(), self.get_alt()
            # element transparency
            if self.get_trans():
                trans = ' [transparent]'
            else:
                trans = ''
            # additional description
            if self._desc:
                desc = ' [%s]' % self._desc
            else:
                desc = ''
            #
            return '<%s%s%s : %r -> %s' % (self._name, desc, trans, sv, alt.repr()[1:])
        else:
            return self.get_alt().repr()
    
    def show(self):
        if self.REPR_EXPL:
            sv, alt = self.get_sel(), self.get_alt()
            # element transparency
            if self.get_trans():
                trans = ' [transparent]'
            else:
                trans = ''
            # additional description
            if self._desc:
                desc = ' [%s]' % self._desc
            else:
                desc = ''
            #
            alts = alt.show()
            if alts.lstrip()[:4] == '### ':
                # when the alternative is a constructed element
                return alts.replace('### ', '### %s%s%s : %r -> ' % (self._name, desc, trans, sv), 1)
            else:
                # when the alternative is a base element
                spaces = self.get_hier_abs() * '    '
                return '%s### %s%s%s : %r ###\n %s' % (spaces, self._name, desc, trans, sv, alts)
        else:
            alt = self.get_alt()
            _hier = alt._hier
            alt._hier = self._hier
            s = alt.show()
            alt._hier = _hier
            return s
    
    #--------------------------------------------------------------------------#
    # Python built-ins override
    #--------------------------------------------------------------------------#
    
    __call__ = get_val
    __repr__ = repr
    #if python_implementation != 'PyPy':
        # PyPy iterator implementation lead to an infinite loop
        # __iter__() calls __len__(), but here, get_bl() calls __iter__()
    #    __len__ = get_bl

    #--------------------------------------------------------------------------#
    # json interface
    #--------------------------------------------------------------------------#
    
    if _with_json:
        
        def _from_jval(self, val):
            self.get_alt()._from_jval_wrap(val)
        
        def _to_jval(self):
            return self.get_alt()._to_jval_wrap()

