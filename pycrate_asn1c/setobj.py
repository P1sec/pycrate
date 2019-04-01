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
# * File Name : pycrate_asn1c/rangeobj.py
# * Created : 2016-07-12
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from functools import reduce

from .utils  import *
from .err    import *
from .refobj import ASN1Ref

#------------------------------------------------------------------------------#
# range for integers, reals and some character strings
#------------------------------------------------------------------------------#

class ASN1Range(object):
    """
    Special class to handle range of values for ASN.1 types that support
    ordering their values (e.g. INTEGER and REAL)
    
    Init args:
        type   : str (TYPE_*), type of the ASN.1 object handling the value range
        lb     : single value according to the type, lower bound of the range
        lb_incl: bool, indicate if the lower bound is part of the range
        ub     : single value according to the type, upper bound of the range
        ub_incl: bool, indicate if the upper bound is part of the range
    
    When type is TYPE_INT or TYPE_STR_*, lb_incl and ub_incl shall always be True
    """
    
    _TYPE_STR = (TYPE_STR_IA5, TYPE_STR_PRINT, TYPE_STR_VIS)
    _TYPE     = (TYPE_INT, TYPE_REAL) + _TYPE_STR
    
    # methods for emulating a dictionnary
    # this enables to reference path within ASN.1 objects in the form of 
    # list of str or int; e.g. path = ['const', 0, 'root', 0, 'ub'] 
    def __getitem__(self, kw):
        if kw in self.KW:
            return getattr(self, kw)
        else:
            return object.__getitem__(self, kw)
    
    def __setitem__(self, kw, arg):
        if kw in self.KW:
            return setattr(self, kw, arg)
        else:
            return object.__setitem__(self, kw, arg)
    
    def copy(self):
        """
        returns an equal but independent copy of self
        """
        if isinstance(self.lb, ASN1Ref):
            lb = self.lb.copy()
        else:
            lb = self.lb
        if isinstance(self.ub, ASN1Ref):
            ub = self.ub.copy()
        else:
            ub = self.ub
        if isinstance(self, (ASN1RangeInt, ASN1RangeStr)):
            return self.__class__(self.lb, self.ub)
        elif isinstance(self, ASN1RangeReal):
            return self.__class__(self.lb, self.ub, self.lb_incl, self.ub_incl)
    
    def expand(self):
        raise(ASN1Err('{0!r}: unable to expand this type of range'.format(self)))


class ASN1RangeInt(ASN1Range):
    
    KW = ('lb', 'ub')
        
    _EXP_MAX = 2**18 # max range that can be expanded
    
    def __init__(self, lb=None, ub=None):
        self.lb = lb
        self.ub = ub
    
    def _safechk(self):
        if not isinstance(self.lb, integer_types + (NoneType, )) or \
        not isinstance(self.ub, integer_types + (NoneType, )) or \
        (self.ub is not None and self.lb is not None and self.ub < self.lb):
            raise(ASN1Err('{0!r}: invalid bounds'.format(self)))
    
    def __repr__(self):
        return 'ASN1RangeInt({0!r}..{1!r})'.format(self.lb, self.ub)
    
    def expand(self):
        """
        returns a list of integers
        """
        if self.lb is None or self.ub is None:
            raise(ASN1Err('{0!r}: unable to expand infinite range'.format(self)))
        elif self.ub - self.lb < self._EXP_MAX:
            return list(range(self.lb, 1+self.ub))
        else:
            raise(ASN1Err('{0!r}: range too large for expansion'.format(self)))
    
    def __contains__(self, item):
        if not isinstance(item, integer_types):
            return None
        elif self.lb is None:
            if self.ub is None:
                return True
            else:
                return item <= self.ub
        elif self.ub is None:
            return self.lb <= item
        else:
            return self.lb <= item <= self.ub
    
    def intersect(self, ra):
        """
        returns a single ASN1RangeInt which is the intersection of self and `ra' 
        in case they intersect, None otherwise
        """
        if not isinstance(ra, ASN1RangeInt):
            return None
        #
        # disjoint sets:
        if self.ub is not None and ra.lb is not None and self.ub < ra.lb:
            return None
        elif ra.ub is not None and self.lb is not None and ra.ub < self.lb:
            return None
        #
        # intersecting sets:
        elif ra.lb in self:
            if ra.ub in self:
                return ASN1RangeInt(ra.lb, ra.ub)
            else:
                return ASN1RangeInt(ra.lb, self.ub)
        elif ra.ub in self:
            return ASN1RangeInt(self.lb, ra.ub)
        else:
            return ASN1RangeInt(self.lb, self.ub)
    
    def unite(self, ra):
        """
        returns a single ASN1RangeInt which is the union of self and `ra'
        in case they intersect, None otherwise
        """
        if not isinstance(ra, ASN1RangeInt):
            return None
        #
        # disjoint sets:
        if self.ub is not None and ra.lb is not None and self.ub < ra.lb:
            return None
        elif ra.ub is not None and self.lb is not None and ra.ub < self.lb:
            return None
        #
        # intersecting sets:
        if self.lb is None or ra.lb is None:
            lb = None
        else:
            lb = min(self.lb, ra.lb)
        if self.ub is None or ra.ub is None:
            ub = None
        else:
            ub = max(self.ub, ra.ub)
        return ASN1RangeInt(lb, ub)
    
    def diff(self, ra):
        """
        returns a 2-tuple of ASN1RangeStr or None, which are the exclusive 
        parts of each self and `ra' ranges
        """
        if not isinstance(ra, ASN1RangeInt):
            return self, ra
        #
        # disjoint sets:
        if self.ub is not None and ra.lb is not None and self.ub < ra.lb:
            return self, ra
        elif ra.ub is not None and self.lb is not None and ra.ub < self.lb:
            return ra, self
        #
        # intersecting sets:
        # lower set
        if self.lb == ra.lb:
            lset = None
        else:
            lset = ASN1RangeStr(min(self.lb, ra.lb), max(self.lb, ra.lb) - 1)
        # upper set
        if self.lb == ra.lb:
            lset = None
        else:
            if None in (self.lb, ra.lb):
                lset = ASN1RangeInt(None, max(self.lb, ra.lb) - 1)
            else:
                lset = ASN1RangeInt(min(self.lb, ra.lb), max(self.lb, ra.lb) - 1)
        if self.ub == ra.ub:
            uset = None
        else:
            if None in (self.ub, ra.ub):
                uset = ASN1RangeInt(min(self.ub, ra.ub) + 1, None)
            else:
                uset = ASN1RangeInt(min(self.ub, ra.ub) + 1, max(self.ub, ra.ub))
        return lset, uset


class ASN1RangeStr(ASN1Range):
    
    KW = ('lb', 'ub')
    
    def __init__(self, lb=chr(0), ub=chr(0xff)):
        self.lb = lb
        self.ub = ub
    
    def _safechk(self):
        if not isinstance(self.lb, str_types) or \
        not isinstance(self.ub, str_types) or \
        len(self.lb) != 1 or len(self.ub) != 1 or ord(self.ub) < ord(self.lb):
            raise(ASN1Err('{0!r}!: invalid bounds'.format(self)))
    
    def __repr__(self):
        return 'ASN1RangeStr("{0}".."{1}")'.format(self.lb, self.ub)
    
    def expand(self):
        """
        returns a list of characters
        """
        return list(map(chr, range(ord(self.lb), 1+ord(self.ub))))
    
    def __contains__(self, item):
        if not isinstance(item, str_types) or len(item) > 1:
            return False
        else:
            return ord(self.lb) <= ord(item) <= ord(self.ub)
    
    def intersect(self, ra):
        """
        returns a single ASN1RangeStr which is the intersection of self and `ra'
        in case they intersect, None otherwise
        """
        if not isinstance(ra, ASN1RangeStr):
            return None
        #
        lb, ub, ralb, raub = ord(self.lb), ord(self.ub), ord(ra.lb), ord(ra.ub)
        # disjoint sets:
        if ub < ralb or raub < lb:
            return None
        #
        # intersecting sets:
        else:
            return ASN1RangeStr(chr(max(lb, ralb)), chr(min(ub, raub)))
    
    def unite(self, ra):
        """
        returns a single ASN1RangeInt which is the union of self and `ra'
        in case they intersect, None otherwise
        """
        if not isinstance(ra, ASN1RangeStr):
            return None
        #
        lb, ub, ralb, raub = ord(self.lb), ord(self.ub), ord(ra.lb), ord(ra.ub)
        # disjoint sets:
        if ub < ralb or raub < lb:
            return None
        #
        # intersecting sets:
        else:
            return ASN1RangeStr(chr(min(lb, ralb)), chr(max(ub, raub)))
    
    def diff(self, ra):
        """
        returns a 2-tuple of ASN1RangeStr or None, which are the exclusive 
        parts of each self and `ra' ranges
        """
        if not isinstance(ra, ASN1RangeStr):
            return self, ra
        #
        lb, ub, ralb, raub = ord(self.lb), ord(self.ub), ord(ra.lb), ord(ra.ub)
        # disjoint sets:
        if ub < ralb:
            return self, ra
        elif raub < lb:
            return ra, self
        #
        # intersecting sets:
        # lower set
        if self.lb == ra.lb:
            lset = None
        else:
            lset = ASN1RangeStr(min(self.lb, ra.lb), max(self.lb, ra.lb) - 1)
        # upper set
        if self.ub == ra.ub:
            uset = None
        else:
            uset = ASN1RangeStr(min(self.ub, ra.ub) + 1, max(self.ub, ra.ub))
        return lset, uset


MINUS_INF = (-1, None, None)
PLUS_INF  = ( 1, None, None)
NAN       = ( 0, None, None)

def real_to_float(realtuple):
    # TODO: Python float default precision is quite bad
    # it would be nice to use the Decimal module to set the floating point 
    # precision as required
    # or even better, to use a module dedicated to arbitrary precision floating
    # point operation
    # TODO: moreover, for very large exponent, it will raises an OverflowError
    # as the integral exponentiation will fail
    return float(realtuple[0]*(realtuple[1]**realtuple[2]))

def real_lowest(rt1, rt2):
    if rt1 == MINUS_INF or rt2 == MINUS_INF:
        return MINUS_INF
    elif rt1 == PLUS_INF:
        return rt2
    elif rt2 == PLUS_INF:
        return rt1
    #
    rt1f, rt2f = real_to_float(rt1), real_to_float(rt2)
    if rt1f <= rt2f:
        return rt1
    else:
        return rt2

def real_highest(rt1, rt2):
    if rt1 == PLUS_INF or rt2 == PLUS_INF:
        return PLUS_INF
    elif rt1 == MINUS_INF:
        return rt2
    elif rt2 == MINUS_INF:
        return rt1
    #
    rt1f, rt2f = real_to_float(rt1), real_to_float(rt2)
    if rt1f <= rt2f:
        return rt2
    else:
        return rt1

class ASN1RangeReal(ASN1Range):
    
    KW = ('lb', 'ub', 'lb_incl', 'ub_incl')
    
    def __init__(self, lb=MINUS_INF, ub=PLUS_INF, lb_incl=True, ub_incl=True):
        self.lb = lb
        self.lb_incl = lb_incl
        self.ub = ub
        self.ub_incl = ub_incl
    
    def _safechk(self):
        if not isinstance(self.lb, tuple) or not isinstance(self.ub, tuple) or \
        len(self.lb) != 3 or len(self.ub) != 3 or \
        not isinstance(self.lb[0], integer_types) or \
        not isinstance(self.ub[0], integer_types) or \
        not all([isinstance(b, integer_types + (NoneType, )) for b in \
                 (self.lb[1], self.lb[2], self.ub[1], self.ub[2])]):
            raise(ASN1Err('{0!r}: invalid bounds'.format(self.__class__.__name__)))
        elif self.lb in (NAN, PLUS_INF) or self.ub in (NAN, MINUS_INF):
            raise(ASN1Err('{0!r}: invalid inifinite bound'.format(self)))
        elif self.lb != MINUS_INF and self.ub != PLUS_INF:
            lb, ub = real_to_float(self.lb), real_to_float(self.ub)
            if ub < lb:
                raise(ASN1Err('{0!r}: invalid bounds'.format(self)))
            elif lb == ub and not (self.lb_incl and self.ub_incl):
                raise(ASN1Err('{0!r}: invalid bounds'.format(self)))
    
    def __repr__(self):
        if self.lb == MINUS_INF:
            lb = 'MINUS-INFINITY'
        elif self.lb[1] == 10:
            lb = '{0!r}e{1!r}'.format(self.lb[0], self.lb[2])
        else:
            lb = '{0!r}*{1!r}**{2!r}'.format(self.lb[0], self.lb[1], self.lb[2])
        if not self.lb_incl:
            lb = lb + '<'
        if self.ub == PLUS_INF:
            ub = 'PLUS-INFINITY'
        elif self.ub[1] == 10:
            ub = '{0!r}e{1!r}'.format(self.ub[0], self.ub[2])
        else:
            ub = '{0!r}*{1!r}**{2!r}'.format(self.lb[0], self.lb[1], self.lb[2])
        if not self.ub_incl:
            ub = '<' + ub
        return 'ASN1RangeReal({0}..{1})'.format(lb, ub)
    
    def __contains__(self, item):
        if not isinstance(item, tuple) or len(item) != 3:
            return False
        elif not all([isinstance(i, integer_types) for i in item]) or \
        item not in (MINUS_INF, PLUS_INF):
            return False
        #
        if item == MINUS_INF and self.lb == MINUS_INF:
            return self.lb_incl
        elif item == PLUS_INF and self.ub == PLUS_INF:
            return self.ub_incl
        elif real_lowest(self.lb, item) == item:
            return False
        elif real_highest(self.ub, item) == item:
            return False
        else:
            return True
    
    def intersect(self, ra):
        """
        returns a single ASN1RangeReal which is the intersection of self and `ra' 
        in case they intersect, None otherwise
        """
        if not isinstance(ra, ASN1RangeReal):
            return None
        #
        if self.lb != MINUS_INF:
            slb = real_to_float(self.lb)
        if self.ub != PLUS_INF:
            sub = real_to_float(self.ub)
        if ra.lb != MINUS_INF:
            ralb = real_to_float(ra.lb)
        if ra.ub != PLUS_INF:
            raub = real_to_float(ra.ub)
        #
        # disjoint sets:
        if self.ub is not PLUS_INF and ra.lb is not MINUS_INF and sub < ralb:
            return None
        elif ra.ub is not PLUS_INF and self.lb is not MINUS_INF and raub < slb:
            return None
        #
        # intersecting sets:
        # lower bound
        if MINUS_INF == self.lb == ra.lb:
            lb, lb_incl = MINUS_INF, self.lb_incl & ra.lb_incl
        elif MINUS_INF not in (self.lb, ra.lb) and slb == ralb:
            lb, lb_incl = self.lb, self.lb_incl & ra.lb_incl
        else:
            lb = real_highest(self.lb, ra.lb)
            if lb == self.lb:
                lb_incl = self.lb_incl
            else:
                lb_incl = ra.lb_incl
        # upper bound
        if PLUS_INF == self.ub == ra.ub:
            ub, ub_incl = PLUS_INF, self.ub_incl & ra.ub_incl
        elif PLUS_INF not in (self.ub, ra.ub) and sub == raub:
            ub, ub_incl = self.ub, self.ub_incl & ra.ub_incl
        else:
            ub = real_lowest(self.ub, ra.ub)
            if ub == self.ub:
                ub_incl = self.ub_incl
            else:
                ub_incl = ra.ub_incl
        return ASN1RangeReal(lb, ub, lb_incl, ub_incl)
    
    def unite(self, ra):
        """
        returns a single ASN1RangeReal which is the union of self and `ra'
        in case they intersect, None otherwise
        """
        if not isinstance(ra, ASN1RangeReal):
            return None
        #
        if self.lb != MINUS_INF:
            slb = real_to_float(self.lb)
        if self.ub != PLUS_INF:
            sub = real_to_float(self.ub)
        if ra.lb != MINUS_INF:
            ralb = real_to_float(ra.lb)
        if ra.ub != PLUS_INF:
            raub = real_to_float(ra.ub)
        #
        # disjoint sets:
        if self.ub is not PLUS_INF and ra.lb is not MINUS_INF and sub < ralb:
            return None
        elif ra.ub is not PLUS_INF and self.lb is not MINUS_INF and raub < slb:
            return None
        #
        # intersecting sets:
        # lower bound
        if MINUS_INF == self.lb == ra.lb:
            lb, lb_incl = MINUS_INF, self.lb_incl | ra.lb_incl
        elif MINUS_INF not in (self.lb, ra.lb) and slb == ralb:
            lb, lb_incl = self.lb, self.lb_incl | ra.lb_incl
        else:
            lb = real_lowest(self.lb, ra.lb)
            if lb == self.lb:
                lb_incl = self.lb_incl
            else:
                lb_incl = ra.lb_incl
        # upper bound
        if PLUS_INF == self.ub == ra.ub:
            ub, ub_incl = PLUS_INF, self.ub_incl | ra.ub_incl
        elif PLUS_INF not in (self.ub, ra.ub) and sub == raub:
            ub, ub_incl = self.ub, self.ub_incl | ra.ub_incl
        else:
            ub = real_highest(self.ub, ra.ub)
            if ub == self.ub:
                ub_incl = self.ub_incl
            else:
                ub_incl = ra.ub_incl
        return ASN1RangeReal(lb, ub, lb_incl, ub_incl)
    
    def diff(self, ra):
        """
        returns a 2-tuple of ASN1RangeReal or None, which are the exclusive 
        parts of each self and `ra' ranges
        """
        if not isinstance(ra, ASN1RangeReal):
            return self, ra
        #
        if self.lb != MINUS_INF:
            slb = real_to_float(self.lb)
        if self.ub != PLUS_INF:
            sub = real_to_float(self.ub)
        if ra.lb != MINUS_INF:
            ralb = real_to_float(ra.lb)
        if ra.ub != PLUS_INF:
            raub = real_to_float(ra.ub)
        #
        # disjoint sets:
        if self.ub is not PLUS_INF and ra.lb is not MINUS_INF and sub < ralb:
            return self, ra
        elif ra.ub is not PLUS_INF and self.lb is not MINUS_INF and raub < slb:
            return ra, self
        #
        # intersecting sets
        # lower set
        if MINUS_INF == self.lb == ra.lb or \
        MINUS_INF not in (self.lb, ra.lb) and slb == ralb:
            # no lower set
            lset = None
        else:
            lset_lb = real_lowest(self.lb, ra.lb)
            if lset_lb == self.lb:
                lset_lb_incl = self.lb_incl
                lset_ub = ra.lb
                lset_ub_incl = not ra.lb_incl
            else:
                lset_lb_incl = ra.lb_incl
                lset_ub = self.lb
                lset_ub_incl = not self.lb_incl
            lset = ASN1RangeReal(lset_lb, lset_ub, lset_lb_incl, lset_ub_incl)
        # upper set
        if PLUS_INF == self.ub == ra.ub or \
        PLUS_INF not in (self.ub, ra.ub) and sub == raub:
            uset = None
        else:
            uset_ub = real_highest(self.ub, ra.ub)
            if uset_ub == self.ub:
                uset_ub_incl = self.ub_incl
                uset_lb = ra.ub
                uset_lb_incl = not ra.ub_incl
            else:
                uset_ub_incl = ra.ub_incl
                uset_lb = self.ub
                uset_lb_incl = self.ub_incl
            uset = ASN1RangeReal(uset_lb, uset_ub, uset_lb_incl, uset_ub_incl)
        #
        return lset, uset


def reduce_rangelist(rl=[]):
    """
    reduces a list of ranges by reuniting intersecting ones
    """
    # reduced list, to be returned
    red = []
    #
    for r in rl:
        if r is None:
            pass
        else:
            # check in case this range can get united within some previous one(s)
            u, united = None, []
            for rr in red:
                u = rr.unite(r)
                if u is not None:
                    united.append(red.index(rr))
                    # r is growing...
                    r = u
            # remove from red all ranges united with r
            for i in united[::-1]:
                del red[i]
            red.append(r)
    return red 


#------------------------------------------------------------------------------#
# set of ASN.1 values or range of values
#------------------------------------------------------------------------------#
# WNG: in case of TYPE_REAL values, they are managerd in their 3-tuple format
# hence test for inclusion may fail

class ASN1Set(object):
    """
    Class to handle a set of (range of) values for any ASN.1 types
    
    _rr  : list with all individual values in the root set
    _rv  : list with all ranges of values in the root set
    _ev  : None (if not extendable) or list with all individual values in the 
           extension set
    _er  : list with all ranges of values in the extension set
    
    root : ordered list with all individual and ranges of values in the root set
    ext  : ordered list with all individual and ranges of values in the 
           extension set
    """
    def __init__(self, d={'root':[], 'ext':None}):
        self._rr = reduce_rangelist([v for v in d['root'] if isinstance(v, ASN1Range)])
        self._rv = []
        self._rv = [v for v in d['root'] if not isinstance(v, ASN1Range) and not self.in_root(v)]
        if d['ext'] is not None:
            self._er = reduce_rangelist([v for v in d['ext'] if isinstance(v, ASN1Range)])
            self._ev = []
            self._ev = [v for v in d['ext'] if not isinstance(v, ASN1Range) and \
                        not self.in_root(v) and not self.in_ext(v)]
        else:
            self._er = []
            self._ev = None
        self._init()
    
    def _init(self):
        """
        creates the `root' and `ext' attributes which lists all values and 
        ranges of their domain in order
        """
        self.root = []
        rv, rr = self._rv, [_rr.lb for _rr in self._rr]
        rv_off = 0
        if rr and rr[0] is None:
            self.root.append(self._rr[0])
            rr_off = 1
        else:
            rr_off = 0
        while rv_off < len(rv) and rr_off < len(rr):
            if rv[rv_off] < rr[rr_off]:
                self.root.append(self._rv[rv_off])
                rv_off += 1
            else:
                self.root.append(self._rr[rr_off])
                rr_off += 1
        if rv_off < len(rv):
            self.root.extend( self._rv[rv_off:] )
        elif rr_off < len(rr):
            self.root.extend( self._rr[rr_off:] )
        #
        if self._ev is not None:
            self.ext = []
            ev, er = self._ev, [_er.lb for _er in self._er]
            ev_off = 0
            if er and er[0] is None:
                self.ext.append(self._er[0])
                er_off = 1
            else:
                er_off = 0
            while ev_off < len(ev) and er_off < len(er):
                if ev[ev_off] < er[er_off]:
                    self.ext.append(self._ev[ev_off])
                    ev_off += 1
                else:
                    self.ext.append(self._er[er_off])
                    er_off += 1
            if ev_off < len(ev):
                self.ext.extend( self._ev[ev_off:] )
            elif er_off < len(er):
                self.ext.extend( self._er[er_off:] )
        else:
            self.ext = None
    
    def __repr__(self):
        root = '[' + ', '.join([repr(r) for r in self.root]) + ']'
        if self.ext is None:
            ext = 'None'
        else:
            ext = '[' + ', '.join([repr(e) for e in self.ext]) + ']'
        return 'ASN1Set(root={0}, ext={1})'.format(root, ext)
        
    def is_empty(self):
        return self._rv == [] and self._rr == []
    
    def is_ext(self):
        return self._ev is not None
    
    def __contains__(self, v):
        if self._CONTAIN_WEXT:
            return self.in_root(v) or self.in_ext(v)
        else:
            return self.in_root(v)
    
    def in_root(self, v):
        for r in self._rr:
            if v in r:
                return True
        if v in self._rv:
            return True
        return False
    
    def in_ext(self, v):
        if self._ev is None:
            return False
        for r in self._er:
            if v in r:
                return True
        if v in self._ev:
            return True
        return False
    
    def intersect(self, S):
        """
        returns an ASN1Set which root part is the intersection or the root parts
        of self and S, and ext part contains all remaining defined values if self
        and S are extensible
        """
        ret_root, ret_root_r, = [], []
        # 1) check if ret is extensible
        if self.is_ext() and S.is_ext():
            ret_ext = []
        else:
            ret_ext = None
        # 2) get the intersection of root ranges
        if self._rr and S._rr:
            for r in S._rr:
                # list of intersection with all root ranges of self 
                inter = [r.intersect(sr) for sr in self._rr]
                for r in inter:
                    if r is not None:
                        if r.lb is not None and r.lb == r.ub:
                            # range with a single value
                            ret_root.append(r.lb)
                        else:
                            ret_root_r.append(r)
        ret = ASN1Set()
        ret._rv, ret._rr, ret._ev = ret_root, ret_root_r, ret_ext
        ret._init()
        # 3) check the root individual values
        for v in self._rv:
            if S.in_root(v) and not ret.in_root(v):
                ret._rv.append(v)
        for v in S.root:
            if self.in_root(v) and not ret.in_root(v):
                ret._rv.append(v)
        # 4) build ret extension
        if ret_ext is not None:
            # 4.1) gather both self and S root and extension ranges and remove
            # ret._rv and ret._rr parts of it to put in ret._er
            union = reduce_rangelist(self._rr + S._rr + self._er + S._er)
            ret._er = union
            # TODO: doing holes in ext_r ...
            # ret.ext_r = union - (ret.root_r + ret.root)
            #
            # 4.2) gather both self and S extension individual values
            for v in self._ev:
                if not ret.in_root(v) and not ret.in_ext(v):
                    ret._ev.append(v)
            for v in S._ev:
                if not ret.in_root(v) and not ret.in_ext(v):
                    ret._ev.append(v)
            # 4.3) add self and S root values not intersecting
            for v in self.root:
                if not ret.in_root(v) and not ret.in_ext(v):
                    ret._ev.append(v)
            for v in S.root:
                if not ret.in_root(v) and not ret.in_ext(v):
                    ret._ev.append(v)
        ret._init()
        return ret


def reduce_setdicts(sdl):
    """
    gets a list of set dicts of a given type (i.e. constraints of type CONST_VAL
    or CONST_SIZE), and reduce them by intersecting their root part, 
    and extending their ext part, into a single ASN1Set that is to be returned
    """
    return reduce_sets([ASN1Set(sd) for sd in sdl])
    
def reduce_sets(sl):
    """
    gets a list of ASN1Set for a given type, and reduce them by intersecting 
    their root part, and extending their ext part, into a single ASN1Set that 
    is to be returned
    """
    return reduce(lambda a, b: a.intersect(b), sl[::-1])

