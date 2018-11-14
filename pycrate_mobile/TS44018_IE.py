# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.3
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
# * File Name : pycrate_mobile/TS44018_IE.py
# * Created : 2018-06-21
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# 3GPP TS 44.018 GSM / EDGE RRC protocol
# release 13 (d80)
#------------------------------------------------------------------------------#

from pycrate_core.utils  import *
from pycrate_core.elt    import Envelope, Array, Sequence, Alt, \
                                REPR_RAW, REPR_HEX, REPR_BIN, REPR_HD, REPR_HUM
from pycrate_core.base   import *
from pycrate_core.repr   import *


#------------------------------------------------------------------------------#
# generic objects
#------------------------------------------------------------------------------#

'''to be removed
def smod(n, m):
    """
    offset remainder of the euclidian division of n by m:
        1 <= (n smod m) <= m and there exists k such that 
        n = (k*m) + (n smod m);
    """
    r = n%m
    if r == 0:
        return m
    else:
        return r
'''

class BitMap(Buf):
    """handles bit map
    
    derives from the Buf object and includes get() / set() / unset() methods
    for handling bit value at given offset
    """
    _pre = REPR_BIN
    
    # dedicated method to get, set and unset at a given offset
    def get(self, off):
        return 1 & (self.to_uint()>>(off-1))
    
    def set(self, off):
        u = self.to_uint()
        o = 1<<(off-1)
        if not u & o:
            self.from_uint(u+o)
    
    def unset(self, off):
        u = self.to_uint()
        o = 1<<(off-1)
        if u & o:
            self.from_uint(u-o)


#------------------------------------------------------------------------------#
# Cell Channel Description
# TS 44.018, 10.5.2.1b
#------------------------------------------------------------------------------#
# This is the same structure as FreqList defined in 10.5.2.13,
# but with a fixed length of 16 bytes


#------------------------------------------------------------------------------#
# Channel Description
# TS 44.018, 10.5.2.5
#------------------------------------------------------------------------------#

ChanDescType_dict = {
    1  : 'TCH/F + ACCHs; TSC Set 1 shall be used',
    17 : 'TCH/F + ACCHs; TSC Set 2 shall be used; subchannel 0',
    18 : 'TCH/F + ACCHs; TSC Set 2 shall be used; subchannel 1',
    4  : 'SDCCH/4 + SACCH/C4 or CBCH (SDCCH/4); TSC Set 1 shall be used; subchannel 0',
    5  : 'SDCCH/4 + SACCH/C4 or CBCH (SDCCH/4); TSC Set 1 shall be used; subchannel 1',
    6  : 'SDCCH/4 + SACCH/C4 or CBCH (SDCCH/4); TSC Set 1 shall be used; subchannel 2',
    7  : 'SDCCH/4 + SACCH/C4 or CBCH (SDCCH/4); TSC Set 1 shall be used; subchannel 3',
    8  : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 0',
    9  : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 1',
    10 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 2',
    11 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 3',
    12 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 4',
    13 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 5',
    14 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 6',
    15 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 7',
    }

ChanDescHop_dict = {
    0 : 'Single RF channel',
    1 : 'RF hopping channel',
    }

class ChanDesc(Envelope):
    _GEN = (
        Uint('ChanType', bl=5, dic=ChanDescType_dict),
        Uint('TN', bl=3),
        Uint('TSC', bl=3),
        Uint('HopChan', bl=1, dic=ChanDescHop_dict),
        Alt(GEN={
            0: Envelope('ChanSingle', GEN=(
                Uint('spare', bl=2, rep=REPR_HEX),
                Uint('ARFCN', bl=10)
                )),
            1: Envelope('ChanHopping', GEN=(
                Uint('MAIO', bl=6),
                Uint('HSN', bl=6)
                ))},
            sel=lambda self:self.get_env()[3].get_val())
        )


#------------------------------------------------------------------------------#
# Channel Description 2
# TS 44.018, 10.5.2.5a
#------------------------------------------------------------------------------#

ChanDesc2Type_dict = {
    0  : 'TCH/F + FACCH/F and SACCH/M',
    1  : 'TCH/F + FACCH/F and SACCH/F',
    2  : 'TCH/H + ACCHs, subchannel 0',
    3  : 'TCH/H + ACCHs, subchannel 1',
    4  : 'SDCCH/4 + SACCH/C4 or CBCH (SDCCH/4); subchannel 0',
    5  : 'SDCCH/4 + SACCH/C4 or CBCH (SDCCH/4); subchannel 1',
    6  : 'SDCCH/4 + SACCH/C4 or CBCH (SDCCH/4); subchannel 2',
    7  : 'SDCCH/4 + SACCH/C4 or CBCH (SDCCH/4); subchannel 3',
    8  : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); subchannel 0',
    9  : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); subchannel 1',
    10 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); subchannel 2',
    11 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); subchannel 3',
    12 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); subchannel 4',
    13 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); subchannel 5',
    14 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); subchannel 6',
    15 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); subchannel 7',
    24 : 'TCH/F + ACCHs using TSC Set 2',
    28 : 'TCH/H + ACCHs using TSC Set 2; subchannel 0',
    29 : 'TCH/H + ACCHs using TSC Set 2; subchannel 1',
    16 : 'TCH/F + FACCH/F and SACCH/M; no additional timeslots',
    17 : 'TCH/F + FACCH/F and SACCH/M; additional bidirectional TCH/Fs and SACCH/Ms at timeslot n-1',
    18 : 'TCH/F + FACCH/F and SACCH/M; additional bidirectional TCH/Fs and SACCH/Ms at timeslot n+1, n-1',
    19 : 'TCH/F + FACCH/F and SACCH/M; additional bidirectional TCH/Fs and SACCH/Ms at timeslot n+1, n-1 and n-2',
    20 : 'TCH/F + FACCH/F and SACCH/M; additional bidirectional TCH/Fs and SACCH/Ms at timeslot n+1, n-1, n-2, and n-3',
    21 : 'TCH/F + FACCH/F and SACCH/M; additional bidirectional TCH/Fs and SACCH/Ms at timeslot n+1, n-1, n-2, n-3 and n-4',
    22 : 'TCH/F + FACCH/F and SACCH/M; additional bidirectional TCH/Fs and SACCH/Ms at timeslot n+1, n-1, n-2, n-3, n-4 and n-5',
    23 : 'TCH/F + FACCH/F and SACCH/M; additional bidirectional TCH/Fs and SACCH/Ms at timeslot n+1, n-1, n-2, n-3, n-4, n-5 and n-6',
    25 : 'TCH/F + FACCH/F and SACCH/M; additional unidirectional TCH/FDs and SACCH/MDs at timeslot n-1',
    26 : 'TCH/F + FACCH/F and SACCH/M; additional unidirectional TCH/FDs and SACCH/MDs at timeslot n+1, n-1',
    27 : 'TCH/F + FACCH/F and SACCH/M; additional unidirectional TCH/FDs and SACCH/MDs at timeslot n+1, n-1 and n-2'
    }

ChanDescHop_dict = {
    0 : 'Single RF channel',
    1 : 'RF hopping channel',
    }

class ChanDesc2(Envelope):
    _GEN = (
        Uint('ChanType', bl=5, dic=ChanDesc2Type_dict),
        Uint('TN', bl=3),
        Uint('TSC', bl=3),
        Uint('HopChan', bl=1, dic=ChanDescHop_dict),
        Alt(GEN={
            0: Envelope('ChanSingle', GEN=(
                Uint('spare', bl=2, rep=REPR_HEX),
                Uint('ARFCN', bl=10)
                )),
            1: Envelope('ChanHopping', GEN=(
                Uint('MAIO', bl=6),
                Uint('HSN', bl=6)
                ))},
            sel=lambda self:self.get_env()[3].get_val())
        )


#------------------------------------------------------------------------------#
# Frequency List
# TS 44.018, 10.5.2.13
#------------------------------------------------------------------------------#

# for range 512 and range 1024, there is a W(parent) selection
# which requires some damned numerology !
# So we build a dict of W_index -> W_parent_index up to index 511 (rank 8),
# what corresponds to the longest sequence of W (for range 512)

def __exp_ind(ind):
    l = [i*2 for i in ind]
    r = [1+i for i in l]
    return l + r

def _build_w_parent_dict(rank=8):
    ind, par = [[1]], {}
    for i in range(rank):
        ind.append( __exp_ind(ind[i]) )
        for j in range(0, len(ind[-1]), 2):
            par[ind[i+1][j]]   = ind[i][j>>1]
            par[ind[i+1][j+1]] = ind[i][j>>1]
    return par


# generic class to handle the parsing, decoding and encoding of ranges of ARFCN
class _FreqListRange(Envelope):
    _Range  = 0
    _Layout = ()
    _Parent = _build_w_parent_dict(8)
    _GEN    = ()
    
    def _from_char(self, char):
        # char can be of variable length in bits
        # hence, the number of W has to be set according to this 
        # and the layout of bit length for W
        if self._Range == 1024:
            self[0]._from_char(char)
            off = 6
        else:
            off = 17
        i = 1
        while True:
            ccur, wbl = char._cur, self._Layout[i-1]
            if char._len_bit - ccur >= wbl:
                w = Uint('W_%i' % i, bl=wbl)
                w._from_char(char)
                self.append(w)
                i   += 1
                off += wbl
            else:
                break
        # add some spare bits for octet-alignment
        sbl = -off % 8
        if sbl:
            s = Uint('spare', bl=sbl, rep=REPR_HEX)
            s._from_char(char)
            self.append(s)
    
    def _decode(self):
        if self._Range == 1024:
            start = 1
        else:
            start = 0
        if self[-1]._name[0:1] != 'W':
            # spare bits field present
            end = len(self._content) - 1
        else:
            end = len(self._content)
        W, F = [None] + self.get_val()[start:end], []
        for i in range(1, len(W)):
            # INDEX = i
            N = W[i]
            if N == 0:
                break
            else:
                J = [j for j in (1, 2, 4, 8, 16, 32, 64, 128, 256) if j <= i].pop()
                while i > 1:
                    if 2*i < 3*J:
                        N = 1 + (N + W[self._dec_get_w_ind(i)] + self._Range//J - 2) \
                                % (2*self._Range//J - 1)
                        i -= J>>1
                    else:
                        N = 1 + (N + W[self._dec_get_w_ind(i)] + 2*self._Range//J - 2) \
                                % (2*self._Range//J - 1)
                        i -= J
                    J = J//2
                F.append(N)
        F.sort()
        return F
    
    def _dec_get_w_ind(self, ind):
        return ind
    
    def _encode(self, arfcns):
        # TODO
        raise(PycrateErr('not implemented'))


# from 15 (W1 only) to 1013 bits (W1 -> W511), could be 1023 bits
class FreqListRange512(_FreqListRange):
    _Range  = 512
    _Layout = (9, 8, 8, 7, 7, 7, 7, 6, 6, 6, 6, 6, 6, 6, 6) + \
              16  * (5,) + \
              32  * (4,) + \
              64  * (3,) + \
              128 * (2,) + \
              256 * (1,)
    
    def _dec_get_w_ind(self, ind):
        return self._Parent[ind]


# from 8 (W1 only) to 502 bits (W1 -> W255), could be 1023 bits
class FreqListRange256(_FreqListRange):
    _Range  = 256
    _Layout = (8, 7, 7, 6, 6, 6, 6, 5, 5, 5, 5, 5, 5, 5, 5) + \
              16  * (4,) + \
              32  * (3,) + \
              64  * (2,) + \
              128 * (1,)


# from 8 (W1 only) to 247 bits (W1 to W127), could be 1023 bits
class FreqListRange128(_FreqListRange):
    _Range  = 128
    _Layout = (7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4) + \
              16 * (3,) + \
              32 * (2,) + \
              64 * (1,)


class FreqListBitmapVar(BitMap):
    
    def _decode(self):
        rrfcns = []
        rr_uint, rr_bl = self.to_uint(), self.get_bl()
        for i in range(0, rr_bl):
            if rr_uint & 1<<(rr_bl-i-1):
                rrfcns.append(i+1)
        return rrfcns
    
    def _encode(self, rrfcns):
        # bitmap length is the maximum offset, rounding to the octet boundary
        rr_uint, rr_bl = 0, max(rrfcns)
        if rr_bl % 8:
            rr_bl += -rr_bl % 8
        for o in rrfcns:
            rr_uint += 1<<(rr_bl-o-1)
        self.from_uint(rr_uint)


class FreqListAlt2(Envelope):
    _GEN = (
        Uint('FmtExt2', bl=2, dic={0: 'range 512', 1: 'range 256', 2: 'range 128', 3: 'variable bit map'}),
        Uint('OriginARFCN', val=0, bl=10),
        Alt(GEN={
            0: FreqListRange512(),
            1: FreqListRange256(),
            2: FreqListRange128(),
            3: FreqListBitmapVar()},
            sel=lambda self: self.get_env()[0].get_val())
        )
    
    def decode(self):
        """returns the list of ARFCNs set
        """
        if self[0].get_val() == 3:
            # variable bitmap
            orig_arfcn = self[1].get_val()
            add_orig_arfcn = lambda x: x+orig_arfcn
            return list(map(add_orig_arfcn, self[2].get_alt()._decode()))
        else:
            # range
            return [self[1].get_val()] + self[2].get_alt()._decode()
    
    def encode(self, arfcns):
        """sets a list of ARFCNs
        """
        arfcns = set(arfcns)
        try:
            arfcns.sort()
            orig_arfcn = arfcns.pop(0)
            self[1].set_val(orig_arfcn)
            if self[0].get_val() == 3:
                # variable bitmap, update every ARFCNs
                rem_orig_arfcn = lambda x: x-orig_arfcn
                arfcns = list(map(rem_orig_arfcn, arfcns))
            self[2].get_alt()._encode(arfcns)
        except:
            pass


# from 11 (W1 only) to 1035 bits (W1 -> W264)
class FreqListRange1024(_FreqListRange):
    _Range  = 1024
    _Layout = (10, 9, 9, 8, 8, 8, 8, 7, 7, 7, 7, 7, 7, 7, 7, 7) + \
              16  * (6,) + \
              32  * (5,) + \
              64  * (4,) + \
              128 * (3,) + \
              8   * (2,)
    _GEN    = (
        Uint('F0', val=0, bl=1),
        )
    
    def _dec_get_w_ind(self, ind):
        return self._Parent[ind]
    
    def decode(self):
        """returns the list of ARFCNs set
        """
        if self[0].get_val():
            return [0] + self._decode
        else:
            return self._decode()
    
    def encode(self, arfcns):
        """sets a list of ARFCNs
        """
        # TODO
        raise(PycrateErr('not implemented'))
    

class FreqListAlt1(Envelope):
    _GEN = (
        Uint('FmtExt', bl=1, dic={0:'range 1024'}),
        Alt(GEN={
            0: FreqListRange1024(),
            1: FreqListAlt2()},
            sel=lambda self: self.get_env()[0].get_val())
        )
    
    def decode(self):
        """returns the list of ARFCNs set
        """
        return self[1].get_alt().decode()
    
    def encode(self, arfcns):
        """sets a list of ARFCNs
        """
        self[1].get_alt().encode(arfcns)


class FreqListBitmap0(BitMap):
    _bl = 124
    
    def decode(self):
        """returns the list of ARFCNs set
        """
        arfcns = []
        ar_uint = self.to_uint()
        for i in range(0, 124):
            if ar_uint & (1<<i):
                arfcns.append(1+i)
        arfcns.sort()
        return arfcns
    
    def encode(self, arfcns):
        """sets a list of ARFCNs
        """
        ar_uint = 0
        for ar in set(arfcns):
            if isinstance(ar, integer_types) and 0 < ar <= 124:
                ar_uint += 1<<(124-ar)
        self.set_val(uint_to_bytes(ar_uint, 124))


# from 2 to 130 bytes, 16 to 1040 bits
class FreqList(Envelope):
    _GEN = (
        Uint('Fmt', bl=2, dic={0:'bit map 0', 1:'undefined', 3: 'undefined'}),
        Uint('spare', bl=2),
        Alt(GEN={
            0: FreqListBitmap0(),
            2: FreqListAlt1()},
            DEFAULT=Buf('undefined', rep=REPR_HEX),
            sel=lambda self: self.get_env()[0].get_val())
        )
    
    def decode(self):
        """returns the list of ARFCNs set
        """
        return self[2].get_alt().decode()
    
    def encode(self, arfcns):
        """sets the list of ARFCNs
        """
        # TODO: choose the best possible encoding ?!
        raise(PycrateErr('not implemented'))


#------------------------------------------------------------------------------#
# Mobile Allocation
# TS 44.018, 10.5.2.21
#------------------------------------------------------------------------------#

class MobAlloc(BitMap):
    pass


#------------------------------------------------------------------------------#
# Power Command
# TS 44.018, 10.5.2.28
#------------------------------------------------------------------------------#

class PowerCmd(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('EPCMode', bl=1),
        Uint('FPC_EPC', bl=1),
        Uint('PowerLevel', bl=5)
        )


#------------------------------------------------------------------------------#
# Starting Time
# TS 44.018, 10.5.2.38
#------------------------------------------------------------------------------#

class StartingTime(Envelope):
    _GEN = (
        Uint('T1prime', bl=5),
        Uint('T3', bl=6),
        Uint('spare', bl=5)
        )


#------------------------------------------------------------------------------#
# Extended TSC Set
# TS 44.018, 10.5.2.82
#------------------------------------------------------------------------------#

class ExtTSCSet(Envelope):
    _GEN = (
        Uint('PSSecondTSCVal', bl=3),
        Uint('PSSecondTSCSet', bl=1),
        Uint('PSPrimTSCSet', bl=1),
        Uint('PSSecondTSCAssign', bl=1),
        Uint('CSTSCSet', bl=2)
        )

