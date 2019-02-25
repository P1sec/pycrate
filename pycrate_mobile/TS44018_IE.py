# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2018. Benoit Michau. ANSSI. P1sec.
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

from .TS24007    import RestOctets
from .TS24008_IE import LAI, RAI, ID, MSCm2, BroadcastCallRef, TMGI, AddUpdateParams, \
    CellId, CKSN_dict

#------------------------------------------------------------------------------#
# TS 44.018 IE specified with CSN.1
#------------------------------------------------------------------------------#

from pycrate_csn1dir.ba_list_pref           import ba_list_pref
from pycrate_csn1dir.utran_freq_list        import utran_freq_list
from pycrate_csn1dir.individual_priorities  import individual_priorities
from pycrate_csn1dir.classmark_3_value_part import classmark_3_value_part
from pycrate_csn1dir.dynamic_arfcn_mapping  import dynamic_arfcn_mapping
from pycrate_csn1dir.ia_rest_octets         import ia_rest_octets
from pycrate_csn1dir.ipa_rest_octets        import ipa_rest_octets
from pycrate_csn1dir.iax_rest_octets        import iax_rest_octets
from pycrate_csn1dir.iar_rest_octets        import iar_rest_octets
from pycrate_csn1dir.notification_facch     import notification_facch
from pycrate_csn1dir.ntn_rest_octets        import ntn_rest_octets
from pycrate_csn1dir.vbs_vgcs_reconfigure   import vbs_vgcs_reconfigure
from pycrate_csn1dir.vbs_vgcs_reconfigure2  import vbs_vgcs_reconfigure2
from pycrate_csn1dir.p1_rest_octets         import p1_rest_octets
from pycrate_csn1dir.p2_rest_octets         import p2_rest_octets
from pycrate_csn1dir.p3_rest_octets         import p3_rest_octets
from pycrate_csn1dir.si1_rest_octets        import si1_rest_octets
from pycrate_csn1dir.si2bis_rest_octets     import si2bis_rest_octets
from pycrate_csn1dir.si2ter_rest_octets     import si2ter_rest_octets
from pycrate_csn1dir.si2quater_rest_octets  import si2quater_rest_octets
from pycrate_csn1dir.si2n_rest_octets       import si2n_rest_octets
from pycrate_csn1dir.si3_rest_octet         import si3_rest_octet
from pycrate_csn1dir.si4_rest_octets        import si4_rest_octets
from pycrate_csn1dir.si6_rest_octets        import si6_rest_octets
from pycrate_csn1dir.si9_rest_octets        import si9_rest_octets
from pycrate_csn1dir.si_13_rest_octets      import si_13_rest_octets
from pycrate_csn1dir.si16_rest_octets       import si16_rest_octets, si17_rest_octets
from pycrate_csn1dir.si_19_rest_octets      import si_19_rest_octets
from pycrate_csn1dir.si_18_rest_octets      import si_18_rest_octets
from pycrate_csn1dir.si14_rest_octets       import si14_rest_octets
from pycrate_csn1dir.si15_rest_octets       import si15_rest_octets
from pycrate_csn1dir.si_13alt_rest_octets   import si_13alt_rest_octets
from pycrate_csn1dir.si_21_rest_octets      import si_21_rest_octets
from pycrate_csn1dir.si_22_rest_octets      import si_22_rest_octets
from pycrate_csn1dir.si_23_rest_octets      import si_23_rest_octets
from pycrate_csn1dir.gprs_broadcast_information_value_part      import gprs_broadcast_information_value_part
from pycrate_csn1dir.rr_packet_uplink_assignment_value_part     import rr_packet_uplink_assignment_value_part
from pycrate_csn1dir.rr_packet_downlink_assignment_value_part   import rr_packet_downlink_assignment_value_part
from pycrate_csn1dir.dtm_information_details_value_part         import dtm_information_details_value_part
from pycrate_csn1dir.channel_request_description_2_value_part   import channel_request_description_2_value_part
from pycrate_csn1dir.packet_channel_description                 import packet_channel_description
from pycrate_csn1dir.measurement_results_contents               import measurement_results_contents
from pycrate_csn1dir.gprs_broadcast_information_value_part      import gprs_broadcast_information_value_part
from pycrate_csn1dir.mprach_description_value_part              import mprach_description_value_part
from pycrate_csn1dir.mbms_p_t_m_channel_description_value_part  import mbms_p_t_m_channel_description_value_part
from pycrate_csn1dir.mbms_session_parameters_list_value_part    import mbms_session_parameters_list_value_part
from pycrate_csn1dir.ec_packet_channel_description_type_1       import ec_packet_channel_description_type_1
from pycrate_csn1dir.rr_packet_downlink_assignment_type_2_value_part import \
    rr_packet_downlink_assignment_type_2_value_part
from pycrate_csn1dir.ec_immediate_assignment_type_2_message_content  import \
    ec_immediate_assignment_type_2_message_content
from pycrate_csn1dir.cell_selection_indicator_after_release_of_all_tch_and_sdcch_value_part import \
    cell_selection_indicator_after_release_of_all_tch_and_sdcch_value_part


#------------------------------------------------------------------------------#
# generic objects
#------------------------------------------------------------------------------#

class BitMap(Buf):
    """handles bit map
    
    derives from the Buf object and includes get() / set() / unset() methods
    for handling bit value at given offset
    """
    _rep = REPR_HEX
    
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
# BA Range
# TS 44.018, 10.5.2.1a
#------------------------------------------------------------------------------#

class BARange(Envelope):
    _GEN = (
        Uint8('Num'),
        Array('Ranges', GEN=Envelope('Range', GEN=(
            Uint('RANGE_LOWER', bl=10),
            Uint('RANGE_HIGHER', bl=10)))),
        Buf('spare', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Cell Channel Description
# TS 44.018, 10.5.2.1b
#------------------------------------------------------------------------------#
# This is the same structure as FreqList defined in 10.5.2.13,
# but with a fixed length of 16 bytes

# _FreqListRange is the generic class template for all Range* as defined 
# in 10.5.2.13
# For range 512 and range 1024, there is a W(parent) selection
# which requires some damned numerology !
# So we build a dict of W_index -> W_parent_index up to index 511 (rank 8),
# what corresponds to the longest sequence of W (for range 512)

# For all _FreqListRange / _FreqListRangeLong / _FreqListRange1024
# only Layout and eventually Range need to be set

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
        # TODO: read 44.018 annex J
        raise(PycrateErr('not implemented'))


# _FreqListRangeLong and _FreqListRange1024 are parent classes as defined in 
# 10.5.2.13
class _FreqListRangeLong(_FreqListRange):
    _Range  = 512
    
    def _dec_get_w_ind(self, ind):
        return self._Parent[ind]


class _FreqListRange1024(_FreqListRangeLong):
    _Range  = 1024
    _GEN    = (
        Uint('F0', val=0, bl=1),
        )
    
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


# _FreqListAlt2, _FreqListAlt1  and _FreqList are parent classes with common 
# methods used children classes which have different generators
class _FreqListAlt2(Envelope):
    
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


class _FreqListAlt1(Envelope):
    
    def decode(self):
        """returns the list of ARFCNs set
        """
        return self[1].get_alt().decode()
    
    def encode(self, arfcns):
        """sets a list of ARFCNs
        """
        self[1].get_alt().encode(arfcns)


class _FreqList(Envelope):
    
    def decode(self):
        """returns the list of ARFCNs set
        """
        try:
            return self[2].get_alt().decode()
        except:
            return []
    
    def encode(self, arfcns):
        """sets the list of ARFCNs
        """
        # TODO: choose the best possible encoding ?!
        raise(PycrateErr('not implemented'))


# FreqListBitmapVar and FreqListBitmap0 are defined in 10.5.2.13
# but actually used as-is in several places
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


class FreqListBitmap0(BitMap):
    _bl = 124
    
    def decode(self):
        """returns the list of ARFCNs set
        """
        arfcns = []
        ar_uint, ar_bl = self.to_uint(), 124
        for i in range(0, ar_bl):
            if ar_uint & (1<<i):
                arfcns.append(1+i)
        arfcns.sort()
        return arfcns
    
    def encode(self, arfcns):
        """sets a list of ARFCNs
        """
        ar_uint, ar_bl = 0, 124
        for ar in set(arfcns):
            if isinstance(ar, integer_types) and 0 < ar <= ar_bl:
                ar_uint += 1<<(124-ar)
        self.set_val(uint_to_bytes(ar_uint, 124))


# Actual Cell Channel definitions
class CellChanRange1024(_FreqListRange1024):
    _Layout = (10, 9, 9, 8, 8, 8, 8, 7, 7, 7, 7, 7, 7, 7, 7, 6)


class CellChanRange512(_FreqListRangeLong):
    _Layout = (9, 8, 8, 7, 7, 7, 7, 6, 6, 6, 6, 6, 6, 6, 6, 5, 5)


class CellChanRange256(_FreqListRange):
    _Range  = 256
    _Layout = (8, 7, 7, 6, 6, 6, 6, 5, 5, 5, 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4)


class CellChanRange128(_FreqListRange):
    _Range  = 128
    _Layout = (7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 
               3, 3, 3, 3, 3, 3, 3)


class CellChanAlt2(_FreqListAlt2):
    _GEN = (
        Uint('FmtExt2', bl=2, dic={0: 'range 512', 1: 'range 256', 2: 'range 128', 3: 'variable bit map'}),
        Uint('OriginARFCN', val=0, bl=10),
        Alt(GEN={
            0: CellChanRange512(),
            1: CellChanRange256(),
            2: CellChanRange128(),
            3: FreqListBitmapVar('CellChanBitmapVar', bl=111)},
            sel=lambda self: self.get_env()[0].get_val())
        )


class CellChanAlt1(_FreqListAlt1):
    _GEN = (
        Uint('FmtExt', bl=1, dic={0:'range 1024'}),
        Alt(GEN={
            0: CellChanRange1024(),
            1: CellChanAlt2()},
            sel=lambda self: self.get_env()[0].get_val())
        )


# 16 bytes, 128 bits
class CellChan(_FreqList):
    _GEN = (
        Uint('Fmt', bl=2, dic={0:'bit map 0', 1:'undefined', 3: 'undefined'}),
        Uint('spare', bl=2),
        Alt(GEN={
            0: FreqListBitmap0('CellChanBitmap0'),
            2: CellChanAlt1()},
            DEFAULT=Buf('undefined', rep=REPR_HEX),
            sel=lambda self: self.get_env()[0].get_val())
        )


#------------------------------------------------------------------------------#
# Cell Description
# TS 44.018, 10.5.2.2
#------------------------------------------------------------------------------#

class CellDesc(Envelope):
    _GEN = (
        Uint('BCCHARFCN_hi', bl=2),
        Uint('NCC', bl=3),
        Uint('BCC', bl=3),
        Uint8('BCCHARFCN_lo'),
        Uint16('BCCHARFCN', trans=True) 
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[4].set_valauto(lambda: self[3].get_val() + (self[0].get_val()<<8)) 


#------------------------------------------------------------------------------#
# Cell Options
# TS 44.018, 10.5.2.3
#------------------------------------------------------------------------------#

_DTXInd_dict = {
    0 : 'MS may use uplink discontinuous Tx',
    1 : 'MS shall use uplink discontinuous Tx',
    2 : 'MS shall not use uplink discontinuous Tx',
    }

class CellOpt(Envelope):
    _GEN = (
        Uint('DynARFCNMappingInd', bl=1),
        Uint('PwrCtrlInd', bl=1),
        Uint('DTXInd', bl=2, dic=_DTXInd_dict),
        Uint('RadioLinkTimeout', bl=4)
        )


#------------------------------------------------------------------------------#
# Cell Selection Parameters
# TS 44.018, 10.5.2.4
#------------------------------------------------------------------------------#

_CellReselHyst_dict = {
    0 : '0 dB RXLEV hysteresis for LA re-selection',
    1 : '2 dB RXLEV hysteresis for LA re-selection',
    2 : '4 dB RXLEV hysteresis for LA re-selection',
    3 : '6 dB RXLEV hysteresis for LA re-selection',
    4 : '8 dB RXLEV hysteresis for LA re-selection',
    5 : '10 dB RXLEV hysteresis for LA re-selection',
    6 : '12 dB RXLEV hysteresis for LA re-selection',
    7 : '14 dB RXLEV hysteresis for LA re-selection',
    }

_NECI_dict = {
    0 : 'New establishment causes not supported',
    1 : 'New establishment causes supported'
    }

class CellSelParams(Envelope):
    _GEN = (
        Uint('CellReselectHyst', bl=3, dic=_CellReselHyst_dict),
        Uint('MS-TXPWR-MAX-CCH', bl=5),
        Uint('ACS', bl=1),
        Uint('NECI', bl=1, dic=_NECI_dict),
        Uint('RXLEV-ACCESS-MIN', bl=6)
        )


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
# Channel Description 3
# TS 44.018, 10.5.2.5c
#------------------------------------------------------------------------------#

class ChanDesc3(Envelope):
    _GEN = (
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
            sel=lambda self:self.get_env()[1].get_val())
        )


#------------------------------------------------------------------------------#
# Channel Mode
# TS 44.018, 10.5.2.6
#------------------------------------------------------------------------------#

class ChanMode(Uint8):
    _dic = {
        0   : 'signalling only',
        1   : 'GSM FR or GSM HR',
        0xc1: 'GSM FR or GSM HR in VAMOS mode',
        0x21: 'GSM EFR',
        0xc2: 'GSM EFR in VAMOS mode',
        0x41: 'FR AMR or HR AMR',
        0xc3: 'FR AMR or HR AMR in VAMOS mode',
        0x81: 'OFR AMR-WB or OHR AMR-WB',
        0x82: 'FR AMR-WB',
        0xc5: 'FR AMR-WB in VAMOS mode',
        0x83: 'OHR AMR',
        0x61: 'data, 43.5 kbit/s (downlink)+14.5 kbps (uplink)',
        0x62: 'data, 29.0 kbit/s (downlink)+14.5 kbps (uplink)',
        0x64: 'data, 43.5 kbit/s (downlink)+29.0 kbps (uplink)',
        0x67: 'data, 14.5 kbit/s (downlink)+43.5 kbps (uplink)',
        0x65: 'data, 14.5 kbit/s (downlink)+29.0 kbps (uplink)',
        0x66: 'data, 29.0 kbit/s (downlink)+43.5 kbps (uplink)',
        0x47: 'data, 43.5 kbit/s radio interface rate',
        0x63: 'data, 32.0 kbit/s radio interface rate',
        0x43: 'data, 29.0 kbit/s radio interface rate',
        15  : 'data, 14.5 kbit/s radio interface rate',
        3   : 'data, 12.0 kbit/s radio interface rate',
        11  : 'data, 6.0 kbit/s radio interface rate',
        0x13: 'data, 6.0 kbit/s radio interface rate',
        0x10: 'data, 64.0 kbit/s Transparent Data Bearer'
        }


#------------------------------------------------------------------------------#
# Channel Mode 2
# TS 44.018, 10.5.2.7
#------------------------------------------------------------------------------#

class ChanMode2(Uint8):
    _dic = {
        0   : 'signalling only',
        5   : 'GSM HR',
        0xc1: 'GSM HR in VAMOS mode',
        0x25: 'speech half rate version 2',
        0x45: 'HR AMR',
        0xc3: 'HR AMR in VAMOS mode',
        0x85: 'OHR AMR-WB',
        0x46: 'OHR AMR',
        15  : 'data, 6.0 kbit/s radio interface rate',
        0x17: 'data, 3.6 kbit/s radio interface rate'
        }


#------------------------------------------------------------------------------#
# Classmark Enquiry Mask
# TS 44.018, 10.5.2.7c
#------------------------------------------------------------------------------#

class CmEnquiryMask(Envelope):
    _GEN = (
        Uint('CmChange', bl=1, dic={0:'requested', 1:'not requested'}),
        Uint('UTRANCmChange', bl=3, dic={0:'requested', 7:'not requested'}),
        Uint('cdma2000CmChange', bl=1, dic={0:'requested', 1:'not requested'}),
        Uint('GERANIUModeCmChange', bl=1, dic={0:'requested', 1:'not requested'}),
        Uint('spare', bl=2)
        )


#------------------------------------------------------------------------------#
# Channel Needed
# TS 44.018, 10.5.2.8
#------------------------------------------------------------------------------#

_ChanNeeded_dict = {
    0 : 'Any channel',
    1 : 'SDCCH',
    2 : 'TCH/F (Full rate)',
    3 : 'TCH/H or TCH/F (Dual rate)'
    }

class ChanNeeded(Envelope):
    _GEN = (
        Uint('SECOND', bl=2, dic=_ChanNeeded_dict),
        Uint('FIRST', bl=2, dic=_ChanNeeded_dict)
        )


#------------------------------------------------------------------------------#
# Cipher Mode Setting
# TS 44.018, 10.5.2.9
#------------------------------------------------------------------------------#

_AlgoId_dict = {
    0 : 'A5/1',
    1 : 'A5/2',
    2 : 'A5/3',
    3 : 'A5/4',
    4 : 'A5/5',
    5 : 'A5/6',
    6 : 'A5/7',
    7 : 'reserved'
    }

class CipherModeSetting(Envelope):
    _GEN = (
        Uint('AlgoId', bl=3, dic=_AlgoId_dict),
        Uint('SC', bl=1, dic={0:'no ciphering', 1:'start ciphering'})
        )


#------------------------------------------------------------------------------#
# Cipher Response
# TS 44.018, 10.5.2.10
#------------------------------------------------------------------------------#

class CipherResp(Envelope):
    _GEN = (
        Uint('spare', bl=3),
        Uint('CR', bl=1, dic={0:'IMEISV shall not be included', 1:'IMEISV shall be included'})
        )


#------------------------------------------------------------------------------#
# Control Channel Description
# TS 44.018, 10.5.2.11
#------------------------------------------------------------------------------#

_CCCHConf_dict = {
    0 : '1 PHY chan for CCCH, not combined with SDCCH',
    1 : '1 PHY chan for CCCH, combined with SDCCH',
    2 : '2 PHY chan for CCCH, combined with SDCCH',
    4 : '3 PHY chan for CCCH, combined with SDCCH',
    6 : '4 PHY chan for CCCH, combined with SDCCH',
}

_CBQ3_dict = {
    0 : 'Iu mode not supported',
    1 : 'Iu mode capable MSs barred',
    2 : 'Iu mode supported, cell not barred',
    3 : 'Iu mode supported, cell not barred. The network shall not use this value.'
    }

class CtrlChanDesc(Envelope):
    _GEN = (
        Uint('MSCRel', bl=1, dic={0:'release 98 or older', 1:'release 99 onwards'}),
        Uint('ATT', bl=1, dic={0:'IMSI attach and detach not allowed', 1:'MS shall apply IMSI attach and detach'}),
        Uint('BS-AG-BLKS-RES', bl=3),
        Uint('CCCHConf', bl=3, dic=_CCCHConf_dict),
        Uint('SI22Ind', bl=1, dic={1:'SI22 broadcasted'}),
        Uint('CBQ3', bl=2, dic=_CBQ3_dict),
        Uint('spare', bl=2),
        Uint('BS-PA-MFRMS', bl=3),
        Uint8('T3212', dic={0:'periodic location updating shall not be used in the cell'})
        )


#------------------------------------------------------------------------------#
# Frequency Channel Sequence
# TS 44.018, 10.5.2.12
#------------------------------------------------------------------------------#

class FreqChanSeq(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('LowestARFCN', bl=7),
        Array(GEN=Uint('IncSkipARFCN', bl=4), num=16)
        )


#------------------------------------------------------------------------------#
# Frequency List
# TS 44.018, 10.5.2.13
#------------------------------------------------------------------------------#

# from 11 (W1 only) to 1035 bits (W1 -> W264)
class FreqListRange1024(_FreqListRange):
    _Layout = (10, 9, 9, 8, 8, 8, 8, 7, 7, 7, 7, 7, 7, 7, 7) + \
              16  * (6,) + \
              32  * (5,) + \
              64  * (4,) + \
              128 * (3,) + \
              11  * (2,)


# from 15 (W1 only) to 1013 bits (W1 -> W511), could be 1023 bits
class FreqListRange512(_FreqListRange):
    _Layout = (9, 8, 8, 7, 7, 7, 7, 6, 6, 6, 6, 6, 6, 6, 6) + \
              16  * (5,) + \
              32  * (4,) + \
              64  * (3,) + \
              128 * (2,) + \
              256 * (1,)


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


class FreqListAlt2(_FreqListAlt2):
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


class FreqListAlt1(_FreqListAlt1):
    _GEN = (
        Uint('FmtExt', bl=1, dic={0:'range 1024'}),
        Alt(GEN={
            0: FreqListRange1024(),
            1: FreqListAlt2()},
            sel=lambda self: self.get_env()[0].get_val())
        )


# from 2 to 130 bytes, 16 to 1040 bits
class FreqList(_FreqList):
    _GEN = (
        Uint('Fmt', bl=2, dic={0:'bit map 0', 1:'undefined', 3: 'undefined'}),
        Uint('spare', bl=2),
        Alt(GEN={
            0: FreqListBitmap0(),
            2: FreqListAlt1()},
            DEFAULT=Buf('undefined', rep=REPR_HEX),
            sel=lambda self: self.get_env()[0].get_val())
        )


#------------------------------------------------------------------------------#
# Frequency Short List
# TS 44.018, 10.5.2.14
#------------------------------------------------------------------------------#
# This is the same structure as FreqList defined in 10.5.2.13,
# but with a fixed length of 9 bytes

class FreqShortListRange1024(_FreqListRange1024):
    _Layout = (10, 9, 9, 8, 8, 8, 8)


class FreqShortListRange512(_FreqListRangeLong):
    _Layout = (9, 8, 8, 7, 7, 7, 7)


class FreqShortListRange256(_FreqListRange):
    _Range  = 256
    _Layout = (8, 7, 7, 6, 6, 6, 6, 5)


class FreqShortListRange128(_FreqListRange):
    _Range  = 128
    _Layout = (7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4)


class FreqShortListAlt2(_FreqListAlt2):
    _GEN = (
        Uint('FmtExt2', bl=2, dic={0: 'range 512', 1: 'range 256', 2: 'range 128', 3: 'variable bit map'}),
        Uint('OriginARFCN', val=0, bl=10),
        Alt(GEN={
            0: FreqShortListRange512(),
            1: FreqShortListRange256(),
            2: FreqShortListRange128(),
            3: FreqListBitmapVar('FreqShortListBitmapVar', bl=55)},
            sel=lambda self: self.get_env()[0].get_val())
        )


class FreqShortListAlt1(_FreqListAlt1):
    _GEN = (
        Uint('FmtExt', bl=1, dic={0:'range 1024'}),
        Alt(GEN={
            0: FreqShortListRange1024(),
            1: FreqShortListAlt2()},
            sel=lambda self: self.get_env()[0].get_val())
        )


# 9 bytes, 72 bits
class FreqShortList(_FreqList):
    _GEN = (
        Uint('Fmt', val=2, bl=2),
        Uint('spare', bl=2),
        Alt(GEN={
            2: FreqShortListAlt1()},
            DEFAULT=Buf('undefined', rep=REPR_HEX),
            sel=lambda self: self.get_env()[0].get_val())
        )


#------------------------------------------------------------------------------#
# Group Channel Description
# TS 44.018, 10.5.2.14b
#------------------------------------------------------------------------------#

GroupChanDescType_dict = {
    1  : 'TCH/FS + ACCHs (speech codec version 1)',
    2  : 'TCH/HS + ACCHs (speech codec version 1); subchannel 0',
    3  : 'TCH/HS + ACCHs (speech codec version 1); subchannel 1',
    16 : 'TCH/FS + ACCHs (speech codec version 2)',
    17 : 'TCH/AFS + ACCHs (speech codec version 3)',
    18 : 'TCH/AHS + ACCHs (speech codec version 3); subchannel 0',
    19 : 'TCH/AHS + ACCHs (speech codec version 3); subchannel 1',
    4  : 'SDCCH/4 + SACCH/C4; subchannel 0',
    5  : 'SDCCH/4 + SACCH/C4; subchannel 1',
    6  : 'SDCCH/4 + SACCH/C4; subchannel 2',
    7  : 'SDCCH/4 + SACCH/C4; subchannel 3',
    8  : 'SDCCH/8 + SACCH/C8; subchannel 0',
    9  : 'SDCCH/8 + SACCH/C8; subchannel 1',
    10 : 'SDCCH/8 + SACCH/C8; subchannel 2',
    11 : 'SDCCH/8 + SACCH/C8; subchannel 3',
    12 : 'SDCCH/8 + SACCH/C8; subchannel 4',
    13 : 'SDCCH/8 + SACCH/C8; subchannel 5',
    14 : 'SDCCH/8 + SACCH/C8; subchannel 6',
    15 : 'SDCCH/8 + SACCH/C8; subchannel 7',
    }

class GroupChanDesc(Envelope):
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
            sel=lambda self:self.get_env()[3].get_val()),
        BitMap('MobileAllocChan')
        )


#------------------------------------------------------------------------------#
# GPRS Resumption
# TS 44.018, 10.5.2.14c
#------------------------------------------------------------------------------#

class GPRSResumption(Envelope):
    _GEN = (
        Uint('spare', bl=3),
        Uint('ACK', bl=1,
             dic={0:'resumption of GPRS services not successfully acknowledged',
                  1:'resumption of GPRS services successfully acknowledged'})
        )


#------------------------------------------------------------------------------#
# Group Channel Description 2
# TS 44.018, 10.5.2.14f
#------------------------------------------------------------------------------#

class GroupChanDesc2(Envelope):
    _GEN = (
        Uint('ChanType', bl=5, dic=ChanDescType_dict),
        Uint('TN', bl=3),
        Uint('TSC', bl=3),
        Uint('spare', bl=1),
        Uint('MAIO', bl=6),
        Uint('HSN', bl=6),
        BitMap('MobileAllocChan')
        )


#------------------------------------------------------------------------------#
# Handover Reference
# TS 44.018, 10.5.2.15
#------------------------------------------------------------------------------#

class HandoverRef(Uint8):
    pass


#------------------------------------------------------------------------------#
# L2 Pseudo Length
# TS 44.018, 10.5.2.19
#------------------------------------------------------------------------------#
# The length value is automated to sum up the length of all IE within a RR msg
# after the L2PseudoLength (index 0) and before the RestOctets (index -1)

class L2PseudoLength(Envelope):
    _GEN  = (
        Uint('Value', bl=6),
        Uint('M', val=0, bl=1),
        Uint('EL', val=1, bl=1)
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        if self[0]._val is None:
            # in case the Value is not fixed at init, it is handled in 
            # a dynamic way
            self[0].set_valauto(lambda: self._get_l2pl())
    
    def _get_l2pl(self):
        l2pl = 0
        for elt in self.get_env()._content[1:]:
            if isinstance(elt, RestOctets):
                break
            else:
                l2pl += elt.get_bl()
        return l2pl>>3


#------------------------------------------------------------------------------#
# Mobile Allocation
# TS 44.018, 10.5.2.21
#------------------------------------------------------------------------------#

class MobileAlloc(BitMap):
    pass


#------------------------------------------------------------------------------#
# Mobile Time Difference
# TS 44.018, 10.5.2.21a
#------------------------------------------------------------------------------#

class MobileTimeDiff(Envelope):
    _GEN = (
        Uint('Value', bl=21),
        Uint('spare', bl=3)
        )


#------------------------------------------------------------------------------#
# MultiRate configuration
# TS 44.018, 10.5.2.21aa
#------------------------------------------------------------------------------#

class MultirateConfig(BitMap):
    _GEN = (
        Uint('MultirateSpeechVers', bl=3,
             dic={1:'FR AMR, HR AMR or OHR AMR ',
                  2:'FR AMR-WB, OFR AMR-WB or OHR AMR-WB'}),
        Uint('NSCB', bl=1),
        Uint('ICMI', bl=1),
        Uint('spare', bl=1),
        Uint('StartMode', bl=2),
        Buf('ParamsMultirateSpeech', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Mobile Time Difference on Hyperframe level
# TS 44.018, 10.5.2.21ab
#------------------------------------------------------------------------------#

class MobileTimeDiffHFLevel(Envelope):
    _GEN = (
        Uint('Value', bl=33),
        Uint('spare', bl=3)
        )


#------------------------------------------------------------------------------#
# Multislot Allocation
# TS 44.018, 10.5.2.21b
#------------------------------------------------------------------------------#

class MultislotAllocUA(Envelope):
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('UA', bl=7)
        )
         
class MultislotAlloc(Envelope):
    _GEN = (
        Uint('ext', bl=1),
        Uint('DA', bl=7),
        MultislotAllocUA(),
        BitMap('ChannelSets')
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_transauto(lambda: True if self[1].get_val() else False)


#------------------------------------------------------------------------------#
# Neighbour Cell Description
# TS 44.018, 10.5.2.22
#------------------------------------------------------------------------------#
# coded as the Cell Channel Description information element in 10.5.2.1b
# except spare bits

class NeighbourCellChan(Envelope):
    _GEN = (
        Uint('Fmt', bl=2, dic={0:'bit map 0', 1:'undefined', 3: 'undefined'}),
        Uint('ExtInd', bl=1, dic={0:'complete BA', 1:'part of BA'}),
        Uint('BAInd', bl=1, dic={0:'BA(BCCH)', 1:'BA(SACCH)'}),
        Alt(GEN={
            0: FreqListBitmap0('CellChanBitmap0'),
            2: CellChanAlt1()},
            DEFAULT=Buf('undefined', rep=REPR_HEX),
            sel=lambda self: self.get_env()[0].get_val())
        )
    
    def decode(self):
        """returns the list of ARFCNs set
        """
        try:
            return self[3].get_alt().decode()
        except:
            return []
    
    def encode(self, arfcns):
        """sets the list of ARFCNs
        """
        # TODO: choose the best possible encoding ?!
        raise(PycrateErr('not implemented'))


#------------------------------------------------------------------------------#
# Neighbour Cell Description 2
# TS 44.018, 10.5.2.22a
#------------------------------------------------------------------------------#
# coded as the Cell Channel Description information element in 10.5.2.1b
# except some changes in the 1st byte

class NeighbourCellChan2(Envelope):
    _GEN = (
        Uint('Fmt', bl=1),
        Uint('MultibandReport', bl=2),
        Uint('BAInd', bl=1, dic={0:'BA(BCCH)', 1:'BA(SACCH)'}),
        Alt(GEN={
            0: FreqListBitmap0('CellChanBitmap0'),
            1: CellChanAlt1()},
            sel=lambda self: self.get_env()[0].get_val())
        )
    
    def decode(self):
        """returns the list of ARFCNs set
        """
        try:
            return self[3].get_alt().decode()
        except:
            return []
    
    def encode(self, arfcns):
        """sets the list of ARFCNs
        """
        # TODO: choose the best possible encoding ?!
        raise(PycrateErr('not implemented'))


#------------------------------------------------------------------------------#
# Dedicated Mode or TBF
# TS 44.018, 10.5.2.25b
#------------------------------------------------------------------------------#

class DedicatedModeOrTBF(Envelope):
    _GEN = (
        Uint('NRA', bl=1),
        Uint('TMA', bl=1),
        Uint('Downlink', bl=1, dic={0:'UL', 1:'DL'}),
        Uint('TD', bl=1, dic={0:'dedicated mode', 1:'TBF'})
        )


#------------------------------------------------------------------------------#
# Page Mode
# TS 44.018, 10.5.2.26
#------------------------------------------------------------------------------#

PageMode_dict ={
    0:'normal paging',
    1:'extended paging',
    2:'paging reorganization',
    3:'same as before'
    }


#------------------------------------------------------------------------------#
# NCC Permitted
# TS 44.018, 10.5.2.27
#------------------------------------------------------------------------------#

class NCCPermitted(BitMap):
    _bl = 8


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
# Power Command and access type
# TS 44.018, 10.5.2.28a
#------------------------------------------------------------------------------#

class PowerCmdAccType(Envelope):
    _GEN = (
        Uint('ATC', bl=1, dic={0:'sending of Handover Access mandatory',
            1:'sending of Handover Access optional'}),
        Uint('EPCMode', bl=1),
        Uint('FPC_EPC', bl=1),
        Uint('PowerLevel', bl=5)
        )


#------------------------------------------------------------------------------#
# RACH Control Parameters
# TS 44.018, 10.5.2.29
#------------------------------------------------------------------------------#

_MaxRetrans_dict = {
    0 : '1 retransmission max',
    1 : '2 retransmissions max',
    2 : '4 retransmissions max',
    3 : '7 retransmissions max'
    }

_TxInt_dict = {
    0 : '3 slots',
    1 : '4 slots',
    2 : '5 slots',
    3 : '6 slots',
    4 : '7 slots',
    5 : '8 slots',
    6 : '9 slots',
    7 : '10 slots',
    8 : '11 slots',
    9 : '12 slots',
    10 : '14 slots',
    11 : '16 slots',
    12 : '20 slots',
    13 : '25 slots',
    14 : '32 slots',
    15 : '50 slots'
    }

class RACHCtrl(Envelope):
    _GEN = (
        Uint('MaxRetrans', bl=2, dic=_MaxRetrans_dict),
        Uint('TxInt', bl=4, dic=_TxInt_dict),
        Uint('CELL_BARR_ACCESS', bl=1, dic={0:'cell not barred', 1:'cell barred'}),
        Uint('CallReestab', bl=1, dic={0:'allowed', 1:'not allowed'}),
        BitMap('AccessCtrlClass', bl=16)
        )


#------------------------------------------------------------------------------#
# Request Reference
# TS 44.018, 10.5.2.30
#------------------------------------------------------------------------------#

class RequestRef(Envelope):
    _GEN = (
        Uint8('RA'),
        Uint('T1prime', bl=5),
        Uint('T3', bl=6),
        Uint('T2', bl=5)
        )

#------------------------------------------------------------------------------#
# Random Reference/ Establishment Cause
# TS 44.018, 10.5.2.30a
#------------------------------------------------------------------------------#

_EstabCause_dict = {
    0 : 'Reset emergency talker indication',
    5 : 'Privilege subscriber request',
    6 : 'reserved',
    7 : 'Emergency subscriber request'
    }

class EstabCauseRandomRef(Envelope):
    _GEN = (
        Uint('EstabCause', bl=3, dic=_EstabCause_dict),
        Uint('RandomRef', bl=5)
        )


#------------------------------------------------------------------------------#
# RR Cause
# TS 44.018, 10.5.2.31
#------------------------------------------------------------------------------#

class RRCause(Uint8):
    _dic = {
        0   : 'Normal event',
        1   : 'Abnormal release, unspecified',
        2   : 'Abnormal release, channel unacceptable',
        3   : 'Abnormal release, timer expired',
        4   : 'Abnormal release, no activity on the radio path',
        5   : 'Preemptive release',
        6   : 'UTRAN configuration unknown',
        8   : 'Handover impossible, timing advance out of range',
        9   : 'Channel mode unacceptable',
        10  : 'Frequency not implemented',
        11  : 'Originator or talker leaving group call area',
        12  : 'Lower layer failure',
        0x41: 'Call already cleared',
        0x5F: 'Semantically incorrect message',
        0x60: 'Invalid mandatory information',
        0x61: 'Message type non-existent or not implemented',
        0x62: 'Message type not compatible with protocol state',
        0x64: 'Conditional IE error',
        0x65: 'No cell allocation available',
        0x6F: 'Protocol error unspecified'
        }


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
# Synchronization Indication
# TS 44.018, 10.5.2.39
#------------------------------------------------------------------------------#

_SI_dict = {
    0 : 'Non-synchronized',
    1 : 'Synchronized',
    2 : 'Pre-synchronised',
    3 : 'Pseudo-synchronised',
    }

class SynchInd(Envelope):
    _GEN = (
        Uint('NCI', bl=1),
        Uint('ROT', bl=1),
        Uint('SI', bl=2, dic=_SI_dict)
        )


#------------------------------------------------------------------------------#
# Timing Advance
# TS 44.018, 10.5.2.40
#------------------------------------------------------------------------------#

class TimingAdvance(Uint8):
    pass


#------------------------------------------------------------------------------#
# Time Difference
# TS 44.018, 10.5.2.41
#------------------------------------------------------------------------------#

class TimeDiff(Uint8):
    pass


#------------------------------------------------------------------------------#
# TLLI
# TS 44.018, 10.5.2.41a
#------------------------------------------------------------------------------#

class TLLI(Uint32):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# TMSI / P-TMSI
# TS 44.018, 10.5.2.42
#------------------------------------------------------------------------------#

class TMSI(Uint32):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# VGCS Ciphering Parameters
# TS 44.018, 10.5.2.42b
#------------------------------------------------------------------------------#

class VGCSCipherParams(Envelope):
    _GEN = (
        Uint('spare', bl=2),
        Uint('RANDInd', val=0, bl=1),
        Uint('LACInd', val=0, bl=1),
        Uint('CellInd', val=0, bl=1),
        Uint('B22Count', bl=1),
        Uint('CellGlobalCount', bl=1),
        Uint16('CellId', rep=REPR_HEX),
        LAI(),
        Buf('VSTK_RAND', bl=36, rep=REPR_HEX),
        Uint('spare', bl=4, rep=REPR_HEX)
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[6].set_transauto(lambda: False if self[3].get_val() else True)
        self[7].set_transauto(lambda: False if self[2].get_val() else True)
        self[8].set_transauto(lambda: False if self[1].get_val() else True)
        self[9].set_transauto(lambda: False if self[1].get_val() else True)


#------------------------------------------------------------------------------#
# VGCS target mode Indication
# TS 44.018, 10.5.2.42a
#------------------------------------------------------------------------------#

class VGCSTargetModeInd(Envelope):
    _GEN = (
        Uint('TargetMode', bl=2, dic={0:'dedicated mode', 1:'group transmit mode'}),
        Uint('GroupCipherKeyNum', bl=4),
        Uint('spare', bl=2)
        )


#------------------------------------------------------------------------------#
# Wait Indication
# TS 44.018, 10.5.2.43
#------------------------------------------------------------------------------#

class T3122(Uint8):
    pass

class T3142(Uint8):
    pass


#------------------------------------------------------------------------------#
# Extended Measurement Results
# TS 44.018, 10.5.2.45
#------------------------------------------------------------------------------#

class ExtMeasRes(Envelope):
    _GEN = (
        Uint('SeqCodeUsed', bl=1),
        Uint('DTXUsed', bl=1),
        Array(GEN=Uint('RXLevel', bl=6))
        )


#------------------------------------------------------------------------------#
# Extended Measurement Frequency List
# TS 44.018, 10.5.2.46
#------------------------------------------------------------------------------#
# coded as the Cell Channel Description information element in 10.5.2.1b
# except spare bits

class ExtMeasFreqList(Envelope):
    _GEN = (
        Uint('Fmt', bl=2, dic={0:'bit map 0', 1:'undefined', 3: 'undefined'}),
        Uint('spare', bl=1),
        Uint('SeqCode', bl=1),
        Alt(GEN={
            0: FreqListBitmap0('CellChanBitmap0'),
            2: CellChanAlt1()},
            DEFAULT=Buf('undefined', rep=REPR_HEX),
            sel=lambda self: self.get_env()[0].get_val())
        )


#------------------------------------------------------------------------------#
# Suspension Cause
# TS 44.018, 10.5.2.47
#------------------------------------------------------------------------------#

class SuspensionCause(Uint8):
    _dic = {
        0 : 'Emergency call, mobile originating call or call re-establishment',
        1 : 'Location Area Update',
        2 : 'MO Short message service',
        3 : 'Other procedure which can be completed with an SDCCH',
        4 : 'MO Voice broadcast or group call',
        5 : 'Mobile terminating CS connection',
        6 : 'DTM not supported in the cell'
        }


#------------------------------------------------------------------------------#
# APDU ID
# TS 44.018, 10.5.2.48
#------------------------------------------------------------------------------#

APDUID_dict = {
    0 : 'RRLP (3GPP TS 44.031) / LCS',
    1 : 'ETWS (3GPP TS 23.041)'
    }


#------------------------------------------------------------------------------#
# APDU Flags
# TS 44.018, 10.5.2.49
#------------------------------------------------------------------------------#

class APDUFlags(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('CR', bl=1),
        Uint('FirstSeg', bl=1, dic={0:'first or only segment', 1:'not first or only segment'}),
        Uint('LastSeg', bl=1, dic={0:'last or only segment', 1:'not last or only segment'})
        )


#------------------------------------------------------------------------------#
# Service Support
# TS 44.018, 10.5.2.57
#------------------------------------------------------------------------------#

_ServiceSupport_dict = {
    0:'notification not required',
    1:'notification required'
    }

class ServiceSupport(Envelope):
    _GEN = (
        Uint('spare', bl=6),
        Uint('MBMSMulticast', bl=1, dic=_ServiceSupport_dict),
        Uint('MBMSBroadcast', bl=1, dic=_ServiceSupport_dict)
        )


#------------------------------------------------------------------------------#
# Dedicated Service Information
# TS 44.018, 10.5.2.59
#------------------------------------------------------------------------------#

class DedicatedServiceInfo(Envelope):
    _GEN = (
        Uint('spare', bl=7),
        Uint('SIS', bl=1)
        )


#------------------------------------------------------------------------------#
# Restriction Timer
# TS 44.018, 10.5.2.61
#------------------------------------------------------------------------------#

class RestrictionTimer(Envelope):
    _GEN = (
        Uint('Value', bl=4),
        Uint('spare', bl=4)
        )


#------------------------------------------------------------------------------#
# MBMS Session Identity
# TS 44.018, 10.5.2.62
#------------------------------------------------------------------------------#

class MBMSSessionId(Uint8):
    pass


#------------------------------------------------------------------------------#
# Reduced group or broadcast call reference
# TS 44.018, 10.5.2.63
#------------------------------------------------------------------------------#

class ReducedBroadcastCallRef(Envelope):
    _GEN = (
        Uint('Value', bl=27, rep=REPR_HEX),
        Uint('SF', bl=1, dic={0:'VBS, broadcast call', 1:'VGCS, group call'}),
        Uint('spare', bl=4),
        )


#------------------------------------------------------------------------------#
# Talker Priority Status
# TS 44.018, 10.5.2.64
#------------------------------------------------------------------------------#

class TalkerPriorityStat(Envelope):
    _GEN = (
        Uint('ES', bl=1, dic={0:'emergency mode not set', 1:'emergency mode set'}),
        Uint('spare', bl=3),
        Uint('UAI', bl=1, dic={0:'Group channel', 1:'RACH access'}),
        Uint('Priority', bl=3, dic={0:'normal', 1:'privileged', 2:'emergency'})
        )


#------------------------------------------------------------------------------#
# Talker Identity
# TS 44.018, 10.5.2.65
#------------------------------------------------------------------------------#

class TalkerId(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('FillerBits', bl=4),
        Buf('Value', rep=REPR_HEX)        
        )


#------------------------------------------------------------------------------#
# Token
# TS 44.018, 10.5.2.66
#------------------------------------------------------------------------------#

class Token(Uint32):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# PS Cause
# TS 44.018, 10.5.2.67
#------------------------------------------------------------------------------#

PSCause_dict = {
    0 : 'DTM multislot capabilities violated',
    1 : 'No uplink TBF',
    2 : 'Too m'
    }


#------------------------------------------------------------------------------#
# Carrier Indication
# TS 44.018, 10.5.2.69
#------------------------------------------------------------------------------#

class CarrierInd(Envelope):
    _GEN = (
        Uint('spare', bl=2),
        Uint('CI', bl=1, dic={0:'Carrier 1', 1:'Carrier 2'})      
        )


#------------------------------------------------------------------------------#
# Data Identity
# TS 44.018, 10.5.2.73
#------------------------------------------------------------------------------#

class DataId(Envelope):
    _GEN = (
        Envelope('DataDistrib', GEN=(
            Uint('TalkersListeners', bl=1),
            Uint('Dispatchers', bl=1),
            Uint('NetworkApplication', bl=1))),
        Uint('DataId', bl=4),
        Uint('AppInd', bl=1, dic={0:'application-specific data',
            1:'confirmation of receiving application-specific data'})
        )


#------------------------------------------------------------------------------#
# Uplink Access Indication
# TS 44.018, 10.5.2.74
#------------------------------------------------------------------------------#

class UplinkAccessInd(Envelope):
    _GEN = (
        Uint('spare', bl=3),
        Uint('Value', bl=1, dic={1:'Uplink access for application-specific data on the RACH',
            0:'Uplink access for application-specific data on the group call channel'})
        )


#------------------------------------------------------------------------------#
# Feature Indicator
# TS 44.018, 10.5.2.76
#------------------------------------------------------------------------------#

class FeatureInd(Envelope):
    _GEN = (
        Uint('PEO_BCCH_CHANGE_MARK', bl=2),
        Uint('CS_IR', bl=1),
        Uint('PS_IR', bl=1)
        )


#------------------------------------------------------------------------------#
# PLMN Index
# TS 44.018, 10.5.2.81
#------------------------------------------------------------------------------#

PLMNIndex_dict = {
    1 : 'PLMN identity of the Common PLMN broadcast in SYSTEM INFORMATION TYPE 3/4',
    2 : 'PLMN identity of the first Additional PLMN in the network sharing information broadcast '\
        'in SYSTEM INFORMATION TYPE 22',
    3 : 'PLMN identity of the second Additional PLMN in the network sharing information broadcast broadcast '\
        'in SYSTEM INFORMATION TYPE 22',
    4 : 'PLMN identity of the third Additional PLMN in the network sharing information broadcast '\
        'in SYSTEM INFORMATION TYPE 22',
    5 : 'PLMN identity of the fourth Additional PLMN in the network sharing information broadcast '\
        'in SYSTEM INFORMATION TYPE 22'
    }


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


#------------------------------------------------------------------------------#
# Request Reference Alt
# TS 44.018, 10.5.2.87
#------------------------------------------------------------------------------#

class RequestRefAlt(Envelope):
    _GEN = (
        Uint('RA_lo', bl=3),
        Uint('RAType', bl=2),
        Uint('spare', bl=3),
        Uint8('RA_hi'),
        Uint('T1prime', bl=5),
        Uint('T3', bl=6),
        Uint('T2', bl=5),
        Uint16('RA', trans=True)
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[7].set_valauto(lambda: self[0].get_val() + (self[3].get_val()<<3))

