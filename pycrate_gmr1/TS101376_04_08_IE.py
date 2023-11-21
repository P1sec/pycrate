# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2018. Benoit Michau. P1Sec.
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
# * File Name : pycrate_mobile/TS101376_04_08_IE.py
# * Created : 2018-12-26
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# ETSI TS 101 376 04-08 GMR-1 NAS protocol IEs
# release V3.4.1
#------------------------------------------------------------------------------#

from pycrate_core.utils     import *
from pycrate_core.elt       import *
from pycrate_core.base      import *
from pycrate_mobile.TS24007 import *

from pycrate_mobile.TS24008_IE import (
    ID,
    CalledPartyBCDNumber
    )
from pycrate_mobile.TS44018_IE import (
    L2PseudoLength,
    TMSI,
    CipherResp,
    CipherModeSetting
    )
from pycrate_mobile.TS23038    import (
    encode_7b,
    decode_7b
    )


#------------------------------------------------------------------------------#
# TS 101 376 04-08 IE specified with CSN.1
#------------------------------------------------------------------------------#

from pycrate_gmr1_csn1.prefixed_gps_position_ie import prefixed_gps_position_ie


#------------------------------------------------------------------------------#
# Channel description
# TS 101 376 04-08, section 11.5.2.5
#------------------------------------------------------------------------------#

ChanType_dict = {
    1 : 'TCH3 No offset',
    3 : 'TCH3 1/2 symbol offset',
    4 : 'TCH9 No offset',
    5 : 'TCH9 1/2 symbol offset',
    6 : 'TCH6 No offset',
    7 : 'TCH6 1/2 symbol offset',
    13: 'Reserved for SDCCH frames xx00',
    14: 'Reserved for SDCCH frames xx01',
    15: 'Reserved for SDCCH frames xx10',
    16: 'Reserved for SDCCH frames xx11'
    }

class ChanDesc(Envelope):
    _GEN = (
        Uint('KABLocation', bl=6),
        Uint('RXTimeslot', bl=5),
        Uint('ARFCN', bl=11),
        Uint('TXTimeslot', bl=5),
        Uint('ChanType', bl=5, dic=ChanType_dict)
        )


#------------------------------------------------------------------------------#
# Page mode
# TS 101 376 04-08, section 11.5.2.26
#------------------------------------------------------------------------------#

PageMode_dict = {
    0 : 'Normal paging',
    1 : 'reserved',
    2 : 'Paging reorganization',
    3 : 'Same as before'
    }

 
#------------------------------------------------------------------------------#
# Request Reference
# TS 101 376 04-08, section 11.5.2.30
#------------------------------------------------------------------------------#

class RequestRef(Envelope):
    _GEN = (
        Uint('EstabCauseGroupID', bl=3),
        Uint('RandAccessInfo', bl=5),
        Uint8('FrameNum')
        )


#------------------------------------------------------------------------------#
# RR cause
# TS 101 376 04-08, section 11.5.2.31
#------------------------------------------------------------------------------#

class RRCause(Uint8):
    _dic = {
        0 : 'Normal event',
        1 : 'Abnormal release, unspecified',
        2 : 'Abnormal release, channel unacceptable',
        3 : 'Abnormal release, timer expired',
        4 : 'Abnormal release, no activity on the radio path',
        5 : 'Preemptive release',
        9 : 'Channel mode unacceptable',
        10: 'Frequency not implemented',
        11: 'Position unacceptable',
        65: 'Call already cleared',
        95: 'Semantically incorrect message',
        96: 'Invalid mandatory information',
        97: 'Message type nonexistent or not implemented',
        98: 'Message type not compatible with protocol state',
        111: 'Protocol error unspecified'
        }


#------------------------------------------------------------------------------#
# Timing offset
# TS 101 376 04-08, section 11.5.2.40
#------------------------------------------------------------------------------#

class TimingOffset(Envelope):
    _GEN = (
        Uint('TI', bl=1, dic={0:'no valid value', 1:'valid value'}),
        Int('Value', bl=15)
        )


#------------------------------------------------------------------------------#
# MES information flag
# TS 101 376 04-08, section 11.5.2.44
#------------------------------------------------------------------------------#

MESInfo_PV_dict = {
    0 : 'Position Verification not requested',
    1 : 'MES1 shall send a Channel Request for Position Verification following the completion of the upcoming call'
    }

MESInfo_ab_dict = {
    0 : 'Chan assigned: MES1 registered at selected GS',
    1 : 'Chan assigned: MES1 requires registration at selected GS',
    2 : 'Chan assigned: MES 1 Extended Channel Request required',
    3 : 'Pause Timer Indication'
    }

class MESInfoFlag(Envelope):
    _GEN = (
        Uint('PV', bl=1, dic=MESInfo_PV_dict),
        Uint('MES4', bl=1),
        Uint('MES3', bl=1),
        Uint('MES2', bl=1),
        Uint('MES1_D', bl=1, dic={1:'Dedicated Mode Position Update IE present', 0:'Dedicated Mode Position Update IE absent'}),
        Uint('MES1_I', bl=1, dic={1:'Idle Mode Position Update IE present', 0:'Idle Mode Position Update IE absent'}),
        Uint('MES1_ab', bl=2, dic=MESInfo_ab_dict),
        )


#------------------------------------------------------------------------------#
# Frequency offset
# TS 101 376 04-08, section 11.5.2.49
#------------------------------------------------------------------------------#

class FrequencyOffset(Envelope):
    _GEN = (
        Uint('FI', bl=1, dic={0:'no valid value', 1:'valid value'}),
        Int('Value', bl=12),
        Uint('spare', bl=3, rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Paging information
# TS 101 376 04-08, section 11.5.2.51
#------------------------------------------------------------------------------#

ChanNeeded_dict = {
    0 : 'any',
    1 : 'SDCCH',
    2 : 'TCH3',
    3 : 'spare'
    }

class PagingInfo(Envelope):
    _GEN = (
        Uint('MSC_ID', bl=6),
        Uint('ChanNeeded', bl=2, dic=ChanNeeded_dict)
        )


#------------------------------------------------------------------------------#
# Position display
# TS 101 376 04-08, section 11.5.2.52
#------------------------------------------------------------------------------#

PositionInfoFlag_dict = {
    0 : 'Position not available, MES may continue to use old position string',
    1 : 'No position display service provided. MES should not use the old position string',
    2 : 'Use Default 7-Bit alphabet to encode the country/region name string'
    }

class Buf7b(Buf):
    
    def encode(self, val):
        # WNG: this check is not perfect, as some chars require 7 septets,
        # and we must have exactly 12 septets here 
        if len(val) > 12:
            val = val[:12]
        elif len(val) < 12:
            val = val + (12-len(val))*' '
        self.set_val(encode_7b(val)[0])
        
    def decode(self):
        val = decode_7b(self.get_val())
        if len(val) < 12:
            # in case of stripped last char (@ or \r)
            val = val + (12-len(val))*' '
        return val
    
    def repr(self):
        if self._rep == REPR_HUM:
            return '<%s : %s>' % (self._name, self.decode())
        else:
            return Buf.repr(self)
    
    __repr__ = repr


class PositionDisplay(Envelope):
    _GEN = (
        Uint('DisplayInfoFlag', bl=4, dic=PositionInfoFlag_dict),
        Buf7b('CountryRegionName', bl=84, rep=REPR_HUM) # 12 7-bit chars
        )


#------------------------------------------------------------------------------#
# GPS position
# TS 101 376 04-08, section 11.5.2.53
#------------------------------------------------------------------------------#

class GPSPosition(Envelope):
    _GEN = (
        Uint('CPI', bl=1, dic={0:'GPS position is old', 1:'GPS position is current'}),
        Uint('GPSLatitude', bl=19),
        Uint('GPSLongitude', bl=20)
        )


#------------------------------------------------------------------------------#
# Idle or dedicated mode position update information
# TS 101 376 04-08, section 11.5.2.54
#------------------------------------------------------------------------------#

class PosUpdInfo(Envelope):
    _GEN = (
        Uint('GPSUpdDistance', bl=7),
        Uint('V', bl=1, dic={0:'no valid value', 1:'valid value'}),
        Uint8('GPSUpdTimer')
        )


#------------------------------------------------------------------------------#
# GPS timestamp
# TS 101 376 04-08, section 11.5.2.57
#------------------------------------------------------------------------------#

class GPSTimestamp(Uint16):
    pass


#------------------------------------------------------------------------------#
# GPS almanac data
# TS 101 376 04-08, section 11.5.2.63
#------------------------------------------------------------------------------#

class GPSAlmanacData(Envelope):
    _GEN = (
        Uint('PageNum', bl=5),
        Uint('WordNum', bl=3),
        Uint24('GPSAlmanacWord'),
        Uint('SFN', bl=1),
        Uint('CO', bl=2),
        Uint('spare', bl=5, rep=REPR_HEX)
        )


