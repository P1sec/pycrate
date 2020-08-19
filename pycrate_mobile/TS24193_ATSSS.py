# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2020. Benoit Michau. P1Sec.
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
# * File Name : pycrate_mobile/TS24193_ATSSS.py
# * Created : 2020-08-19
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'ATSSSParams'
    ]

#------------------------------------------------------------------------------#
# 3GPP TS 24.193:
# Access Traffic Steering, Switching and Splitting (ATSSS)
# release 16 (g00)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24526_UEPOL import TrafficDescComp


#------------------------------------------------------------------------------#
# Encoding of ATSSS rules
# TS 24.193, 6.1.3 
#------------------------------------------------------------------------------#

_AccessSelDescLen_dict = {
    3 : 'smallest delay steering mode',
    4 : 'not smallest delay steering mode'
    }

_SteeringFunc_dict = {
    1 : 'UE\'s supported steering functionality',
    2 : 'MPTCP functionality',
    3 : 'ATSSS-LL functionality'
    }

_SteeringMode_dict = {
    1 : 'Active-standby',
    2 : 'Smallest delay',
    3 : 'Load balancing',
    4 : 'Priority based'
    }

_SteeringModeInfo_dict = {
    1 : {
        1 : 'Active 3GPP and no standby',
        2 : 'Active 3GPP and non-3GPP standby',
        3 : 'Active non-3GPP and no standby',
        4 : 'Active non-3GPP and 3GPP standby'
        },
    3 : {
        1  : '100% over 3GPP and 0% over non-3GPP',
        2  : '90% over 3GPP and 10% over non-3GPP',
        3  : '80% over 3GPP and 20% over non-3GPP',
        4  : '70% over 3GPP and 30% over non-3GPP',
        5  : '60% over 3GPP and 40% over non-3GPP',
        6  : '50% over 3GPP and 50% over non-3GPP',
        7  : '40% over 3GPP and 60% over non-3GPP',
        8  : '30% over 3GPP and 70% over non-3GPP',
        9  : '20% over 3GPP and 80% over non-3GPP',
        10 : '10% over 3GPP and 90% over non-3GPP',
        11 : '0% over 3GPP and 100% over non-3GPP'
        },
    4 : {
        1 : '3GPP is high priority access',
        2 : 'non-3GPP is high priority access'
        }
    }


class AccessSelDesc(Envelope):
    _GEN = (
        Uint8('Len', val=3, dic=_AccessSelDescLen_dict),
        Uint8('SteeringFunc', val=1, dic=_SteeringFunc_dict),
        Uint8('SteeringMode', val=1, dic=_SteeringMode_dict),
        Uint8('SteeringModeInfo')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 3 if self[2].get_val() == 2 else 4)
        self[3].set_transauto(lambda: True if self[2].get_val() == 2 else False)
        self[3].set_dicauto(lambda: _SteeringModeInfo_dict.get(self[2].get_val(), {}))


class ATSSSRule(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint8('Precedence'),
        Uint16('LenTrafficDesc'),
        Sequence('TrafficDesc', GEN=TrafficDescComp()),
        AccessSelDesc()
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 3 + self[2].get_val() + self[4].get_len())
        self[2].set_valauto(lambda: self[3].get_len())
        self[3].set_blauto(lambda: self[2].get_val()<<3)


class ATSSSRules(Sequence):
    _GEN = ATSSSRule()


#------------------------------------------------------------------------------#
# Encoding of network steering functionalities information
# TS 24.193, 6.1.4.2 
#------------------------------------------------------------------------------#

_IPAddrType_dict = {
    1 : 'IPv4',
    2 : 'IPv6',
    3 : 'IPv4v6'
    }

class _IPAddr(Envelope):
    _GEN = (
        Uint8('Type', val=1, dic=_IPAddrType_dict),
        Alt('Addr', GEN={
            1 : Buf('IPv4', bl=32, rep=REPR_HEX),
            2 : Buf('IPv6', bl=128, rep=REPR_HEX),
            3 : Envelope('IPv4v6', GEN=(
                    Buf('IPv4', bl=32, rep=REPR_HEX),
                    Buf('IPv6', bl=128, rep=REPR_HEX))
                )},
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val())
        )


class MPTCPProxInfo(Envelope):
    _GEN = (
        _IPAddr('IPAddr'),
        Uint16('Port'),
        Uint8('Type', val=1, dic={1:'Transport converter'})
        )


class NetSteeringFuncInfo(Envelope):
    _GEN = (
        _IPAddr('UE3GPPIPAddr'),
        _IPAddr('UENon3GPPIPAddr'),
        Uint8('MPTCPProxInfoLen'),
        Sequence('MPTCPProxInfos', GEN=MPTCPProxInfo())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_valauto(lambda: self[3].get_len())
        self[3].set_blauto(lambda: self[2].get_val()<<3)


#------------------------------------------------------------------------------#
# Encoding of measurement assistance information
# TS 24.193, 6.1.5.2
#------------------------------------------------------------------------------#

class MeasureAssistInfoIP(Envelope):
    _GEN = (
        _IPAddr('PMFIPAddr'),
        Uint16('PMFPort'),
        Uint16('PMFNon3GPPPort'),
        Uint('spare', bl=7),
        Uint('AARI', bl=1)
        ) # 10, 23 or 26 bytes


class MeasureAssistInfoEth(Envelope):
    _GEN = (
        Buf('PMF3GPPMACAddr', bl=48, rep=REPR_HEX),
        Buf('PMFNon3GPPMACAddr', bl=48, rep=REPR_HEX),
        Uint('spare', bl=7),
        Uint('AARI', bl=1)
        ) # 13 bytes


#------------------------------------------------------------------------------#
# Encoding of ATSSS parameters
# TS 24.193, 6.1.2 
#------------------------------------------------------------------------------#

ATSSSParamId_dict = {
    1 : 'ATSSS rules',
    2 : 'Network steering functionalities information',
    3 : 'Measurement assistance information'
    }

# Warning: this is dirty for the encodong process to select the MeasureAssistInfo 
# based on the Len, but we have no choice...
class ATSSSParam(Envelope):
    _GEN = (
        Uint8('Id', dic=ATSSSParamId_dict),
        Uint16('Len'),
        Alt('Cont', GEN={
            1: ATSSSRules(),
            2: NetSteeringFuncInfo(),
            3: Alt('MeasureAssistInfo',
                GEN={13: MeasureAssistInfoEth()},
                DEFAULT=MeasureAssistInfoIP(),
                sel=lambda self: self.get_env()[1].get_val()
                )},
            DEFAULT=Buf('unk', rep=REPR_HEX),
            sel=lambda self: self.get_env()[0].get_val()
            )
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
        self[2].set_blauto(lambda: self[1].get_val()<<3)


class ATSSSParams(Sequence):
    _GEN = ATSSSParam()

