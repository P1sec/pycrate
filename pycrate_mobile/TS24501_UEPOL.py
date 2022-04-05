# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
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
# * File Name : pycrate_mobile/TS24501_UEPOL.py
# * Created : 2019-12-05
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#__all__ = [
#    ]

#------------------------------------------------------------------------------#
# 3GPP TS 24.501: UE policy delivery service (annex D)
# release 16 (g20)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24007       import *
from .TS24526_UEPOL import *
from .TS24588_UEPOL import *
from .TS24008_IE    import (
    PLMN, 
    )


#------------------------------------------------------------------------------#
# UE policy delivery service message type
# TS 24.501, section D.6.1
#------------------------------------------------------------------------------#

_UEPolMsgType_dict = {
    0 : 'Reserved',
    1 : 'MANAGE UE POLICY COMMAND message',
    2 : 'MANAGE UE POLICY COMPLETE message',
    3 : 'MANAGE UE POLICY COMMAND REJECT message',
    4 : 'UE STATE INDICATION message'
    }

class FGUEPOLHeader(Envelope):
    _name = '5GUEPOLHeader'
    _GEN = (
        Uint8('PTI'),
        Uint8('Type', val=1, dic=_UEPolMsgType_dict)
        )


#------------------------------------------------------------------------------#
# UE policy section management list
# TS 24.501, section D.6.2
#------------------------------------------------------------------------------#

_UEPolPartType_dict = {
    0 : 'Reserved',
    1 : 'URSP',
    2 : 'ANDSP',
    3 : 'V2XP'
    }


class UEPolPart(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('Type', bl=4, dic=_UEPolPartType_dict),
        Alt('Cont', GEN={
            1 : URSPRules(),
            2 : ANDSPInfos(),
            3 : V2XPInfos()
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()[2].get_val())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[3].get_len())
        self[3].set_blauto(lambda: (self[0].get_val()-1)<<3)


class UEPolInstruction(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint16('UPSC'),
        Sequence('Cont', GEN=UEPolPart())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 2 + self[2].get_len())
        self[2].set_blauto(lambda: (self[0].get_val()-2)<<3)


class UEPolSectionSublist(Envelope):
    _GEN = (
        Uint16('Len'),
        PLMN(),
        Sequence('Cont', GEN=UEPolInstruction())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 3 + self[2].get_len())
        self[2].set_blauto(lambda: (self[0].get_val()-3)<<3)


class UEPolSectionList(Sequence):
    _GEN = UEPolSectionSublist()


#------------------------------------------------------------------------------#
# UE policy section management result
# TS 24.501, section D.6.3
#------------------------------------------------------------------------------#

class UEPolResult(Envelope):
    _GEN = (
        Uint16('UPSC'),
        Uint16('FailedInstructionOrder'),
        Uint8('Cause', val=111, dic={111:'Protocol error, unspecified'})
        )


class UEPolSectionMgmtSubresult(Envelope):
    _GEN = (
        Uint16('Len'),
        PLMN(),
        Sequence('Cont', GEN=UEPolResult())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 3 + self[2].get_len())
        self[2].set_blauto(lambda: (self[0].get_val()-3)<<3)


class UEPolSectionMgmtResult(Sequence):
    _GEN = UEPolSectionMgmtSubresult()


#------------------------------------------------------------------------------#
# UPSI list
# TS 24.501, section D.6.4
#------------------------------------------------------------------------------#

class UPSISublist(Envelope):
    _GEN = (
        Uint16('Len'),
        PLMN(),
        Array('Cont', GEN=Uint16('UPSC'))
        )


class UPSIList(Sequence):
    _GEN = UPSISublist()


#------------------------------------------------------------------------------#
# UE policy classmark
# TS 24.501, section D.6.5
#------------------------------------------------------------------------------#

class UEPolicyCm(Envelope):
    _GEN = (
        Uint('spare', bl=7),
        Uint('ANDSPSupp', bl=1),
        Buf('spare', val=b'', rep=REPR_HEX)
        )
    
    def disable_from(self, ind):
        """disables all elements from index `ind' excluded (integer -bit offset- 
        or element name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = self._by_name.index(ind)
        [e.set_trans(True) for e in self._content[ind:]]
    
    def enable_upto(self, ind):
        """enables all elements up to index `ind' included (integer -bit offset- 
        or element name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = 1 + self._by_name.index(ind)
        [e.set_trans(False) for e in self._content[:ind]]


#------------------------------------------------------------------------------#
# UE OS Id
# TS 24.501, section D.6.6
#------------------------------------------------------------------------------#

class UEOSId(Array):
    _GEN = Buf('OS_UUID', bl=128, rep=REPR_HEX)


#------------------------------------------------------------------------------#
# Manage UE policy command
# TS 24.501, section D.5.1
#------------------------------------------------------------------------------#

class FGUEPOLManageUEPolicyCommand(Layer3):
    _name = '5GUEPOLManageUEPolicyCommand'
    _GEN = (
        FGUEPOLHeader(val={'Type':1}),
        Type6LVE('UEPolSectionList', val={'V':b'\0\7\0\0\0\0\2\0\0'}, IE=UEPolSectionList()),
        )


#------------------------------------------------------------------------------#
# Manage UE policy complete
# TS 24.501, section D.5.2
#------------------------------------------------------------------------------#

class FGUEPOLManageUEPolicyComplete(Layer3):
    _name = '5GUEPOLManageUEPolicyComplete'
    _GEN = (
        FGUEPOLHeader(val={'Type':2}),
        )


#------------------------------------------------------------------------------#
# Manage UE policy command reject
# TS 24.501, section D.5.3
#------------------------------------------------------------------------------#

class FGUEPOLManageUEPolicyCommandReject(Layer3):
    _name = '5GUEPOLManageUEPolicyCommandReject'
    _GEN = (
        FGUEPOLHeader(val={'Type':3}),
        Type6LVE('UEPolSectionMgmtResult', val={'V':b'\0\7\0\0\0\0\0\0\0\0\x6f'}, IE=UEPolSectionMgmtResult()),
        )


#------------------------------------------------------------------------------#
# UE state indication
# TS 24.501, section D.5.4
#------------------------------------------------------------------------------#

class FGUEPOLStateInd(Layer3):
    _name = '5GUEPOLStateInd'
    _GEN = (
        FGUEPOLHeader(val={'Type':4}),
        Type6LVE('UPSIList', val={'V':b'\0\7\0\0\0\0\0\0\0'}, IE=UPSIList()),
        Type4LV('UEPolicyCm', val={'V':b'\x01'}, IE=UEPolicyCm()),
        Type4TLV('UEOSId', val={'T':0x41, 'V':16*b'\0'}, IE=UEOSId())
        )


#------------------------------------------------------------------------------#
# 5G UE Policy dispatcher
#------------------------------------------------------------------------------#

FGUEPOLTypeClasses = {
    1 : FGUEPOLManageUEPolicyCommand,
    2 : FGUEPOLManageUEPolicyComplete,
    3 : FGUEPOLManageUEPolicyCommandReject,
    4 : FGUEPOLStateInd
    }

def get_5guepol_msg_instances():
    return {k: FGUEPOLTypeClasses[k]() for k in FGUEPOLTypeClasses}

