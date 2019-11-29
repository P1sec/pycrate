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
# * File Name : pycrate_mobile/TS24501_FGSM.py
# * Created : 2019-11-08
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#__all__ = [
#    ]

#------------------------------------------------------------------------------#
# 3GPP TS 24.501: NAS protocol for 5G
# release 16 (g20)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24007    import *
from .TS24008_IE import (
    ProtConfig, GPRSTimer,
    )
from .TS24301_IE import (
    HdrCompConfig, 
    )
from .TS24501_IE import *

#------------------------------------------------------------------------------#
# 5GS Session Management header
# TS 24.501, section 9
#------------------------------------------------------------------------------#

# section 9.7
_FGSM_dict = {
    #
    193 : "PDU session establishment request",
    194 : "PDU session establishment accept",
    195 : "PDU session establishment reject",
    #
    197 : "PDU session authentication command",
    198 : "PDU session authentication complete",
    199 : "PDU session authentication result",
    #
    201 : "PDU session modification request",
    202 : "PDU session modification reject",
    203 : "PDU session modification command",
    204 : "PDU session modification complete",
    205 : "PDU session modification command reject",
    #
    209 : "PDU session release request",
    210 : "PDU session release reject",
    211 : "PDU session release command",
    212 : "PDU session release complete",
    #
    214 : "5GSM status"
    }


class FGSMHeader(Envelope):
    _GEN = (
        Uint8('EPD', val=46, dic=ProtDisc_dict),
        PDUSessID(),
        Uint8('PTI'),
        Uint8('Type', val=214, dic=_FGSM_dict)
        )


#------------------------------------------------------------------------------#
# PDU session establishment request
# TS 24.501, section 8.3.1
#------------------------------------------------------------------------------#

class FGSMPDUSessionEstabRequest(Layer3):
    _name = '5GSMPDUSessionEstabRequest'
    _GEN = (
        FGSMHeader(val={'Type':193})
        Type3V('IntegrityProtMaxDataRate', val={'V':b'\0\0'}, IE=IntegrityProtMaxDataRate()),
        Type1TV('PDUSessType', val={'T':0x9, 'V':1}, IE=PDUSessType()),
        Type1TV('SSCMode', val={'T':0xA, 'V':1}, IE=SSCMode()),
        Type4TLV('5GSMCap', val={'T':0x28, 'V':b'\0'}, IE=FGSMCap()),
        Type3TV('MaxPktFilters', val={'T':0x55, 'V':b'\x02\x20'}, bl={'V':16}, IE=MaxPktFilters()),
        Type1TV('AlwaysOnPDUSessReq', val={'T':0xB, 'V':0}, IE=AlwaysOnPDUSessReq()),
        Type4TLV('SMPDUDNReqContainer', val={'T':0x39, 'V':b'\0'}, IE=SMPDUDNReqContainer()),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'}, IE=ProtConfig()),
        Type4TLV('HdrCompConfig', val={'T':0x66, 'V':b'\0\0\0'}, IE=HdrCompConfig()),
        #Type4TLV('DSTTEthernetMAC', val={'T':0x00, 'V':6*b'\0'}), # WNG: tag is undefined in current TS
        #Type4TLV('DSTTResidenceTime', val={'T':0x00, 'V':8*b'\0'}), # WNG: tag is undefined in current TS
        )


#------------------------------------------------------------------------------#
# PDU session establishment accept
# TS 24.501, section 8.3.2
#------------------------------------------------------------------------------#

class FGSMPDUSessionEstabAccept(Layer3):
    _name = '5GSMPDUSessionEstabAccept'
    _GEN = (
        FGSMHeader(val={'Type':194})
        Type1V('SSCMode', val={'V':1}, IE=SSCMode()),
        Type1V('PDUSessType', val={'V':1}, IE=PDUSessType()),
        Type6LVE('QoSRules', val={'V':b'\0\0\0\0'}, IE=QoSRules()),
        Type4LV('SessAMBR', val={'V':b'\x06\0\x01\x06\0\x01'}, IE=SessAMBR()),
        Type3TV('FGSMCause', val={'T':0x59, 'V':b'\x1a'}, IE=FGSMCause()),
        Type4TLV('PDUAddress', val={'T':0x29, 'V':b'\x01\x7f\0\0\x01'}, IE=PDUAddress()),
        Type3TV('RQTimer', val={'T':0x56, 'V':b'\0'}, IE=GPRSTimer()),
        Type4TLV('SNSSAI', val={'T':0x22, 'V':b'\0'}, IE=SNSSAI()),
        Type1TV('AlwaysOnPDUSessInd', val={'T':0x8, 'V':0}, IE=AlwaysOnPDUSessInd()),
        # TODO

        )


#------------------------------------------------------------------------------#
# PDU session establishment reject
# TS 24.501, section 8.3.3
#------------------------------------------------------------------------------#

class FGSMPDUSessionEstabReject(Layer3):
    _name = '5GSMPDUSessionEstabReject'
    _GEN = (
        FGSMHeader(val={'Type':195})
        
        )


#------------------------------------------------------------------------------#
# PDU session authentication command
# TS 24.501, section 8.3.4
#------------------------------------------------------------------------------#

class FGSMPDUSessionAuthentCommand(Layer3):
    _name = '5GSMPDUSessionAuthentCommand'
    _GEN = (
        FGSMHeader(val={'Type':197})
        
        )


#------------------------------------------------------------------------------#
# PDU session authentication complete
# TS 24.501, section 8.3.5
#------------------------------------------------------------------------------#

class FGSMPDUSessionAuthentComplete(Layer3):
    _name = '5GSMPDUSessionAuthentComplete'
    _GEN = (
        FGSMHeader(val={'Type':198})
        
        )


#------------------------------------------------------------------------------#
# PDU session authentication result
# TS 24.501, section 8.3.6
#------------------------------------------------------------------------------#

class FGSMPDUSessionAuthentResult(Layer3):
    _name = '5GSMPDUSessionAuthentResult'
    _GEN = (
        FGSMHeader(val={'Type':199})
        
        )


#------------------------------------------------------------------------------#
# PDU session modification request
# TS 24.501, section 8.3.7
#------------------------------------------------------------------------------#

class FGSMPDUSessionModifRequest(Layer3):
    _name = '5GSMPDUSessionModifRequest'
    _GEN = (
        FGSMHeader(val={'Type':201})
        
        )


#------------------------------------------------------------------------------#
# PDU session modification reject
# TS 24.501, section 8.3.8
#------------------------------------------------------------------------------#

class FGSMPDUSessionModifReject(Layer3):
    _name = '5GSMPDUSessionModifReject'
    _GEN = (
        FGSMHeader(val={'Type':202})
        
        )


#------------------------------------------------------------------------------#
# PDU session modification command
# TS 24.501, section 8.3.9
#------------------------------------------------------------------------------#

class FGSMPDUSessionModifCommand(Layer3):
    _name = '5GSMPDUSessionModifCommand'
    _GEN = (
        FGSMHeader(val={'Type':203})
        
        )


#------------------------------------------------------------------------------#
# PDU session modification complete
# TS 24.501, section 8.3.10
#------------------------------------------------------------------------------#

class FGSMPDUSessionModifComplete(Layer3):
    _name = '5GSMPDUSessionModifComplete'
    _GEN = (
        FGSMHeader(val={'Type':204})
        
        )


#------------------------------------------------------------------------------#
# PDU session modification command reject
# TS 24.501, section 8.3.11
#------------------------------------------------------------------------------#

class FGSMPDUSessionModifCommandReject(Layer3):
    _name = '5GSMPDUSessionModifCommandReject'
    _GEN = (
        FGSMHeader(val={'Type':205})
        
        )


#------------------------------------------------------------------------------#
# PDU session release request
# TS 24.501, section 8.3.12
#------------------------------------------------------------------------------#

class FGSMPDUSessionReleaseRequest(Layer3):
    _name = '5GSMPDUSessionReleaseRequest'
    _GEN = (
        FGSMHeader(val={'Type':209})
        
        )


#------------------------------------------------------------------------------#
# PDU session release reject
# TS 24.501, section 8.3.13
#------------------------------------------------------------------------------#

class FGSMPDUSessionReleaseReject(Layer3):
    _name = '5GSMPDUSessionReleaseReject'
    _GEN = (
        FGSMHeader(val={'Type':210})
        
        )


#------------------------------------------------------------------------------#
# PDU session release command
# TS 24.501, section 8.3.14
#------------------------------------------------------------------------------#

class FGSMPDUSessionReleaseCommand(Layer3):
    _name = '5GSMPDUSessionReleaseCommand'
    _GEN = (
        FGSMHeader(val={'Type':211})
        
        )


#------------------------------------------------------------------------------#
# PDU session release complete
# TS 24.501, section 8.3.15
#------------------------------------------------------------------------------#

class FGSMPDUSessionReleaseComplete(Layer3):
    _name = '5GSMPDUSessionReleaseComplete'
    _GEN = (
        FGSMHeader(val={'Type':212})
        
        )


#------------------------------------------------------------------------------#
# 5GSM status
# TS 24.501, section 8.3.16
#------------------------------------------------------------------------------#

class FGSMStatus(Layer3):
    _name = '5GSMStatus'
    _GEN = (
        FGSMHeader(val={'Type':214})
        
        )


#------------------------------------------------------------------------------#
# 5GSM dispatcher
#------------------------------------------------------------------------------#

FGSMTypeClasses = {
    193 : 5GSMPDUSessionEstabRequest,
    194 : 5GSMPDUSessionEstabAccept,
    195 : 5GSMPDUSessionEstabReject,
    197 : 5GSMPDUSessionAuthentCommand,
    198 : 5GSMPDUSessionAuthentComplete,
    199 : 5GSMPDUSessionAuthentResult,
    201 : 5GSMPDUSessionModifRequest,
    202 : 5GSMPDUSessionModifReject,
    203 : 5GSMPDUSessionModifCommand,
    204 : 5GSMPDUSessionModifComplete,
    205 : 5GSMPDUSessionModifCommandReject,
    209 : 5GSMPDUSessionReleaseRequest,
    210 : 5GSMPDUSessionReleaseReject,
    211 : 5GSMPDUSessionReleaseCommand,
    212 : 5GSMPDUSessionReleaseComplete,
    214 : 5GSMStatus
    }

def get_5gsm_msg_instances():
    return {k: FGSMTypeClasses[k]() for k in FGSMTypeClasses}

