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

from .TS24007           import *
from .TS24008_IE        import (
    ProtConfig, GPRSTimer,
    )
from .TS24301_IE        import (
    HdrCompConfig as IPHdrCompConfig, ServingPLMNRateCtrl, 
    )
from .TS24501_IE        import *
from .TS24193_ATSSS     import *


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
    _name = '5GSMHeader'
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

class FGSMPDUSessionEstabRequest(Layer3E):
    _name = '5GSMPDUSessionEstabRequest'
    _GEN = (
        FGSMHeader(val={'Type':193}),
        Type3V('IntegrityProtMaxDataRate', val={'V':b'\0\0'}, bl={'V':16}, IE=IntegrityProtMaxDataRate()),
        Type1TV('PDUSessType', val={'T':0x9, 'V':1}, IE=PDUSessType()),
        Type1TV('SSCMode', val={'T':0xA, 'V':1}, IE=SSCMode()),
        Type4TLV('5GSMCap', val={'T':0x28, 'V':b'\0'}, IE=FGSMCap()),
        Type3TV('MaxPktFilters', val={'T':0x55, 'V':b'\x02\x20'}, bl={'V':16}, IE=MaxPktFilters()),
        Type1TV('AlwaysOnPDUSessReq', val={'T':0xB, 'V':0}, IE=AlwaysOnPDUSessReq()),
        Type4TLV('SMPDUDNReqContainer', val={'T':0x39, 'V':b'\0'}, IE=SMPDUDNReqContainer()),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'}, IE=ProtConfig()),
        Type4TLV('IPHdrCompConfig', val={'T':0x66, 'V':b'\0\0\0'}, IE=IPHdrCompConfig()),
        Type4TLV('DSTTEthernetMAC', val={'T':0x6E, 'V':6*b'\0'}),
        Type4TLV('UEDSTTResidenceTime', val={'T':0x6F, 'V':8*b'\0'}),
        Type6TLVE('PortMgmtInfoContainer', val={'T':0x7C, 'V':b'\0'}), # see TS 24.519
        Type4TLV('EthHdrCompConfig', val={'T':0x1F, 'V':b'\0'}, IE=EthHdrCompConfig()) 
        )


#------------------------------------------------------------------------------#
# PDU session establishment accept
# TS 24.501, section 8.3.2
#------------------------------------------------------------------------------#

class FGSMPDUSessionEstabAccept(Layer3E):
    _name = '5GSMPDUSessionEstabAccept'
    _GEN = (
        FGSMHeader(val={'Type':194}),
        Type1V('SSCMode', val={'V':1}, IE=SSCMode()),
        Type1V('PDUSessType', val={'V':1}, IE=PDUSessType()),
        Type6LVE('QoSRules', val={'V':b'\0\0\0\0'}, IE=QoSRules()),
        Type4LV('SessAMBR', val={'V':b'\x06\0\x01\x06\0\x01'}, IE=SessAMBR()),
        Type3TV('5GSMCause', val={'T':0x59, 'V':b'\x1a'}, bl={'V':8}, IE=FGSMCause()),
        Type4TLV('PDUAddress', val={'T':0x29, 'V':b'\x01\x7f\0\0\x01'}, IE=PDUAddress()),
        Type3TV('RQTimer', val={'T':0x56, 'V':b'\0'}, bl={'V':8}, IE=GPRSTimer()),
        Type4TLV('SNSSAI', val={'T':0x22, 'V':b'\0'}, IE=SNSSAI()),
        Type1TV('AlwaysOnPDUSessInd', val={'T':0x8, 'V':0}, IE=AlwaysOnPDUSessInd()),
        Type6TLVE('MappedEPSBearerCtxt', val={'T':0x75, 'V':b'\0\0\0\0'}, IE=MappedEPSBearerCtxt()),
        Type6TLVE('EAPMsg', val={'T':0x78, 'V':b'\0\0\0\0\0'}),
        Type6TLVE('QoSFlowDesc', val={'T':0x79, 'V':b'\0\0\0'}, IE=QoSFlowDesc()),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'}, IE=ProtConfig()),
        Type4TLV('DNN', val={'T':0x25, 'V':b'\0'}, IE=APN('DNN')),
        Type4TLV('5GSMNetFeat', val={'T':0x17, 'V':b'\0'}, IE=FGSMNetFeat()),
        Type4TLV('ServingPLMNRateCtrl', val={'T':0x18, 'V':b'\0\0'}, IE=ServingPLMNRateCtrl()),
        Type6TLVE('ATSSSContainer', val={'T':0x77, 'V':b''}, IE=ATSSSParams()),
        Type1TV('CtrlPlaneOnlyInd', val={'T':0xC, 'V':1}, IE=CtrlPlaneOnlyInd()),
        Type4TLV('IPHdrCompConfig', val={'T':0x66, 'V':b'\0\0\0'}, IE=IPHdrCompConfig()),
        Type4TLV('EthHdrCompConfig', val={'T':0x1F, 'V':b'\0'}, IE=EthHdrCompConfig()) 
        )


#------------------------------------------------------------------------------#
# PDU session establishment reject
# TS 24.501, section 8.3.3
#------------------------------------------------------------------------------#

class FGSMPDUSessionEstabReject(Layer3E):
    _name = '5GSMPDUSessionEstabReject'
    _GEN = (
        FGSMHeader(val={'Type':195}),
        Type3V('5GSMCause', val={'V':b'\x1a'}, bl={'V':8}, IE=FGSMCause()),
        Type4TLV('BackOffTimer', val={'T':0x37, 'V':b'\0'}, IE=GPRSTimer3()),
        Type1TV('AllowedSSCMode', val={'T':0xF, 'V':0}, IE=AllowedSSCMode()),
        Type6TLVE('EAPMsg', val={'T':0x78, 'V':b'\0\0\0\0\0'}),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'}, IE=ProtConfig()),
        Type4TLV('ReattemptInd', val={'V':0x1D, 'V':b'\0'}, IE=ReattemptInd()),
        Type4TLV('CongestReattemptInd', val={'T':0x61, 'V':b'\0'}, IE=CongestReattemptInd())
        )


#------------------------------------------------------------------------------#
# PDU session authentication command
# TS 24.501, section 8.3.4
#------------------------------------------------------------------------------#

class FGSMPDUSessionAuthentCommand(Layer3E):
    _name = '5GSMPDUSessionAuthentCommand'
    _GEN = (
        FGSMHeader(val={'Type':197}),
        Type6LVE('EAPMsg', val={'V':b'\0\0\0\0\0'}),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'}, IE=ProtConfig())
        )


#------------------------------------------------------------------------------#
# PDU session authentication complete
# TS 24.501, section 8.3.5
#------------------------------------------------------------------------------#

class FGSMPDUSessionAuthentComplete(Layer3E):
    _name = '5GSMPDUSessionAuthentComplete'
    _GEN = (
        FGSMHeader(val={'Type':198}),
        Type6LVE('EAPMsg', val={'V':b'\0\0\0\0\0'}),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'}, IE=ProtConfig())
        )


#------------------------------------------------------------------------------#
# PDU session authentication result
# TS 24.501, section 8.3.6
#------------------------------------------------------------------------------#

class FGSMPDUSessionAuthentResult(Layer3E):
    _name = '5GSMPDUSessionAuthentResult'
    _GEN = (
        FGSMHeader(val={'Type':199}),
        Type6TLVE('EAPMsg', val={'T':0x78, 'V':b'\0\0\0\0\0'}),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'}, IE=ProtConfig())
        )


#------------------------------------------------------------------------------#
# PDU session modification request
# TS 24.501, section 8.3.7
#------------------------------------------------------------------------------#

class FGSMPDUSessionModifRequest(Layer3E):
    _name = '5GSMPDUSessionModifRequest'
    _GEN = (
        FGSMHeader(val={'Type':201}),
        Type4TLV('5GSMCap', val={'T':0x28, 'V':b'\0'}, IE=FGSMCap()),
        Type3TV('5GSMCause', val={'T':0x59, 'V':b'\x1a'}, bl={'V':8}, IE=FGSMCause()),
        Type3TV('MaxPktFilters', val={'T':0x55, 'V':b'\x02\x20'}, bl={'V':16}, IE=MaxPktFilters()),
        Type1TV('AlwaysOnPDUSessReq', val={'T':0xB, 'V':0}, IE=AlwaysOnPDUSessReq()),
        Type3TV('IntegrityProtMaxDataRate', val={'T':0x13, 'V':b'\0\0'}, bl={'V':16}, IE=IntegrityProtMaxDataRate()),
        Type6TLVE('QoSRules', val={'T':0x7A, 'V':b'\0\0\0\0'}, IE=QoSRules()),
        Type6TLVE('QoSFlowDesc', val={'T':0x79, 'V':b'\0\0\0'}, IE=QoSFlowDesc()),
        Type6TLVE('MappedEPSBearerCtxt', val={'T':0x75, 'V':b'\0\0\0\0'}, IE=MappedEPSBearerCtxt()),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'}, IE=ProtConfig()),
        Type6TLVE('PortMgmtInfoContainer', val={'T':0x7C, 'V':b''}), # see TS 24.519
        Type4TLV('IPHdrCompConfig', val={'T':0x66, 'V':b'\0\0\0'}, IE=IPHdrCompConfig()),
        Type4TLV('EthHdrCompConfig', val={'T':0x1F, 'V':b'\0'}, IE=EthHdrCompConfig()) 
        )


#------------------------------------------------------------------------------#
# PDU session modification reject
# TS 24.501, section 8.3.8
#------------------------------------------------------------------------------#

class FGSMPDUSessionModifReject(Layer3E):
    _name = '5GSMPDUSessionModifReject'
    _GEN = (
        FGSMHeader(val={'Type':202}),
        Type3V('5GSMCause', val={'V':b'\x1a'}, bl={'V':8}, IE=FGSMCause()),
        Type4TLV('BackOffTimer', val={'T':0x37, 'V':b'\0'}, IE=GPRSTimer3()),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'}, IE=ProtConfig()),
        Type4TLV('ReattemptInd', val={'V':0x1D, 'V':b'\0'}, IE=ReattemptInd()),
        Type4TLV('CongestReattemptInd', val={'T':0x61, 'V':b'\0'}, IE=CongestReattemptInd())
        )


#------------------------------------------------------------------------------#
# PDU session modification command
# TS 24.501, section 8.3.9
#------------------------------------------------------------------------------#

class FGSMPDUSessionModifCommand(Layer3E):
    _name = '5GSMPDUSessionModifCommand'
    _GEN = (
        FGSMHeader(val={'Type':203}),
        Type3TV('5GSMCause', val={'T':0x59, 'V':b'\x1a'}, bl={'V':8}, IE=FGSMCause()),
        Type4TLV('SessAMBR', val={'T':0x2A, 'V':b'\x06\0\x01\x06\0\x01'}, IE=SessAMBR()),
        Type3TV('RQTimer', val={'T':0x56, 'V':b'\0'}, bl={'V':8}, IE=GPRSTimer()),
        Type1TV('AlwaysOnPDUSessInd', val={'T':0x8, 'V':0}, IE=AlwaysOnPDUSessInd()),
        Type6TLVE('QoSRules', val={'T':0x7A, 'V':b'\0\0\0\0'}, IE=QoSRules()),
        Type6TLVE('MappedEPSBearerCtxt', val={'T':0x75, 'V':b'\0\0\0\0'}, IE=MappedEPSBearerCtxt()),
        Type6TLVE('QoSFlowDesc', val={'T':0x79, 'V':b'\0\0\0'}, IE=QoSFlowDesc()),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'}, IE=ProtConfig()),
        Type6TLVE('ATSSSContainer', val={'T':0x77, 'V':b''}, IE=ATSSSParams()),
        Type4TLV('IPHdrCompConfig', val={'T':0x66, 'V':b'\0\0\0'}, IE=IPHdrCompConfig()),
        Type6TLVE('PortMgmtInfoContainer', val={'T':0x7C, 'V':b''}), # see TS 24.519
        Type4TLV('ServingPLMNRateCtrl', val={'T':0x1E, 'V':b'\0\0'}, IE=ServingPLMNRateCtrl()),
        Type4TLV('EthHdrCompConfig', val={'T':0x1F, 'V':b'\0'}, IE=EthHdrCompConfig()) 
        )


#------------------------------------------------------------------------------#
# PDU session modification complete
# TS 24.501, section 8.3.10
#------------------------------------------------------------------------------#

class FGSMPDUSessionModifComplete(Layer3E):
    _name = '5GSMPDUSessionModifComplete'
    _GEN = (
        FGSMHeader(val={'Type':204}),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'}, IE=ProtConfig()),
        Type6TLVE('PortMgmtInfoContainer', val={'T':0x7C, 'V':b''}) # see TS 24.519
        )


#------------------------------------------------------------------------------#
# PDU session modification command reject
# TS 24.501, section 8.3.11
#------------------------------------------------------------------------------#

class FGSMPDUSessionModifCommandReject(Layer3E):
    _name = '5GSMPDUSessionModifCommandReject'
    _GEN = (
        FGSMHeader(val={'Type':205}),
        Type3V('5GSMCause', val={'V':b'\x1a'}, bl={'V':8}, IE=FGSMCause()),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'}, IE=ProtConfig())
        )


#------------------------------------------------------------------------------#
# PDU session release request
# TS 24.501, section 8.3.12
#------------------------------------------------------------------------------#

class FGSMPDUSessionReleaseRequest(Layer3E):
    _name = '5GSMPDUSessionReleaseRequest'
    _GEN = (
        FGSMHeader(val={'Type':209}),
        Type3TV('5GSMCause', val={'T':0x59, 'V':b'\x1a'}, bl={'V':8}, IE=FGSMCause()),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'}, IE=ProtConfig())
        )


#------------------------------------------------------------------------------#
# PDU session release reject
# TS 24.501, section 8.3.13
#------------------------------------------------------------------------------#

class FGSMPDUSessionReleaseReject(Layer3E):
    _name = '5GSMPDUSessionReleaseReject'
    _GEN = (
        FGSMHeader(val={'Type':210}),
        Type3V('5GSMCause', val={'V':b'\x1a'}, bl={'V':8}, IE=FGSMCause()),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'}, IE=ProtConfig())
        )


#------------------------------------------------------------------------------#
# PDU session release command
# TS 24.501, section 8.3.14
#------------------------------------------------------------------------------#

class FGSMPDUSessionReleaseCommand(Layer3E):
    _name = '5GSMPDUSessionReleaseCommand'
    _GEN = (
        FGSMHeader(val={'Type':211}),
        Type3V('5GSMCause', val={'V':b'\x1a'}, bl={'V':8}, IE=FGSMCause()),
        Type4TLV('BackOffTimer', val={'T':0x37, 'V':b'\0'}, IE=GPRSTimer3()),
        Type6TLVE('EAPMsg', val={'T':0x78, 'V':b'\0\0\0\0\0'}),
        Type4TLV('CongestReattemptInd', val={'T':0x61, 'V':b'\0'}, IE=CongestReattemptInd()),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'}, IE=ProtConfig()),
        Type1TV('AccessType', val={'T':0xD, 'V':1}, IE=AccessType())
        )


#------------------------------------------------------------------------------#
# PDU session release complete
# TS 24.501, section 8.3.15
#------------------------------------------------------------------------------#

class FGSMPDUSessionReleaseComplete(Layer3E):
    _name = '5GSMPDUSessionReleaseComplete'
    _GEN = (
        FGSMHeader(val={'Type':212}),
        Type3TV('5GSMCause', val={'T':0x59, 'V':b'\x1a'}, bl={'V':8}, IE=FGSMCause()),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'}, IE=ProtConfig())        
        )


#------------------------------------------------------------------------------#
# 5GSM status
# TS 24.501, section 8.3.16
#------------------------------------------------------------------------------#

class FGSMStatus(Layer3E):
    _name = '5GSMStatus'
    _GEN = (
        FGSMHeader(val={'Type':214}),
        Type3V('5GSMCause', val={'V':b'\x1a'}, bl={'V':8}, IE=FGSMCause())
        )


#------------------------------------------------------------------------------#
# 5GSM dispatcher
#------------------------------------------------------------------------------#

FGSMTypeClasses = {
    193 : FGSMPDUSessionEstabRequest,
    194 : FGSMPDUSessionEstabAccept,
    195 : FGSMPDUSessionEstabReject,
    197 : FGSMPDUSessionAuthentCommand,
    198 : FGSMPDUSessionAuthentComplete,
    199 : FGSMPDUSessionAuthentResult,
    201 : FGSMPDUSessionModifRequest,
    202 : FGSMPDUSessionModifReject,
    203 : FGSMPDUSessionModifCommand,
    204 : FGSMPDUSessionModifComplete,
    205 : FGSMPDUSessionModifCommandReject,
    209 : FGSMPDUSessionReleaseRequest,
    210 : FGSMPDUSessionReleaseReject,
    211 : FGSMPDUSessionReleaseCommand,
    212 : FGSMPDUSessionReleaseComplete,
    214 : FGSMStatus
    }

def get_5gsm_msg_instances():
    return {k: FGSMTypeClasses[k]() for k in FGSMTypeClasses}

