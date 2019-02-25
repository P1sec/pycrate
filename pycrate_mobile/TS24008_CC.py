# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2017. Benoit Michau. ANSSI.
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
# * File Name : pycrate_mobile/TS24008_CC.py
# * Created : 2017-10-18
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'CCAlertingMO',
    'CCAlertingMT',
    'CCCallConfirmed',
    'CCCallProceeding',
    'CCCongestionControl',
    'CCConnectAcknowledge',
    'CCConnectMO',
    'CCConnectMT',
    'CCDisconnectMO',
    'CCDisconnectMT',
    'CCEmergencySetup',
    'CCEstablishmentCCBS',
    'CCEstablishmentConfirmedCCBS',
    'CCFacilityMO',
    'CCFacilityMT',
    'CCHold',
    'CCHoldAcknowledge',
    'CCHoldReject',
    'CCModify',
    'CCModifyComplete',
    'CCModifyReject',
    'CCNotify',
    'CCProgress',
    'CCRecallCCBS',
    'CCReleaseCompleteMO',
    'CCReleaseCompleteMT',
    'CCReleaseMO',
    'CCReleaseMT',
    'CCRetrieve',
    'CCRetrieveAcknowledge',
    'CCRetrieveReject',
    'CCSetupMO',
    'CCSetupMT',
    'CCStartCCBS',
    'CCStartDTMF',
    'CCStartDTMFAcknowledge',
    'CCStartDTMFReject',
    'CCStatus',
    'CCStatusEnquiry',
    'CCStopDTMF',
    'CCStopDTMFAcknowledge',
    'CCUserInformation',
    #
    'CCTypeMOClasses',
    'CCTypeMTClasses',
    'get_cc_msg_mo_instances',
    'get_cc_msg_mt_instances'
    ]


#------------------------------------------------------------------------------#
# 3GPP TS 24.008: Mobile radio interface layer 3 specification
# release 13 (d90)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24007    import *
from .TS24008_IE import *
from .TS24080_SS import SSVersion

#------------------------------------------------------------------------------#
# CS Call Control header
# TS 24.008, section 10.1 to 10.4
#------------------------------------------------------------------------------#

_CS_CC_dict = {
    0 : "national specific",
    1 : "Call establishment - ALERTING",
    2 : "Call establishment - CALL PROCEEDING",
    3 : "Call establishment - PROGRESS",
    4 : "Call establishment - CC-ESTABLISHMENT",
    5 : "Call establishment - SETUP",
    6 : "Call establishment - CC-ESTABLISHMENT CONFIRMED",
    7 : "Call establishment - CONNECT",
    8 : "Call establishment - CALL CONFIRMED",
    9 : "Call establishment - START CC",
    11: "Call establishment - RECALL",
    14: "Call establishment - EMERGENCY SETUP",
    15: "Call establishment - CONNECT ACKNOWLEDGE",
    16: "Call information - USER INFORMATION",
    19: "Call information - MODIFY REJECT",
    23: "Call information - MODIFY",
    24: "Call information - HOLD",
    25: "Call information - HOLD ACKNOWLEDGE",
    26: "Call information - HOLD REJECT",
    28: "Call information - RETRIEVE",
    29: "Call information - RETRIEVE ACKNOWLEDGE",
    30: "Call information - RETRIEVE REJECT",
    31: "Call information - MODIFY COMPLETE",
    37: "Call clearing - DISCONNECT",
    42: "Call clearing - RELEASE COMPLETE",
    45: "Call clearing - RELEASE",
    49: "Misc - STOP DTMF",
    50: "Misc - STOP DTMF ACKNOWLEDGE",
    52: "Misc - STATUS ENQUIRY",
    53: "Misc - START DTMF",
    54: "Misc - START DTMF ACKNOWLEDGE",
    55: "Misc - START DTMF REJECT",
    57: "Misc - CONGESTION CONTROL",
    58: "Misc - FACILITY",
    61: "Misc - STATUS",
    62: "Misc - NOTIFY"
    }

class CCHeader(Envelope):
    _GEN = (
        TIPD(val={'ProtDisc': 3}),
        Uint('Seqn', bl=2),
        Uint('Type', val=61, bl=6, dic=_CS_CC_dict)
        )


#------------------------------------------------------------------------------#
# Alerting (network to mobile station direction)
# TS 24.008, section 9.3.1.1
#------------------------------------------------------------------------------#

class CCAlertingMT(Layer3):
    _GEN = (
        CCHeader(val={'Type':1}),
        Type4TLV('Facility', val={'T':0x1C, 'V':b''}),
        Type4TLV('ProgressInd', val={'T':0x1E, 'V':b'\x80\x80'}, IE=ProgressInd()),
        Type4TLV('UserUser', val={'T':0x7E, 'V':b'\x04'}, IE=UserUser())
        )


#------------------------------------------------------------------------------#
# Alerting (mobile station to network direction)
# TS 24.008, section 9.3.1.2
#------------------------------------------------------------------------------#

class CCAlertingMO(Layer3):
    _GEN = (
        CCHeader(val={'Type':1}),
        Type4TLV('Facility', val={'T':0x1C, 'V':b''}),
        Type4TLV('UserUser', val={'T':0x7E, 'V':b'\x04'}, IE=UserUser()),
        Type4TLV('SSVersion', val={'T':0x7F, 'V':b''}, IE=SSVersion())
        )


#------------------------------------------------------------------------------#
# Call confirmed
# TS 24.008, section 9.3.2
#------------------------------------------------------------------------------#

class CCCallConfirmed(Layer3):
    _GEN = (
        CCHeader(val={'Type':8}),
        Type1TV('RepeatInd', val={'T':0xD, 'V':2}, dic=RepeatInd_dict),
        Type4TLV('BearerCap1', val={'T':0x4, 'V':b'\xa0'}, IE=BearerCap()),
        Type4TLV('BearerCap2', val={'T':0x4, 'V':b'\xa0'}, IE=BearerCap()),
        Type4TLV('Cause', val={'T':0x8, 'V':b'\x80\x80'}, IE=Cause()),
        Type4TLV('CCCap', val={'T':0x15, 'V':b'\x01\0'}, IE=CCCap()),
        Type4TLV('StreamIdent', val={'T':0x2D, 'V':b'\0'}, IE=StreamIdent()),
        Type4TLV('SupportedCodecs', val={'T':0x40, 'V':b'\0\x01\0'}, IE=SupportedCodecs())
        )


#------------------------------------------------------------------------------#
# Call proceeding
# TS 24.008, section 9.3.3
#------------------------------------------------------------------------------#

class CCCallProceeding(Layer3):
    _GEN = (
        CCHeader(val={'Type':2}),
        Type1TV('RepeatInd', val={'T':0xD, 'V':2}, dic=RepeatInd_dict),
        Type4TLV('BearerCap1', val={'T':0x4, 'V':b'\xa0'}, IE=BearerCap()),
        Type4TLV('BearerCap2', val={'T':0x4, 'V':b'\xa0'}, IE=BearerCap()),
        Type4TLV('Facility', val={'T':0x1C, 'V':b''}),
        Type4TLV('ProgressInd', val={'T':0x1E, 'V':b'\x80\x80'}, IE=ProgressInd()),
        Type1TV('Priority', val={'T':0x8, 'V':0}, dic=PriorityLevel_dict),
        Type4TLV('NetCCCap', val={'T':0x2F, 'V':b'\0'}, IE=NetCCCap())
        )


#------------------------------------------------------------------------------#
# Congestion control
# TS 24.008, section 9.3.4
#------------------------------------------------------------------------------#

class CCCongestionControl(Layer3):
    _GEN = (
        CCHeader(val={'Type':57}),
        Uint('spare', bl=4),
        Type1V('CongestionLevel', dic=CongestionLevel_dict),
        Type4TLV('Cause', val={'T':0x8, 'V':b'\x80\x80'}, IE=Cause())
        )


#------------------------------------------------------------------------------#
# Connect (network to mobile station direction)
# TS 24.008, section 9.3.5.1
#------------------------------------------------------------------------------#

class CCConnectMT(Layer3):
    _GEN = (
        CCHeader(val={'Type':7}),
        Type4TLV('Facility', val={'T':0x1C, 'V':b''}),
        Type4TLV('ProgressInd', val={'T':0x1E, 'V':b'\x80\x80'}, IE=ProgressInd()),
        Type4TLV('ConnectedNumber', val={'T':0x4C, 'V':b'\x91'}, IE=ConnectedNumber()),
        Type4TLV('ConnectedSubaddress', val={'T':0X4D, 'V':b'\x80'}, IE=ConnectedSubaddress()),
        Type4TLV('UserUser', val={'T':0x7E, 'V':b'\x04'}, IE=UserUser())
        )


#------------------------------------------------------------------------------#
# Connect (mobile station to network direction)
# TS 24.008, section 9.3.5.2
#------------------------------------------------------------------------------#

class CCConnectMO(Layer3):
    _GEN = (
        CCHeader(val={'Type':7}),
        Type4TLV('Facility', val={'T':0x1C, 'V':b''}),
        Type4TLV('ConnectedSubaddress', val={'T':0X4D, 'V':b'\x80'}, IE=ConnectedSubaddress()),
        Type4TLV('UserUser', val={'T':0x7E, 'V':b'\x04'}, IE=UserUser()),
        Type4TLV('SSVersion', val={'T':0x7F, 'V':b''}, IE=SSVersion()),
        Type4TLV('StreamIdent', val={'T':0x2D, 'V':b'\0'}, IE=StreamIdent())
        )


#------------------------------------------------------------------------------#
# Connect acknowledge
# TS 24.008, section 9.3.6
#------------------------------------------------------------------------------#

class CCConnectAcknowledge(Layer3):
    _GEN = (
        CCHeader(val={'Type':15}),
        )


#------------------------------------------------------------------------------#
# Disconnect (network to mobile station direction)
# TS 24.008, section 9.3.7.1
#------------------------------------------------------------------------------#

class CCDisconnectMT(Layer3):
    _GEN = (
        CCHeader(val={'Type':37}),
        Type4LV('Cause', val={'V':b'\x80\x80'}, IE=Cause()),
        Type4TLV('Facility', val={'T':0x1C, 'V':b''}),
        Type4TLV('ProgressInd', val={'T':0x1E, 'V':b'\x80\x80'}, IE=ProgressInd()),
        Type4TLV('UserUser', val={'T':0x7E, 'V':b'\x04'}, IE=UserUser()),
        Type4TLV('CCBSAllowedActions', val={'T':0x7B, 'V':b'\0'}, IE=CCBSAllowedActions())
        )


#------------------------------------------------------------------------------#
# Disconnect (mobile station to network direction)
# TS 24.008, section 9.3.7.1
#------------------------------------------------------------------------------#

class CCDisconnectMO(Layer3):
    _GEN = (
        CCHeader(val={'Type':37}),
        Type4LV('Cause', val={'V':b'\x80\x80'}, IE=Cause()),
        Type4TLV('Facility', val={'T':0x1C, 'V':b''}),
        Type4TLV('UserUser', val={'T':0x7E, 'V':b'\x04'}, IE=UserUser()),
        Type4TLV('SSVersion', val={'T':0x7F, 'V':b''}, IE=SSVersion())
        )


#------------------------------------------------------------------------------#
# Emergency setup
# TS 24.008, section 9.3.8
#------------------------------------------------------------------------------#

class CCEmergencySetup(Layer3):
    _GEN = (
        CCHeader(val={'Type':14}),
        Type4TLV('BearerCap', val={'T':0x4, 'V':b'\xa0'}, IE=BearerCap()),
        Type4TLV('StreamIdent', val={'T':0x2D, 'V':b'\0'}, IE=StreamIdent()),
        Type4TLV('SupportedCodecs', val={'T':0x40, 'V':b'\0\x01\0'}, IE=SupportedCodecs()),
        Type4TLV('EmergencyCat', val={'T':0x2E, 'V':b'\0'}, IE=EmergServiceCat())
        )


#------------------------------------------------------------------------------#
# Facility (network to mobile station direction)
# TS 24.008, section 9.3.9.1
#------------------------------------------------------------------------------#

class CCFacilityMT(Layer3):
    _GEN = (
        CCHeader(val={'Type':58}),
        Type4LV('Facility', val={'V':b''}),
        )


#------------------------------------------------------------------------------#
# Facility ( mobile station to network direction)
# TS 24.008, section 9.3.9.2
#------------------------------------------------------------------------------#

class CCFacilityMO(Layer3):
    _GEN = (
        CCHeader(val={'Type':58}),
        Type4LV('Facility', val={'V':b''}),
        Type4TLV('SSVersion', val={'T':0x7F, 'V':b''}, IE=SSVersion())
        )


#------------------------------------------------------------------------------#
# Hold
# TS 24.008, section 9.3.10
#------------------------------------------------------------------------------#

class CCHold(Layer3):
    _GEN = (
        CCHeader(val={'Type':24}),
        )


#------------------------------------------------------------------------------#
# Hold Acknowledge
# TS 24.008, section 9.3.11
#------------------------------------------------------------------------------#

class CCHoldAcknowledge(Layer3):
    _GEN = (
        CCHeader(val={'Type':25}),
        )


#------------------------------------------------------------------------------#
# Hold Reject
# TS 24.008, section 9.3.12
#------------------------------------------------------------------------------#

class CCHoldReject(Layer3):
    _GEN = (
        CCHeader(val={'Type':26}),
        Type4LV('Cause', val={'V':b'\x80\x80'}, IE=Cause()),
        )


#------------------------------------------------------------------------------#
# Modify
# TS 24.008, section 9.3.13
#------------------------------------------------------------------------------#

class CCModify(Layer3):
    _GEN = (
        CCHeader(val={'Type':23}),
        Type4LV('BearerCap', val={'V':b'\xa0'}, IE=BearerCap()),
        Type4TLV('LowLayerComp', val={'T':0x7C, 'V':b''}),
        Type4TLV('HighLayerComp', val={'T':0x7D, 'V':b''}, IE=HighLayerComp()),
        Type2('ReverseCallSetupDir', val={'T':0xA3}),
        Type2('NetworkInitServUpgradeInd', val={'T':0xA4})
        )


#------------------------------------------------------------------------------#
# Modify complete
# TS 24.008, section 9.3.14
#------------------------------------------------------------------------------#

class CCModifyComplete(Layer3):
    _GEN = (
        CCHeader(val={'Type':31}),
        Type4LV('BearerCap', val={'V':b'\xa0'}, IE=BearerCap()),
        Type4TLV('LowLayerComp', val={'T':0x7C, 'V':b''}),
        Type4TLV('HighLayerComp', val={'T':0x7D, 'V':b''}, IE=HighLayerComp()),
        Type2('ReverseCallSetupDir', val={'T':0xA3})
        )


#------------------------------------------------------------------------------#
# Modify reject
# TS 24.008, section 9.3.15
#------------------------------------------------------------------------------#

class CCModifyReject(Layer3):
    _GEN = (
        CCHeader(val={'Type':19}),
        Type4LV('BearerCap', val={'V':b'\xa0'}, IE=BearerCap()),
        Type4LV('Cause', val={'V':b'\x80\x80'}, IE=Cause()),
        Type4TLV('LowLayerComp', val={'T':0x7C, 'V':b''}),
        Type4TLV('HighLayerComp', val={'T':0x7D, 'V':b''}, IE=HighLayerComp())
        )


#------------------------------------------------------------------------------#
# Notify
# TS 24.008, section 9.3.16
#------------------------------------------------------------------------------#

class CCNotify(Layer3):
    _GEN = (
        CCHeader(val={'Type':62}),
        Type3V('NotificationInd', val={'V':b'\x80'}, bl={'V':8}, IE=NotificationInd()),
        )


#------------------------------------------------------------------------------#
# Progress
# TS 24.008, section 9.3.17
#------------------------------------------------------------------------------#

class CCProgress(Layer3):
    _GEN = (
        CCHeader(val={'Type':3}),
        Type4LV('ProgressInd', val={'V':b'\x80\x80'}, IE=ProgressInd()),
        Type4TLV('UserUser', val={'T':0x7E, 'V':b'\x04'}, IE=UserUser())
        )


#------------------------------------------------------------------------------#
# CC-Establishment $(CCBS)$
# TS 24.008, section 9.3.17a
#------------------------------------------------------------------------------#

class CCEstablishmentCCBS(Layer3):
    _GEN = (
        CCHeader(val={'Type':4}),
        Type4LV('SetupContainer', val={'V':b''}),
        )


#------------------------------------------------------------------------------#
# CC-Establishment confirmed $(CCBS)$
# TS 24.008, section 9.3.17b
#------------------------------------------------------------------------------#

class CCEstablishmentConfirmedCCBS(Layer3):
    _GEN = (
        CCHeader(val={'Type':6}),
        Type1TV('RepeatInd', val={'T':0xD, 'V':2}, dic=RepeatInd_dict),
        Type4TLV('BearerCap1', val={'T':0x4, 'V':b'\xa0'}, IE=BearerCap()),
        Type4TLV('BearerCap2', val={'T':0x4, 'V':b'\xa0'}, IE=BearerCap()),
        Type4TLV('Cause', val={'T':0x8, 'V':b'\x80\x80'}, IE=Cause()),
        Type4TLV('SupportedCodecs', val={'T':0x40, 'V':b'\0\x01\0'}, IE=SupportedCodecs())
        )


#------------------------------------------------------------------------------#
# Release (network to mobile station direction)
# TS 24.008, section 9.3.18.1
#------------------------------------------------------------------------------#

class CCReleaseMT(Layer3):
    _GEN = (
        CCHeader(val={'Type':45}),
        Type4TLV('Cause', val={'T':0x8, 'V':b'\x80\x80'}, IE=Cause()),
        Type4TLV('SecondCause', val={'T':0x8, 'V':b'\x80\x80'}, IE=Cause()),
        Type4TLV('Facility', val={'T':0x1C, 'V':b''}),
        Type4TLV('UserUser', val={'T':0x7E, 'V':b'\x04'}, IE=UserUser())
        )


#------------------------------------------------------------------------------#
# 9.3.18.2	Release (mobile station to network direction)
# TS 24.008, section 9.3.18.2
#------------------------------------------------------------------------------#

class CCReleaseMO(Layer3):
    _GEN = (
        CCHeader(val={'Type':45}),
        Type4TLV('Cause', val={'T':0x8, 'V':b'\x80\x80'}, IE=Cause()),
        Type4TLV('SecondCause', val={'T':0x8, 'V':b'\x80\x80'}, IE=Cause()),
        Type4TLV('Facility', val={'T':0x1C, 'V':b''}),
        Type4TLV('UserUser', val={'T':0x7E, 'V':b'\x04'}, IE=UserUser()),
        Type4TLV('SSVersion', val={'T':0x7F, 'V':b''}, IE=SSVersion())
        )


#------------------------------------------------------------------------------#
# Recall $(CCBS)$
# TS 24.008, section 9.3.18a
#------------------------------------------------------------------------------#

class CCRecallCCBS(Layer3):
    _GEN = (
        CCHeader(val={'Type':11}),
        Type3V('RecallType', val={'V':b'\0'}, bl={'V':8}, IE=RecallType()),
        Type4LV('Facility', val={'V':b''})
        )


#------------------------------------------------------------------------------#
# Release complete (network to mobile station direction)
# TS 24.008, section 9.3.19.1
#------------------------------------------------------------------------------#

class CCReleaseCompleteMT(Layer3):
    _GEN = (
        CCHeader(val={'Type':42}),
        Type4TLV('Cause', val={'T':0x8, 'V':b'\x80\x80'}, IE=Cause()),
        Type4TLV('Facility', val={'T':0x1C, 'V':b''}),
        Type4TLV('UserUser', val={'T':0x7E, 'V':b'\x04'}, IE=UserUser())
        )


#------------------------------------------------------------------------------#
# Release complete (mobile station to network direction)
# TS 24.008, section 9.3.19.2
#------------------------------------------------------------------------------#

class CCReleaseCompleteMO(Layer3):
    _GEN = (
        CCHeader(val={'Type':42}),
        Type4TLV('Cause', val={'T':0x8, 'V':b'\x80\x80'}, IE=Cause()),
        Type4TLV('Facility', val={'T':0x1C, 'V':b''}),
        Type4TLV('UserUser', val={'T':0x7E, 'V':b'\x04'}, IE=UserUser()),
        Type4TLV('SSVersion', val={'T':0x7F, 'V':b''}, IE=SSVersion())
        )


#------------------------------------------------------------------------------#
# Retrieve
# TS 24.008, section 9.3.20
#------------------------------------------------------------------------------#

class CCRetrieve(Layer3):
    _GEN = (
        CCHeader(val={'Type':28}),
        )


#------------------------------------------------------------------------------#
# Retrieve Acknowledge
# TS 24.008, section 9.3.21
#------------------------------------------------------------------------------#

class CCRetrieveAcknowledge(Layer3):
    _GEN = (
        CCHeader(val={'Type':29}),
        )


#------------------------------------------------------------------------------#
# Retrieve Reject
# TS 24.008, section 9.3.22
#------------------------------------------------------------------------------#

class CCRetrieveReject(Layer3):
    _GEN = (
        CCHeader(val={'Type':30}),
        Type4LV('Cause', val={'V':b'\x80\x80'}, IE=Cause()),
        )


#------------------------------------------------------------------------------#
# Setup (mobile terminated call establishment)
# TS 24.008, section 9.3.23.1
#------------------------------------------------------------------------------#

class CCSetupMT(Layer3):
    _GEN = (
        CCHeader(val={'Type':5}),
        Type1TV('RepeatInd', val={'T':0xD, 'V':2}, dic=RepeatInd_dict),
        Type4TLV('BearerCap1', val={'T':0x4, 'V':b'\xa0'}, IE=BearerCap()),
        Type4TLV('BearerCap2', val={'T':0x4, 'V':b'\xa0'}, IE=BearerCap()),
        Type4TLV('Facility', val={'T':0x1C, 'V':b''}),
        Type4TLV('ProgressInd', val={'T':0x1E, 'V':b'\x80\x80'}, IE=ProgressInd()),
        Type3TV('Signal', val={'T':0x34, 'V':b'\0'}, bl={'V':8}, IE=Signal()),
        Type4TLV('CallingPartyBCDNumber', val={'T':0x5C, 'V':b'\x91'}, IE=CallingPartyBCDNumber()),
        Type4TLV('CallingPartySubaddress', val={'T':0x5D, 'V':b''}, IE=CallingPartySubaddress()),
        Type4TLV('CalledPartyBCDNumber', val={'T':0x5E, 'V':b'\x91'}, IE=CalledPartyBCDNumber()),
        Type4TLV('CalledPartySubaddress', val={'T':0x6D, 'V':b''}, IE=CalledPartySubaddress()),
        Type4TLV('RedirectingPartyBCDNumber', val={'T':0x74, 'V':b'\x91'}, IE=RedirectingPartyBCDNumber()),
        Type4TLV('RedirectingPartySubaddress', val={'T':0x75, 'V':b''}, IE=RedirectingPartySubaddress()),
        Type1TV('RepeatInd', val={'T':0xD, 'V':2}, dic=RepeatInd_dict),
        Type4TLV('LowLayerComp1', val={'T':0x7C, 'V':b''}),
        Type4TLV('LowLayerComp2', val={'T':0x7C, 'V':b''}),
        Type1TV('RepeatInd', val={'T':0xD, 'V':2}, dic=RepeatInd_dict),
        Type4TLV('HighLayerComp1', val={'T':0x7D, 'V':b''}, IE=HighLayerComp()),
        Type4TLV('HighLayerComp2', val={'T':0x7D, 'V':b''}, IE=HighLayerComp()),
        Type4TLV('UserUser', val={'T':0x7E, 'V':b'\x04'}, IE=UserUser()),
        Type1TV('Priority', val={'T':0x8, 'V':0}, dic=PriorityLevel_dict),
        Type4TLV('Alert', val={'T':0x19, 'V':b'\0'}, IE=AlertingPattern()),
        Type4TLV('NetCCCap', val={'T':0x2F, 'V':b'\0'}, IE=NetCCCap()),
        Type4TLV('CauseNoCLI', val={'T':0x3A, 'V':b'\0'}, IE=CauseNoCLI()),
        Type4TLV('BackupBearerCap', val={'T':0x41, 'V':b'\xa0'}, IE=BackupBearerCap())
        )


#------------------------------------------------------------------------------#
# 9.3.23.2	Setup (mobile originating call establishment)
# TS 24.008, section 9.3.23.2
#------------------------------------------------------------------------------#

class CCSetupMO(Layer3):
    _GEN = (
        CCHeader(val={'Type':5}),
        Type1TV('RepeatInd', val={'T':0xD, 'V':2}, dic=RepeatInd_dict),
        Type4TLV('BearerCap1', val={'T':0x4, 'V':b'\xa0'}, IE=BearerCap()),
        Type4TLV('BearerCap2', val={'T':0x4, 'V':b'\xa0'}, IE=BearerCap()),
        Type4TLV('Facility', val={'T':0x1C, 'V':b''}),
        Type4TLV('CallingPartySubaddress', val={'T':0x5D, 'V':b''}, IE=CallingPartySubaddress()),
        Type4TLV('CalledPartyBCDNumber', val={'T':0x5E, 'V':b'\x91'}, IE=CalledPartyBCDNumber()),
        Type4TLV('CalledPartySubaddress', val={'T':0x6D, 'V':b''}, IE=CalledPartySubaddress()),
        Type1TV('RepeatInd', val={'T':0xD, 'V':2}, dic=RepeatInd_dict),
        Type4TLV('LowLayerComp1', val={'T':0x7C, 'V':b''}),
        Type4TLV('LowLayerComp2', val={'T':0x7C, 'V':b''}),
        Type1TV('RepeatInd', val={'T':0xD, 'V':2}, dic=RepeatInd_dict),
        Type4TLV('HighLayerComp1', val={'T':0x7D, 'V':b''}, IE=HighLayerComp()),
        Type4TLV('HighLayerComp2', val={'T':0x7D, 'V':b''}, IE=HighLayerComp()),
        Type4TLV('UserUser', val={'T':0x7E, 'V':b'\x04'}, IE=UserUser()),
        Type4TLV('SSVersion', val={'T':0x7F, 'V':b''}, IE=SSVersion()),
        Type2('CLIRSuppr', val={'T':0xA1}),
        Type2('CLIRInvoc', val={'T':0xA2}),
        Type4TLV('CCCap', val={'T':0x15, 'V':b'\x01\0'}, IE=CCCap()),
        Type4TLV('Facility', val={'T':0x1D, 'V':b''}),
        Type4TLV('Facility', val={'T':0x1B, 'V':b''}),
        Type4TLV('StreamIdent', val={'T':0x2D, 'V':b'\0'}, IE=StreamIdent()),
        Type4TLV('SupportedCodecs', val={'T':0x40, 'V':b'\0\x01\0'}, IE=SupportedCodecs()),
        Type2('Redial', val={'T':0xA3})
        )


#------------------------------------------------------------------------------#
# Start CC $(CCBS)$
# TS 24.008, section 9.3.23a
#------------------------------------------------------------------------------#

class CCStartCCBS(Layer3):
    _GEN = (
        CCHeader(val={'Type':9}),
        Type4TLV('CCCap', val={'T':0x15, 'V':b'\x01\0'}, IE=CCCap()),
        )


#------------------------------------------------------------------------------#
# Start DTMF
# TS 24.008, section 9.3.24
#------------------------------------------------------------------------------#

class CCStartDTMF(Layer3):
    _GEN = (
        CCHeader(val={'Type':53}),
        Type3TV('KeypadFacility', val={'T':0x2C, 'V':b'0'}, bl={'V':8}),
        )


#------------------------------------------------------------------------------#
# Start DTMF Acknowledge
# TS 24.008, section 9.3.25
#------------------------------------------------------------------------------#

class CCStartDTMFAcknowledge(Layer3):
    _GEN = (
        CCHeader(val={'Type':54}),
        Type3TV('KeypadFacility', val={'T':0x2C, 'V':b'0'}, bl={'V':8}),
        )


#------------------------------------------------------------------------------#
# Start DTMF reject
# TS 24.008, section 9.3.26
#------------------------------------------------------------------------------#

class CCStartDTMFReject(Layer3):
    _GEN = (
        CCHeader(val={'Type':55}),
        Type4LV('Cause', val={'V':b'\x80\x80'}, IE=Cause()),
        )


#------------------------------------------------------------------------------#
# Status
# TS 24.008, section 9.3.27
#------------------------------------------------------------------------------#

class CCStatus(Layer3):
    _GEN = (
        CCHeader(val={'Type':61}),
        Type4LV('Cause', val={'V':b'\x80\x80'}, IE=Cause()),
        Type3V('CallState', val={'V':b'\0'}, bl={'V':8}, IE=CallState()),
        Type4TLV('AuxiliaryStates', val={'T':0x24, 'V':b'\x80'}, IE=AuxiliaryStates())
        )


#------------------------------------------------------------------------------#
# Status enquiry
# TS 24.008, section 9.3.28
#------------------------------------------------------------------------------#

class CCStatusEnquiry(Layer3):
    _GEN = (
        CCHeader(val={'Type':52}),
        )


#------------------------------------------------------------------------------#
# Stop DTMF
# TS 24.008, section 9.3.29
#------------------------------------------------------------------------------#

class CCStopDTMF(Layer3):
    _GEN = (
        CCHeader(val={'Type':49}),
        )


#------------------------------------------------------------------------------#
# Stop DTMF acknowledge
# TS 24.008, section 9.3.30
#------------------------------------------------------------------------------#

class CCStopDTMFAcknowledge(Layer3):
    _GEN = (
        CCHeader(val={'Type':50}),
        )


#------------------------------------------------------------------------------#
# User information
# TS 24.008, section 9.3.31
#------------------------------------------------------------------------------#

class CCUserInformation(Layer3):
    _GEN = (
        CCHeader(val={'Type':16}),
        Type4TLV('UserUser', val={'T':0x7E, 'V':b'\x04'}, IE=UserUser()),
        Type2('MoreData', val={'T':0xA0})
        )


#------------------------------------------------------------------------------#
# CC dispatcher
#------------------------------------------------------------------------------#

CCTypeMOClasses = {
    1 : CCAlertingMO,
    2 : CCCallProceeding,
    3 : CCProgress,
    4 : CCEstablishmentCCBS,
    5 : CCSetupMO,
    6 : CCEstablishmentConfirmedCCBS,
    7 : CCConnectMO,
    8 : CCCallConfirmed,
    9 : CCStartCCBS,
    11: CCRecallCCBS,
    14: CCEmergencySetup,
    15: CCConnectAcknowledge,
    16: CCUserInformation,
    19: CCModifyReject,
    23: CCModify,
    24: CCHold,
    25: CCHoldAcknowledge,
    26: CCHoldReject,
    28: CCRetrieve,
    29: CCRetrieveAcknowledge,
    30: CCRetrieveReject,
    31: CCModifyComplete,
    37: CCDisconnectMO,
    42: CCReleaseCompleteMO,
    45: CCReleaseMO,
    49: CCStopDTMF,
    50: CCStopDTMFAcknowledge,
    52: CCStatusEnquiry,
    53: CCStartDTMF,
    54: CCStartDTMFAcknowledge,
    55: CCStartDTMFReject,
    57: CCCongestionControl,
    58: CCFacilityMO,
    61: CCStatus,
    62: CCNotify
    }

CCTypeMTClasses = {
    1 : CCAlertingMT,
    2 : CCCallProceeding,
    3 : CCProgress,
    4 : CCEstablishmentCCBS,
    5 : CCSetupMT,
    6 : CCEstablishmentConfirmedCCBS,
    7 : CCConnectMT,
    8 : CCCallConfirmed,
    9 : CCStartCCBS,
    11: CCRecallCCBS,
    14: CCEmergencySetup,
    15: CCConnectAcknowledge,
    16: CCUserInformation,
    19: CCModifyReject,
    23: CCModify,
    24: CCHold,
    25: CCHoldAcknowledge,
    26: CCHoldReject,
    28: CCRetrieve,
    29: CCRetrieveAcknowledge,
    30: CCRetrieveReject,
    31: CCModifyComplete,
    37: CCDisconnectMT,
    42: CCReleaseCompleteMT,
    45: CCReleaseMT,
    49: CCStopDTMF,
    50: CCStopDTMFAcknowledge,
    52: CCStatusEnquiry,
    53: CCStartDTMF,
    54: CCStartDTMFAcknowledge,
    55: CCStartDTMFReject,
    57: CCCongestionControl,
    58: CCFacilityMT,
    61: CCStatus,
    62: CCNotify
    }

def get_cc_msg_mo_instances():
    return {k: CCTypeMOClasses[k]() for k in CCTypeMOClasses}

def get_cc_msg_mt_instances():
    return {k: CCTypeMTClasses[k]() for k in CCTypeMTClasses}

